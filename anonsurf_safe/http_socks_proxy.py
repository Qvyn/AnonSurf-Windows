from __future__ import annotations

import ipaddress
import select
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

DESTINATION_ERROR_LOG_INTERVAL = 10 * 60
OTHER_EXPECTED_ERROR_LOG_INTERVAL = 60


class ProxyBridgeError(RuntimeError):
    pass


class TargetBlockedError(ProxyBridgeError):
    """Raised when forwarding a target could expose or misuse a local address."""


class SocksReplyError(ProxyBridgeError):
    REASONS = {
        1: "general failure",
        2: "connection not allowed",
        3: "network unreachable",
        4: "destination unreachable",
        5: "connection refused",
        6: "connection timed out",
        7: "command not supported",
        8: "address type not supported",
    }

    def __init__(self, code: int) -> None:
        self.code = code
        self.reason = self.REASONS.get(code, "unknown failure")
        super().__init__(f"Tor could not reach the destination ({self.reason}, SOCKS code {code})")


@dataclass(frozen=True)
class Target:
    host: str
    port: int


def validate_target(target: Target) -> None:
    """Fail closed for destinations that should never be sent to a Tor exit."""
    host = target.host.strip().rstrip(".")
    if not host:
        raise TargetBlockedError("Blocked an empty proxy destination")
    if not 1 <= target.port <= 65535:
        raise TargetBlockedError("Blocked a proxy destination with an invalid port")

    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local", ".lan", ".home", ".internal")):
        raise TargetBlockedError("Blocked a local-network destination")

    # Do not resolve domain names here: local DNS resolution would defeat remote
    # DNS through Tor. Only classify literal IP addresses.
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return
    if not ip.is_global:
        raise TargetBlockedError("Blocked a private, local, or reserved IP destination")


def parse_connect_target(value: str) -> Target:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("Malformed IPv6 CONNECT target")
        host = value[1:end]
        remainder = value[end + 1 :]
        port = int(remainder[1:]) if remainder.startswith(":") else 443
        return Target(host, port)
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        return Target(host, int(port_text))
    return Target(value, 443)


def parse_absolute_http_target(uri: str, host_header: str | None) -> tuple[Target, str]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() == "http" and parsed.hostname:
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return Target(parsed.hostname, port), path

    if not host_header:
        raise ValueError("Missing Host header")
    target = parse_connect_target(host_header)
    if ":" not in host_header and not host_header.startswith("["):
        target = Target(target.host, 80)
    return target, uri or "/"


def socks5_connect(proxy_host: str, proxy_port: int, target: Target, timeout: float = 15.0) -> socket.socket:
    validate_target(target)
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        reply = _recv_exact(sock, 2)
        if reply != b"\x05\x00":
            raise ProxyBridgeError("Tor SOCKS proxy rejected unauthenticated connection")

        try:
            ip = ipaddress.ip_address(target.host)
        except ValueError:
            encoded = target.host.encode("idna")
            if len(encoded) > 255:
                raise ProxyBridgeError("Destination hostname is too long")
            address = b"\x03" + bytes([len(encoded)]) + encoded
        else:
            if ip.version == 4:
                address = b"\x01" + ip.packed
            else:
                address = b"\x04" + ip.packed

        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", target.port))
        header = _recv_exact(sock, 4)
        if header[0] != 5:
            raise ProxyBridgeError("Tor SOCKS returned an invalid protocol version")
        if header[1] != 0:
            raise SocksReplyError(header[1])
        atyp = header[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            size = _recv_exact(sock, 1)[0]
            _recv_exact(sock, size)
        elif atyp == 4:
            _recv_exact(sock, 16)
        else:
            raise ProxyBridgeError("Tor SOCKS returned an unknown address type")
        _recv_exact(sock, 2)
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, amount: int) -> bytes:
    chunks: list[bytes] = []
    remaining = amount
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProxyBridgeError("Connection closed during SOCKS handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def relay_bidirectional(
    left: socket.socket,
    right: socket.socket,
    poll_interval: float = 30.0,
) -> None:
    sockets = [left, right]
    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, poll_interval)
        if exceptional:
            return
        # No traffic is not a failure. HTTPS tunnels are routinely quiet while
        # the PC is idle, so keep polling until an endpoint actually closes.
        if not readable:
            continue
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            destination = right if source is left else left
            try:
                destination.sendall(data)
            except OSError:
                return


class _ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HTTPToSocksBridge:
    def __init__(
        self,
        listen_port: int,
        socks_port: int,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.listen_port = int(listen_port)
        self.socks_port = int(socks_port)
        self.logger = logger or (lambda _message: None)
        self._server: _ThreadingServer | None = None
        self._thread: threading.Thread | None = None
        self._expected_error_last_log: dict[str, float] = {}
        self._active_sockets: set[socket.socket] = set()
        self._active_sockets_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return (
            self._server is not None
            and self._thread is not None
            and self._thread.is_alive()
        )

    def start(self) -> None:
        if self.running:
            return
        bridge = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = 30

            def handle(self) -> None:
                bridge._register_socket(self.connection)
                try:
                    bridge._handle_client(self)
                except (SocksReplyError, TargetBlockedError) as exc:
                    bridge._log_expected_error(str(exc))
                    try:
                        self.wfile.write(
                            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                    except OSError:
                        pass
                except (socket.timeout, TimeoutError):
                    # Programs sometimes open the Windows proxy and then leave
                    # the socket unused. Closing that idle request is normal.
                    pass
                except (ConnectionResetError, BrokenPipeError):
                    # Normal when an application exits or refresh closes a
                    # connection that the application still owns.
                    pass
                except Exception as exc:
                    if not bridge._is_expected_disconnect(exc):
                        bridge.logger(f"Proxy request failed: {exc}")
                    try:
                        self.wfile.write(
                            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                    except OSError:
                        pass
                finally:
                    bridge._unregister_socket(self.connection)

        self._server = _ThreadingServer(("127.0.0.1", self.listen_port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.logger(f"Local HTTP proxy listening on 127.0.0.1:{self.listen_port}")

    @staticmethod
    def _is_expected_disconnect(exc: Exception) -> bool:
        if not isinstance(exc, OSError):
            return False
        return getattr(exc, "winerror", None) in {10053, 10054, 10058}

    def _register_socket(self, sock: socket.socket) -> None:
        with self._active_sockets_lock:
            self._active_sockets.add(sock)

    def _unregister_socket(self, sock: socket.socket) -> None:
        with self._active_sockets_lock:
            self._active_sockets.discard(sock)

    def _close_active_connections(self) -> None:
        with self._active_sockets_lock:
            sockets = list(self._active_sockets)
            self._active_sockets.clear()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _log_expected_error(self, message: str) -> None:
        now = time.monotonic()
        interval = (
            DESTINATION_ERROR_LOG_INTERVAL
            if "SOCKS code 4" in message
            else OTHER_EXPECTED_ERROR_LOG_INTERVAL
        )
        previous = self._expected_error_last_log.get(message)
        if previous is not None and now - previous < interval:
            return
        self._expected_error_last_log[message] = now
        self.logger(f"{message}. No direct connection was attempted.")

    def _handle_client(self, handler: socketserver.StreamRequestHandler) -> None:
        request_line = handler.rfile.readline(65537)
        if not request_line or len(request_line) > 65536:
            return
        try:
            method, target_text, version = request_line.decode("iso-8859-1").strip().split(" ", 2)
        except ValueError as exc:
            raise ProxyBridgeError("Malformed HTTP request line") from exc

        header_lines: list[bytes] = []
        headers: dict[str, str] = {}
        total = 0
        while True:
            line = handler.rfile.readline(65537)
            if not line:
                return
            total += len(line)
            if total > 262144:
                raise ProxyBridgeError("HTTP headers are too large")
            if line in (b"\r\n", b"\n"):
                break
            header_lines.append(line)
            decoded = line.decode("iso-8859-1").rstrip("\r\n")
            if ":" in decoded:
                name, value = decoded.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        if method.upper() == "CONNECT":
            target = parse_connect_target(target_text)
            upstream = socks5_connect("127.0.0.1", self.socks_port, target)
            self._register_socket(upstream)
            try:
                with upstream:
                    handler.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    handler.wfile.flush()
                    handler.connection.settimeout(None)
                    relay_bidirectional(handler.connection, upstream)
            finally:
                self._unregister_socket(upstream)
            return

        target, origin_form = parse_absolute_http_target(target_text, headers.get("host"))
        upstream = socks5_connect("127.0.0.1", self.socks_port, target)
        self._register_socket(upstream)
        try:
            with upstream:
                upstream.sendall(f"{method} {origin_form} {version}\r\n".encode("iso-8859-1"))
                for line in header_lines:
                    lower = line.split(b":", 1)[0].strip().lower()
                    if lower in {b"proxy-connection", b"proxy-authorization"}:
                        continue
                    upstream.sendall(line)
                upstream.sendall(b"Connection: close\r\n\r\n")

                content_length = headers.get("content-length")
                if content_length:
                    remaining = int(content_length)
                    while remaining > 0:
                        data = handler.rfile.read(min(65536, remaining))
                        if not data:
                            break
                        upstream.sendall(data)
                        remaining -= len(data)

                while True:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    handler.connection.sendall(data)
        finally:
            self._unregister_socket(upstream)

    def stop(self) -> None:
        server = self._server
        self._server = None
        if server is None:
            return
        server.shutdown()
        self._close_active_connections()
        server.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self.logger("Local HTTP proxy stopped.")
