from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from anonsurf_safe.http_socks_proxy import HTTPToSocksBridge, relay_bidirectional


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class _FakeSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        self.request.settimeout(5)
        greeting = self.request.recv(3)
        if greeting != b"\x05\x01\x00":
            return
        self.request.sendall(b"\x05\x00")
        header = self._recv_exact(4)
        if header[:3] != b"\x05\x01\x00":
            return
        atyp = header[3]
        if atyp == 3:
            size = self._recv_exact(1)[0]
            host = self._recv_exact(size).decode("idna")
        elif atyp == 1:
            host = socket.inet_ntoa(self._recv_exact(4))
        else:
            return
        port = struct.unpack("!H", self._recv_exact(2))[0]
        server.last_target = (host, port)

        upstream = socket.create_connection(("127.0.0.1", server.origin_port), timeout=5)
        self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        with upstream:
            relay_bidirectional(self.request, upstream)

    def _recv_exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data


class _FakeSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler, origin_port):
        super().__init__(server_address, handler)
        self.origin_port = origin_port
        self.last_target = None


class ProxyIntegrationTests(unittest.TestCase):
    def test_idle_tunnel_stays_open(self):
        client, bridge_left = socket.socketpair()
        bridge_right, server = socket.socketpair()
        relay_thread = threading.Thread(
            target=relay_bidirectional,
            args=(bridge_left, bridge_right, 0.05),
            daemon=True,
        )
        relay_thread.start()
        try:
            time.sleep(0.12)
            self.assertTrue(relay_thread.is_alive())
            client.sendall(b"still-open")
            server.settimeout(1)
            self.assertEqual(server.recv(10), b"still-open")
        finally:
            client.close()
            server.close()
            bridge_left.close()
            bridge_right.close()
            relay_thread.join(timeout=1)

    def test_plain_http_uses_remote_domain_through_socks(self):
        origin = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
        origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()

        socks = _FakeSocksServer(("127.0.0.1", 0), _FakeSocksHandler, origin.server_address[1])
        socks_thread = threading.Thread(target=socks.serve_forever, daemon=True)
        socks_thread.start()

        bridge = HTTPToSocksBridge(0, socks.server_address[1])
        bridge.start()
        bridge_port = bridge._server.server_address[1]

        try:
            proxy_url = f"http://127.0.0.1:{bridge_port}"
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
            with opener.open("http://example.test/hello?x=1", timeout=5) as response:
                self.assertEqual(response.read(), b"path=/hello?x=1")
            self.assertEqual(socks.last_target, ("example.test", 80))
        finally:
            bridge.stop()
            socks.shutdown()
            socks.server_close()
            origin.shutdown()
            origin.server_close()


if __name__ == "__main__":
    unittest.main()
