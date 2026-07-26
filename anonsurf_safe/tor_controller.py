from __future__ import annotations

import os
import queue
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .config import app_data_dir


class TorError(RuntimeError):
    pass


class TorController:
    QUIET_NOTICE_FRAGMENTS = (
        "Have tried resolving or connecting to address '[scrubbed]'",
    )

    def __init__(
        self,
        tor_path: str,
        socks_port: int,
        control_port: int,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.tor_path = Path(tor_path).expanduser()
        self.socks_port = int(socks_port)
        self.control_port = int(control_port)
        self.logger = logger or (lambda _message: None)
        self.process: subprocess.Popen[str] | None = None
        self._bootstrap = 0
        self._reader_thread: threading.Thread | None = None
        self._line_queue: queue.Queue[str] = queue.Queue()

        self.data_dir = app_data_dir() / "tor-data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cookie_path = self.data_dir / "control_auth_cookie"

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @property
    def bootstrap_percent(self) -> int:
        return self._bootstrap

    def validate(self) -> None:
        if os.name != "nt":
            raise TorError("This controller is intended for Windows.")
        if not self.tor_path.is_file():
            raise TorError("Select tor.exe from the official Tor Expert Bundle.")
        if self.tor_path.name.lower() != "tor.exe":
            raise TorError("The selected file must be tor.exe.")
        if not (1024 <= self.socks_port <= 65535):
            raise TorError("Invalid SOCKS port.")
        if not (1024 <= self.control_port <= 65535):
            raise TorError("Invalid control port.")
        if self.socks_port == self.control_port:
            raise TorError("SOCKS and control ports must differ.")

    def _reader(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for raw in self.process.stdout:
            line = raw.rstrip()
            self._line_queue.put(line)
            if self.should_display_log_line(line):
                self.logger(line)
            marker = "Bootstrapped "
            if marker in line:
                try:
                    percent_text = line.split(marker, 1)[1].split("%", 1)[0]
                    self._bootstrap = max(self._bootstrap, int(percent_text))
                except (IndexError, ValueError):
                    pass

    @classmethod
    def should_display_log_line(cls, line: str) -> bool:
        """Hide Tor notices already represented by a safer bridge summary."""
        return not any(fragment in line for fragment in cls.QUIET_NOTICE_FRAGMENTS)

    def start(self, timeout: float = 120.0) -> None:
        self.validate()
        if self.running:
            return

        self._bootstrap = 0
        self.cookie_path.unlink(missing_ok=True)
        cmd = [
            str(self.tor_path),
            "--ClientOnly", "1",
            "--SocksPort", f"127.0.0.1:{self.socks_port}",
            "--ControlPort", f"127.0.0.1:{self.control_port}",
            "--CookieAuthentication", "1",
            "--CookieAuthFile", str(self.cookie_path),
            "--DataDirectory", str(self.data_dir),
            "--AvoidDiskWrites", "1",
            "--Log", "notice stdout",
        ]
        geoip_dir = self.tor_path.parent.parent / "data"
        geoip_file = geoip_dir / "geoip"
        geoip6_file = geoip_dir / "geoip6"
        if geoip_file.is_file():
            cmd.extend(["--GeoIPFile", str(geoip_file)])
        if geoip6_file.is_file():
            cmd.extend(["--GeoIPv6File", str(geoip6_file)])

        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        env = os.environ.copy()
        tor_dir = str(self.tor_path.parent)
        env["PATH"] = tor_dir + os.pathsep + env.get("PATH", "")

        self.logger("Starting Tor from official executable...")
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=startupinfo,
            creationflags=creationflags,
            env=env,
        )
        self._reader_thread = threading.Thread(target=self._reader, daemon=True)
        self._reader_thread.start()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.running:
                code = self.process.returncode if self.process else "unknown"
                self.process = None
                raise TorError(f"Tor exited before connecting (exit code {code}).")
            if self._bootstrap >= 100:
                self.logger("Tor bootstrapped successfully.")
                return
            time.sleep(0.1)

        self.stop()
        raise TorError("Tor did not finish bootstrapping before the timeout.")

    def _control_command(self, command: str) -> list[str]:
        if not self.running:
            raise TorError("Tor is not running.")
        try:
            cookie = self.cookie_path.read_bytes().hex()
        except OSError as exc:
            raise TorError(f"Unable to read Tor authentication cookie: {exc}") from exc

        replies: list[str] = []
        with socket.create_connection(("127.0.0.1", self.control_port), timeout=5) as sock:
            stream = sock.makefile("rwb", buffering=0)
            stream.write(f"AUTHENTICATE {cookie}\r\n".encode("ascii"))
            auth = stream.readline().decode("utf-8", "replace").strip()
            if not auth.startswith("250"):
                raise TorError(f"Tor control authentication failed: {auth}")

            stream.write((command + "\r\n").encode("ascii"))
            while True:
                line = stream.readline().decode("utf-8", "replace").strip()
                if not line:
                    break
                replies.append(line)
                if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                    break
        return replies

    def new_identity(self) -> None:
        replies = self._control_command("SIGNAL NEWNYM")
        if not replies or not replies[-1].startswith("250"):
            raise TorError("Tor rejected the new-identity request.")
        self.logger("Requested a new Tor circuit. Sites may reuse existing sessions.")

    def stop(self) -> None:
        process = self.process
        self.process = None
        self._bootstrap = 0
        if process is None:
            return
        if process.poll() is None:
            self.logger("Stopping Tor...")
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.logger("Tor stopped.")


def find_tor_candidates() -> list[Path]:
    candidates: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        try:
            normalized = str(path.resolve()).lower()
        except OSError:
            normalized = str(path).lower()
        if normalized not in seen and path.is_file():
            seen.add(normalized)
            candidates.append(path)

    which = shutil.which("tor.exe")
    if which:
        add(Path(which))

    homes = [Path.home() / "Downloads", Path.home() / "Desktop"]
    patterns = ("**/tor/tor.exe", "**/Tor/tor.exe", "**/tor.exe")
    for home in homes:
        if not home.exists():
            continue
        for pattern in patterns:
            try:
                for path in home.glob(pattern):
                    add(path)
                    if len(candidates) >= 20:
                        return candidates
            except OSError:
                continue
    return candidates
