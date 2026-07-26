from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

APP_NAME = "AnonSurfSafe"


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if base:
        path = Path(base) / APP_NAME
    else:
        path = Path.home() / f".{APP_NAME.lower()}"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class Settings:
    tor_path: str = ""
    socks_port: int = 19050
    http_proxy_port: int = 19051
    control_port: int = 19052

    @classmethod
    def load(cls) -> "Settings":
        path = app_data_dir() / "settings.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                tor_path=str(raw.get("tor_path", "")),
                socks_port=int(raw.get("socks_port", 19050)),
                http_proxy_port=int(raw.get("http_proxy_port", 19051)),
                control_port=int(raw.get("control_port", 19052)),
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return cls()

    def save(self) -> None:
        path = app_data_dir() / "settings.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        tmp.replace(path)
