from __future__ import annotations

import ctypes
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import app_data_dir

BACKUP_PATH = app_data_dir() / "proxy_backup.json"
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
TRACKED_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")


class ProxyError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegistryValue:
    exists: bool
    value: Any = None
    value_type: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "exists": self.exists,
            "value": self.value,
            "value_type": self.value_type,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "RegistryValue":
        return cls(
            exists=bool(raw.get("exists", False)),
            value=raw.get("value"),
            value_type=raw.get("value_type"),
        )


def _require_windows() -> None:
    if sys.platform != "win32":
        raise ProxyError("Windows proxy management is available only on Windows.")


def _notify_proxy_changed() -> None:
    wininet = ctypes.windll.wininet
    INTERNET_OPTION_REFRESH = 37
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def _read_current() -> dict[str, RegistryValue]:
    _require_windows()
    import winreg

    result: dict[str, RegistryValue] = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
        for name in TRACKED_VALUES:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
                result[name] = RegistryValue(True, value, value_type)
            except FileNotFoundError:
                result[name] = RegistryValue(False)
    return result


def backup_exists() -> bool:
    return BACKUP_PATH.exists()


def backup_current() -> Path:
    """Persist the original proxy settings once; never overwrite a crash-recovery backup."""
    _require_windows()
    if BACKUP_PATH.exists():
        return BACKUP_PATH

    state = {name: item.to_json() for name, item in _read_current().items()}
    payload = {
        "schema": 1,
        "pid": os.getpid(),
        "values": state,
    }
    tmp = BACKUP_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(BACKUP_PATH)
    return BACKUP_PATH


def enable_local_proxy(port: int) -> None:
    _require_windows()
    if not (1024 <= int(port) <= 65535):
        raise ProxyError("Proxy port must be between 1024 and 65535.")

    import winreg

    backup_current()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        REG_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
        # WinINet bypasses simple intranet hostnames. Explicit loopback entries
        # also keep local applications from pointlessly sending them to Tor.
        winreg.SetValueEx(
            key,
            "ProxyOverride",
            0,
            winreg.REG_SZ,
            "<local>;localhost;127.*;[::1]",
        )
        try:
            winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _notify_proxy_changed()


def restore_backup() -> bool:
    """Restore exactly the values saved before enabling the proxy."""
    _require_windows()
    if not BACKUP_PATH.exists():
        return False

    import winreg

    try:
        payload = json.loads(BACKUP_PATH.read_text(encoding="utf-8"))
        raw_values = payload["values"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProxyError(f"Proxy backup is unreadable: {exc}") from exc

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        REG_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        for name in TRACKED_VALUES:
            state = RegistryValue.from_json(raw_values.get(name, {"exists": False}))
            if state.exists:
                if state.value_type is None:
                    raise ProxyError(f"Missing registry type for {name}")
                winreg.SetValueEx(key, name, 0, int(state.value_type), state.value)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass

    _notify_proxy_changed()
    BACKUP_PATH.unlink(missing_ok=True)
    return True


def force_disable_proxy() -> None:
    """Emergency fallback when no valid backup exists."""
    _require_windows()
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        REG_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    _notify_proxy_changed()
