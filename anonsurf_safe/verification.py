from __future__ import annotations

import json
import urllib.request


class VerificationError(RuntimeError):
    pass


def check_tor(http_proxy_port: int, timeout: float = 20.0) -> tuple[bool, str]:
    proxy_url = f"http://127.0.0.1:{int(http_proxy_port)}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    request = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "AnonSurfSafe/1.0.3"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise VerificationError(f"Tor verification failed: {exc}") from exc

    return bool(payload.get("IsTor")), str(payload.get("IP", "unknown"))
