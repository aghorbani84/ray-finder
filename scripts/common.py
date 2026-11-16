"""Shared constants and small helpers for the iran-v2ray-finder pipeline."""

from __future__ import annotations

import re

# v2rayNG-like User-Agent (some sources serve different content to browsers/curl).
USER_AGENT = (
    "v2rayNG/1.8.75/ com.v2ray.ngapp.ping 2024.06.06 "
    "(Linux; Android 14; Pixel 7) Dalvik/2.1.0 (Linux; U; Android 14)"
)

HTTP_TIMEOUT = 30          # seconds for source downloads
MAX_RESPONSE_BYTES = 40 * 1024 * 1024  # 40 MB safety cap per download

TCP_TIMEOUT = 3.0          # seconds per connect attempt
TCP_ATTEMPTS = 2           # attempts per node before declaring it dead
TCP_WORKERS = 150          # concurrent connectivity testers

MAX_NODES = 150            # final cap on selected nodes
MIN_PUBLISH_NODES = 20     # fail closed; never replace a good feed with near-empty output
TOP_N = 20                 # fastest nodes injected into the TOP20 group

PROTOCOLS = ("vless", "vmess", "trojan", "ss", "hysteria2", "tuic")

# URI prefix aliases -> canonical protocol name.
PREFIX_MAP = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "ss",
    "shadowsocks": "ss",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "tuic": "tuic",
}

# A line that starts with one of these prefixes is a node URI.
URI_LINE_RE = re.compile(
    r"^(?P<scheme>vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2|tuic)://\S+",
    re.IGNORECASE,
)

# Long run of base64 characters (a whole-page encoded subscription blob).
B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def log(msg: str) -> None:
    """Print a timestamped log line to stdout."""
    import datetime as _dt

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    print(f"[{stamp}] {msg}", flush=True)
