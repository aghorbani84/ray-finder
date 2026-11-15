"""Fetch stage: download every URL in sources.json and extract node URIs.

Handles, per response body:
  * plain-text lists of node URIs (vmess://, vless://, trojan://, ss://, hy2://, tuic://)
  * whole-page base64 blobs (decoded, then re-scanned for URIs)
  * Clash/mihomo YAML subscriptions (starts with "port:"/"proxies:") -> the "proxies"
    section is extracted and kept as yaml:<node-id> pseudo-URIs so later stages can
    count them; they are converted to real mihomo proxy dicts by build_output.py.

Every network error / bad source is logged and skipped - never raised.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from pathlib import Path

import requests
import yaml

from common import (
    B64_BLOB_RE,
    HTTP_TIMEOUT,
    MAX_RESPONSE_BYTES,
    URI_LINE_RE,
    USER_AGENT,
    log,
)

# A YAML subscription document we do not want to parse line-by-line as text.
CLASH_YAML_HEAD_RE = re.compile(
    r"^\s*(port|socks-port|mixed-port|proxies|proxy-groups|allow-lan|mode|dns)\s*:",
    re.MULTILINE,
)


def load_sources(path: Path) -> list[dict]:
    """Read sources.json; return a list of {"name": str, "urls": [str]}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        log(f"fetch: cannot read {path}: {exc}")
        return []
    sources = []
    for src in data.get("sources", []):
        name = str(src.get("name") or "unnamed").strip()
        urls = [str(u).strip() for u in src.get("urls", []) if str(u).strip()]
        if urls:
            sources.append({"name": name, "urls": urls})
    return sources


def _looks_like_uris(text: str) -> bool:
    return bool(URI_LINE_RE.search(text))


def _decode_b64_blob(blob: str) -> str | None:
    """Best-effort decode of a base64 blob (pad-safe)."""
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        return raw.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _extract_clash_proxies(text: str) -> list[str]:
    """Pull the proxies section out of a Clash YAML subscription.

    Each usable proxy dict is JSON-serialized and wrapped in a "clash://"
    pseudo-URI (base64) so parse.py can normalize it like any other node.
    """
    out: list[str] = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return out
    if not isinstance(doc, dict):
        return out
    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        return out
    for p in proxies:
        if isinstance(p, dict) and p.get("server") and p.get("port"):
            try:
                payload = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
                out.append("clash://" + base64.b64encode(payload.encode("utf-8")).decode("ascii"))
            except (TypeError, ValueError):
                continue
    return out


def _uris_from_text(text: str, depth: int = 0) -> list[str]:
    """Extract node URIs from an arbitrary response body (recursive once for b64)."""
    uris: list[str] = []
    if not text:
        return uris

    # Clash YAML subscription?
    head = text[:2000]
    if CLASH_YAML_HEAD_RE.search(head) and not _looks_like_uris(head):
        found = _extract_clash_proxies(text)
        if found:
            return found
        # fall through: maybe it also contains plain URIs somewhere

    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if URI_LINE_RE.match(line):
            uris.append(line)
            continue
        # inline base64 blob on its own line (whole-page encoded sub)
        if depth < 2 and len(line) >= 200 and B64_BLOB_RE.fullmatch(line.rstrip("=")):
            decoded = _decode_b64_blob(line)
            if decoded:
                uris.extend(_uris_from_text(decoded, depth + 1))

    # The entire body may be one giant base64 blob without newlines.
    if not uris and depth < 2:
        compact = re.sub(r"\s+", "", text)
        if len(compact) >= 200 and B64_BLOB_RE.fullmatch(compact.rstrip("=")):
            decoded = _decode_b64_blob(compact)
            if decoded:
                uris.extend(_uris_from_text(decoded, depth + 1))

    return uris


def fetch_url(session: requests.Session, url: str) -> str:
    resp = session.get(
        url,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        stream=True,
    )
    resp.raise_for_status()
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        total += len(chunk)
        chunks.append(chunk)
        if total > MAX_RESPONSE_BYTES:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def fetch_all(sources_path: Path) -> tuple[list[tuple[str, str]], dict]:
    """Fetch every configured source.

    Returns (items, stats) where items is a list of (source_name, uri_line)
    and stats maps source name -> {"urls_ok", "urls_failed", "configs"}.
    """
    sources = load_sources(sources_path)
    items: list[tuple[str, str]] = []
    stats: dict[str, dict] = {}

    for src in sources:
        name = src["name"]
        st = {"urls_ok": 0, "urls_failed": 0, "configs": 0}
        stats[name] = st
        for url in src["urls"]:
            got = 0
            for attempt in range(2):  # one retry per URL
                try:
                    with requests.Session() as session:
                        text = fetch_url(session, url)
                    uris = _uris_from_text(text)
                    got = len(uris)
                    items.extend((name, u) for u in uris)
                    st["urls_ok"] += 1
                    log(f"fetch: {name} {url} -> {got} configs")
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    st["urls_failed"] += 1
                    log(f"fetch: FAILED {name} {url}: {type(exc).__name__} {exc}")
            st["configs"] += got
        log(f"fetch: source '{name}' done: {st['configs']} configs "
            f"({st['urls_ok']} ok / {st['urls_failed']} failed urls)")

    log(f"fetch: total {len(items)} raw config lines from {len(sources)} sources")
    return items, stats


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    all_items, all_stats = fetch_all(root / "sources.json")
    print(json.dumps(all_stats, indent=2))
