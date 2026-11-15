"""Clean stage: drop junk nodes, dedupe, normalize display names.

Rules:
  * drop private/loopback/link-local/reserved IPs and localhost hostnames
  * drop any server hostname ending in .ir (Iran-hosted servers are useless
    as exits for Iranian users)
  * drop duplicates by hash of protocol+host+port+credential
  * normalize names: keep the original name when usable, otherwise assign
    "PROTOCOL-SOURCE-N"
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from common import log

_LOCALHOST_RE = re.compile(r"^(localhost|(\d{1,3}\.){3}\d{1,3}\.localdomain|ip6-?loopback)$",
                           re.IGNORECASE)
_CREDENTIAL_STRIP_RE = re.compile(r"[^0-9a-zA-Z]")


def _is_bad_host(host: str) -> bool:
    h = host.strip().strip("[]").lower()
    if not h:
        return True
    if h.endswith(".ir"):
        return True
    if _LOCALHOST_RE.match(h) or h == "localhost.localdomain":
        return True
    if ".local" == h.split(".")[-1] or h.endswith(".local"):
        return True
    # literal IPv4 / IPv6 checks
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False  # a normal domain name
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        v4 = ip.ipv4_mapped
        if v4.is_private or v4.is_loopback or v4.is_link_local or v4.is_reserved:
            return True
    return False


def _name_is_usable(name: str) -> bool:
    if not name:
        return False
    n = name.strip()
    if len(n) < 2 or len(n) > 60:
        return False
    lowered = n.lower()
    # pure placeholder names used by scrapers
    if lowered in {"unknown", "unavailable", "test", "", "-", "--"}:
        return False
    if re.fullmatch(r"[\W_]+", n):
        return False
    # names that are just an IP/uuid blob
    if re.fullmatch(r"[0-9a-fA-F\-:.]{8,}", n):
        return False
    return True


def _dedupe_key(node: dict) -> str:
    cred = node.get("uuid") or node.get("password") or ""
    core = f"{node['proto']}|{node['server'].lower()}|{node['port']}|{cred}"
    digest = hashlib.sha1(core.encode("utf-8")).hexdigest()
    return digest


def clean_nodes(nodes: list[dict]) -> list[dict]:
    """Filter + dedupe + name-normalize. Never raises on a bad node."""
    kept: list[dict] = []
    seen: set[str] = set()
    dropped_bad = dropped_dup = 0
    counters: dict[tuple[str, str], int] = {}

    for node in nodes:
        try:
            if _is_bad_host(node["server"]):
                dropped_bad += 1
                continue
            key = _dedupe_key(node)
            if key in seen:
                dropped_dup += 1
                continue
            seen.add(key)
            kept.append(node)
        except Exception as exc:  # noqa: BLE001
            dropped_bad += 1
            log(f"clean: skipped node due to error: {type(exc).__name__} {exc}")

    # normalize names after dedupe so numbering is stable
    for node in kept:
        proto = node["proto"].upper()
        source = re.sub(r"[^A-Za-z0-9]", "", node.get("source") or "SRC") or "SRC"
        pair = (proto, source)
        counters[pair] = counters.get(pair, 0) + 1
        if not _name_is_usable(node.get("name", "")):
            node["name"] = f"{proto}-{source}-{counters[pair]}"

    # ensure globally unique display names (mihomo requires unique proxy names)
    used: set[str] = set()
    suffix_counters: dict[str, int] = {}
    for node in kept:
        name = node["name"].strip()
        if name in used:
            base = name[:50]
            suffix_counters[base] = suffix_counters.get(base, 0) + 1
            name = f"{base}#{suffix_counters[base]}"
            while name in used:
                suffix_counters[base] += 1
                name = f"{base}#{suffix_counters[base]}"
        used.add(name)
        node["name"] = name

    log(f"clean: kept {len(kept)} nodes "
        f"(dropped {dropped_bad} bad hosts, {dropped_dup} duplicates)")
    return kept
