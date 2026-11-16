"""Parse stage: turn raw node URI lines into normalized node dicts.

Supported schemes: vmess:// (base64 JSON), vless://, trojan://, ss://
(SIP002 and legacy base64), hysteria2:// / hy2://, tuic://, plus the
"clash://" pseudo-scheme emitted by fetch.py for Clash YAML proxies.

A node dict looks like:
  {
    "proto": "vless",              # canonical protocol
    "server": "1.2.3.4", "port": 443,
    "uuid": "...", "password": "...",      # credential fields used by whichever proto
    "network": "ws|grpc|tcp|hysteria2|tuic",
    "tls": ""|"tls"|"reality",     "sni": "...", "alpn": [...],
    "fp": "...", "pbk": "...", "sid": "...", "flow": "...",
    "cipher": "...",               # ss only
    "name": "...",                 # display name (may be empty at this point)
    "source": "barry-far",
    "raw": "<original uri or clash json>",
    "host_header": "...",          # vmess http host if present
  }

parse_line() never raises; it returns None for anything unparseable.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse

from common import PREFIX_MAP, log

_HEX_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _b64pad(s: str) -> bytes | None:
    s = s.strip()
    if not s:
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _safe_port(p) -> int | None:
    try:
        port = int(str(p).split(",")[0].strip())
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _clean_name(frag: str | None) -> str:
    """Decode a percent-encoded fragment into a usable display name."""
    if not frag:
        return ""
    try:
        name = urllib.parse.unquote(frag)
    except Exception:  # noqa: BLE001
        name = frag
    name = re.sub(r"[\r\n\t]+", " ", name).strip()
    return name[:100]


def _split_host_port(netloc: str) -> tuple[str, int | None]:
    """Split 'host:port' (IPv6 in brackets) safely."""
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):  # [::1]:443
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?", netloc)
        if m:
            return m.group(1), _safe_port(m.group(2))
        return netloc, None
    host, _, port_s = netloc.rpartition(":")
    if host:
        return host, _safe_port(port_s)
    return netloc, None


def _params_from_query(query: str) -> dict:
    d = {}
    for key, vals in urllib.parse.parse_qs(query, keep_blank_values=True).items():
        d[key.lower()] = vals[0] if vals else ""
    return d

def _requests_insecure_tls(uri: str, scheme: str) -> bool:
    """Reject source entries that explicitly disable TLS certificate checks."""
    values: dict = {}
    if scheme in ("vless", "trojan", "hysteria2", "hy2", "tuic"):
        query = uri.split("?", 1)[1].split("#", 1)[0] if "?" in uri else ""
        values.update(_params_from_query(query))
    elif scheme in ("vmess", "clash"):
        body = uri.split("://", 1)[1].split("#", 1)[0]
        decoded = _b64pad(body)
        if decoded:
            try:
                obj = json.loads(decoded.decode("utf-8", errors="replace"))
                if isinstance(obj, dict):
                    values.update(obj)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
    for key, value in values.items():
        normalized = str(key).lower().replace("_", "-")
        if normalized in {"allowinsecure", "allow-insecure", "skip-cert-verify",
                          "skipcertverify", "insecure"}:
            if str(value).strip().lower() in {"1", "true", "yes", "on"}:
                return True
    return False


def _node(proto: str, server: str, port, **kw) -> dict | None:
    if not server or port is None:
        return None
    node = {
        "proto": proto,
        "server": server,
        "port": port,
        "uuid": "", "password": "",
        "network": kw.pop("network", "tcp"),
        "tls": kw.pop("tls", ""),
        "sni": kw.pop("sni", ""),
        "alpn": kw.pop("alpn", []),
        "fp": "", "pbk": "", "sid": "", "flow": "",
        "cipher": "", "host_header": "",
        "name": kw.pop("name", ""),
        "source": kw.pop("source", ""),
        "raw": kw.pop("raw", ""),
    }
    node.update(kw)
    if node["network"] in ("", "none"):
        node["network"] = "tcp"
    return node


# --------------------------------------------------------------------------- #
# per-protocol parsers
# --------------------------------------------------------------------------- #

def _parse_vless(uri: str, source: str) -> dict | None:
    body = uri[len("vless://"):]
    creds_part, sep, rest = body.partition("?")
    if not sep:
        rest = ""
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
    uuid_ = creds_part.rsplit("@", 1)[0]
    server, port = _split_host_port(creds_part)
    p = _params_from_query(rest)
    if not _HEX_RE.match(uuid_.strip()):
        return None
    network = (p.get("type") or "tcp").lower()
    tls = p.get("security") or ("tls" if p.get("sni") and network == "grpc" else "")
    node = _node("vless", server, port,
                 uuid=uuid_.strip(),
                 network=network, tls=tls,
                 sni=p.get("sni", ""),
                 alpn=[a for a in re.split(r"[,+]", p.get("alpn", "")) if a],
                 flow=p.get("flow", ""),
                 name=_clean_name(frag), source=source, raw=uri)
    if node:
        node["pbk"], node["sid"], node["fp"] = p.get("pbk", ""), p.get("sid", ""), p.get("fp", "")
        node["path"] = p.get("path", "")
        node["host"] = p.get("host", "")
        node["sni"] = node["sni"] or (p.get("peer", "") if tls == "reality" else "")
    return node


def _parse_trojan(uri: str, source: str) -> dict | None:
    body = uri[len("trojan://"):]
    creds_part, sep, rest = body.partition("?")
    if not sep:
        rest = ""
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
    password = creds_part.rsplit("@", 1)[0]
    server, port = _split_host_port(creds_part)
    p = _params_from_query(rest)
    if not password:
        return None
    node = _node("trojan", server, port,
                 password=password,
                 network=(p.get("type") or "tcp").lower(),
                 tls=p.get("security", "tls" if p.get("sni") else ""),
                 sni=p.get("sni", ""),
                 alpn=[a for a in re.split(r"[,+]", p.get("alpn", "")) if a],
                 name=_clean_name(frag), source=source, raw=uri)
    if node:
        node["path"] = p.get("path", "")
        node["host"] = p.get("host", "")
    return node


def _parse_ss(uri: str, source: str) -> dict | None:
    body = uri[len("ss://"):]
    frag = ""
    if "#" in body:
        body, _, frag = body.partition("#")
    server_part = body
    method = password = ""
    if "@" in body:
        creds_b64_or_plain, _, server_part = body.rpartition("@")
        decoded = _b64pad(creds_b64_or_plain)
        text = decoded.decode("utf-8", errors="replace") if decoded else creds_b64_or_plain
        if ":" in text:                       # SIP002 plain or decoded "method:password"
            method, _, password = text.partition(":")
        else:
            method, password = "", text
    else:
        # fully base64 legacy form: b64("method:password@host:port")
        decoded = _b64pad(body)
        text = decoded.decode("utf-8", errors="replace") if decoded else body
        if "@" in text:
            creds, _, server_part = text.rpartition("@")
        else:
            return None
        method, _, password = creds.partition(":")

    method = method.strip().lower()
    server, port = _split_host_port(server_part)
    if not method or not password or not server or port is None:
        return None
    if not re.match(r"^(aes|chacha|rc4|camellia|aria|bf-|idea|des|salsa|xchacha|2022-blake3)", method):
        return None
    return _node("ss", server, port, password=password, cipher=method,
                 network="tcp", tls="",
                 name=_clean_name(frag), source=source, raw=uri)


def _parse_hy2(uri: str, source: str) -> dict | None:
    scheme_len = uri.lower().index("://") + 3
    body = uri[scheme_len:]
    creds_part, sep, rest = body.partition("?")
    if not sep:
        rest = ""
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
    password = creds_part.rsplit("@", 1)[0]
    server, port = _split_host_port(creds_part)
    p = _params_from_query(rest)
    if not password:
        return None
    node = _node("hysteria2", server, port, password=password,
                 network="hysteria2", tls="tls",
                 sni=p.get("sni", ""),
                 alpn=[a for a in re.split(r"[,+]", p.get("alpn", "h3")) if a] or ["h3"],
                 pbk=p.get("fpk", p.get("public-key", p.get("pk", ""))),
                 name=_clean_name(frag), source=source, raw=uri)
    if node:
        node["obfs"] = p.get("obfs", "")
        node["obfs_password"] = p.get("obfs-password", "")
    return node


def _parse_tuic(uri: str, source: str) -> dict | None:
    body = uri[len("tuic://"):]
    creds_part, sep, rest = body.partition("?")
    if not sep:
        rest = ""
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
    uuid_, _, password = creds_part.rsplit("@", 1)[0].partition(":")
    server, port = _split_host_port(creds_part)
    p = _params_from_query(rest)
    if not uuid_:
        return None
    node = _node("tuic", server, port, uuid=uuid_, password=password,
                 network="tuic", tls="tls",
                 sni=p.get("sni", ""),
                 name=_clean_name(frag), source=source, raw=uri)
    if node:
        node["alpn"] = [a for a in re.split(r"[,+]", p.get("alpn", "h3")) if a]
        node["congestion_control"] = p.get("congestion_control", "cubic")
    return node


def _parse_vmess(uri: str, source: str) -> dict | None:
    body = uri[len("vmess://"):]
    frag = ""
    if "#" in body:
        body, _, frag = body.partition("#")
    decoded = _b64pad(body)
    if not decoded:
        return None
    try:
        obj = json.loads(decoded.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    server = str(obj.get("add") or "").strip()
    port = _safe_port(obj.get("port"))
    uuid_ = str(obj.get("id") or "").strip()
    if not server or port is None or len(uuid_) < 16:
        return None
    net = str(obj.get("net") or "tcp").lower()
    security = str(obj.get("security") or "").lower()
    tlsmap = {"tls": "tls", "reality": "reality", "": ""}
    node = _node("vmess", server, port, uuid=uuid_,
                 network=net if net in ("tcp", "ws", "grpc", "h2", "http", "kcp") else "tcp",
                 tls=tlsmap.get(security, ""),
                 sni=str(obj.get("sni") or obj.get("host") or "") if security else "",
                 name=_clean_name(str(obj.get("ps") or "")) or _clean_name(frag),
                 source=source, raw=uri)
    if node:
        # Mihomo requires alterId for every VMess proxy. Modern VMess uses 0.
        raw_alter_id = obj.get("aid", obj.get("alterId", 0))
        try:
            node["alter_id"] = int(raw_alter_id if raw_alter_id not in (None, "") else 0)
        except (TypeError, ValueError):
            return None
        if node["alter_id"] < 0:
            return None
        node["path"] = str(obj.get("path") or "")
        node["host"] = str(obj.get("host") or "")
        node["host_header"] = node["host"]
        node["alpn"] = [a for a in re.split(r"[,+]", str(obj.get("alpn") or "")) if a]
        node["flow"] = str(obj.get("flow") or "")
        node["pbk"], node["sid"], node["fp"] = (str(obj.get(x) or "") for x in ("pbk", "sid", "fp"))
    return node


def _parse_clash(uri: str, source: str) -> dict | None:
    """Handle the clash:// pseudo-scheme from fetch.py (YAML subscription proxy)."""
    payload = _b64pad(uri[len("clash://"):])
    if not payload:
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    type_map = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
                "ss": "ss", "shadowsocks": "ss", "hysteria2": "hysteria2",
                "hy2": "hysteria2", "tuic": "tuic"}
    proto = type_map.get(str(obj.get("type", "")).lower())
    server = str(obj.get("server") or "").strip()
    port = _safe_port(obj.get("port"))
    if not proto or not server or port is None:
        return None
    net = str(obj.get("network") or obj.get("type") or "tcp").lower()
    node = _node(proto, server, port,
                 uuid=str(obj.get("uuid") or ""),
                 password=str(obj.get("password") or obj.get("uuid") or ""),
                 cipher=str(obj.get("cipher") or ""),
                 network=net if net in ("tcp", "ws", "grpc", "h2", "http", "kcp",
                                        "hysteria2", "tuic") else "tcp",
                 tls="tls" if obj.get("tls") or obj.get("reality-opts") else "",
                 sni=str(obj.get("sni") or obj.get("servername") or ""),
                 alpn=[str(a) for a in obj.get("alpn") or [] if a],
                 name=_clean_name(str(obj.get("name") or "")),
                 source=source, raw=uri)
    if node:
        if node["tls"] not in ("tls", "reality"):
            node["tls"] = ""
        node["pbk"], node["sid"], node["fp"] = (str(obj.get(x) or "") for x in ("reality-pubkey", "reality-short-id", "client-fingerprint"))
        node["path"] = str(obj.get("ws-path") or obj.get("grpc-service-name") or obj.get("path") or "")
        node["host"] = str(obj.get("host") or obj.get("sni") or "")
        node["flow"] = str(obj.get("flow") or "")
        node["udp"] = bool(obj.get("udp", True))
    return node


_PARSERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "trojan": _parse_trojan,
    "ss": _parse_ss,
    "shadowsocks": _parse_ss,
    "hysteria2": _parse_hy2,
    "hy2": _parse_hy2,
    "tuic": _parse_tuic,
    "clash": _parse_clash,
}


def parse_line(uri: str, source: str) -> dict | None:
    """Parse one config line into a node dict, or None. Never raises."""
    try:
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9]*)://", uri)
        if not m:
            return None
        scheme = m.group(1).lower()
        parser = _PARSERS.get(PREFIX_MAP.get(scheme, scheme))
        if parser is None:
            return None
        if _requests_insecure_tls(uri, scheme):
            return None
        node = parser(uri, source)
        if node is not None:
            node["proto"] = PREFIX_MAP.get(node["proto"], node["proto"])
        return node
    except Exception as exc:  # noqa: BLE001 - never crash on a bad node
        log(f"parse: skipped bad line from {source}: {type(exc).__name__} {exc}")
        return None


def parse_all(items: list[tuple[str, str]]) -> list[dict]:
    nodes: list[dict] = []
    failed = 0
    for source, uri in items:
        try:
            node = parse_line(uri, source)
        except Exception:  # noqa: BLE001 - belt & suspenders
            node = None
        if node:
            nodes.append(node)
        else:
            failed += 1
    log(f"parse: {len(nodes)} nodes parsed, {failed} lines rejected")
    return nodes
