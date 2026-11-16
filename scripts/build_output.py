"""Build stage: turn selected nodes into the final artifacts.

Produces (all under output/):
  * clash.yaml  — full mihomo config: template + converted proxies + TOP20 names
  * sub.txt     — selected node URIs, one per line, then base64-encoded ONCE
                  (universal v2rayN/v2rayNG subscription format)
  * report.md   — per-source / per-protocol counts, top-20 fastest, timestamp

Also updates the "pipeline stats" section of README.md between markers.

Every function validates its output before writing; yaml.safe_load is used
as a gate on clash.yaml and an invalid document aborts loudly (SystemExit).
All files are written with LF line endings only.
"""

from __future__ import annotations

import base64
import datetime as dt
import re
import sys
from pathlib import Path

import yaml

from common import MAX_NODES, PROTOCOLS, TOP_N, log

# --------------------------------------------------------------------------- #
# node dict -> mihomo proxy dict
# --------------------------------------------------------------------------- #


def _node_to_proxy(node: dict) -> dict | None:
    """Convert a normalized node dict to a mihomo proxy dict. None if unusable."""
    try:
        proto = node["proto"]
        base = {
            "name": node["name"],
            "server": node["server"],
            "port": node["port"],
        }
        network = node.get("network", "tcp") or "tcp"
        tls = node.get("tls", "")
        sni = node.get("sni", "")
        alpn = [a for a in node.get("alpn", []) if a]
        path = node.get("path", "") or ""
        host_hdr = node.get("host", "") or node.get("host_header", "") or ""

        def ws_opts(group: dict) -> None:
            if network == "ws":
                group["ws-opts"] = {"path": path or "/"}
                if host_hdr:
                    group["ws-opts"]["headers"] = {"Host": host_hdr}
            elif network == "grpc":
                group["grpc-opts"] = {"grpc-service-name": path or ""}
            elif network in ("h2", "http"):
                group["h2-opts"] = {"path": path or "/"}
                if host_hdr:
                    group["h2-opts"]["host"] = [host_hdr]

        if proto == "vless":
            p = dict(base, type="vless", uuid=node.get("uuid", ""),
                     network=network if network != "raw" else "tcp")
            if node.get("flow"):
                p["flow"] = node["flow"]
            if tls == "reality":
                # Reality needs complete key/SNI material; incomplete entries
                # are rejected rather than emitted as broken proxy definitions.
                if not node.get("pbk") or not sni:
                    return None
                p.update({
                    "tls": True,
                    "reality-opts": {"public-key": node["pbk"],
                                     "short-id": node.get("sid", "")},
                    "client-fingerprint": node.get("fp") or "chrome",
                    "servername": sni,
                    "udp": True,
                })
            elif tls == "tls":
                p["tls"] = True
                if sni:
                    p["servername"] = sni
                if alpn:
                    p["alpn"] = alpn
            ws_opts(p)
            return p

        if proto == "vmess":
            p = dict(base, type="vmess", uuid=node.get("uuid", ""),
                     alterId=int(node.get("alter_id", 0)),
                     cipher=node.get("cipher") or "auto",
                     network=network)
            if tls == "tls":
                p["tls"] = True
                if sni:
                    p["servername"] = sni
                if alpn:
                    p["alpn"] = alpn
            ws_opts(p)
            return p

        if proto == "trojan":
            p = dict(base, type="trojan", password=node.get("password", ""),
                     network=network)
            if tls in ("tls", "reality"):
                p["tls"] = True
                if sni:
                    p["servername"] = sni
                if alpn:
                    p["alpn"] = alpn
            ws_opts(p)
            return p

        if proto == "ss":
            p = dict(base, type="ss",
                     cipher=node.get("cipher", ""),
                     password=node.get("password", ""),
                     udp=True)
            if not p["cipher"] or not p["password"]:
                return None
            return p

        if proto == "hysteria2":
            p = dict(base, type="hysteria2",
                     password=node.get("password", ""),
                     sni=sni or node["server"], udp=True)
            if node.get("obfs"):
                p["obfs"] = node["obfs"]
                p["obfs-password"] = node.get("obfs_password", "")
            # Certificate verification stays enabled; server is the fallback SNI.
            return p

        if proto == "tuic":
            p = dict(base, type="tuic",
                     uuid=node.get("uuid", ""),
                     password=node.get("password", ""),
                     congestion_control=node.get("congestion_control", "cubic"),
                     udp=True)
            # Never disable certificate verification for TUIC nodes.
            p["sni"] = sni or node["server"]
            if alpn:
                p["alpn"] = alpn
            return p

        return None
    except Exception as exc:  # noqa: BLE001 - never crash on a bad node
        log(f"build: failed converting node '{node.get('name', '?')}': "
            f"{type(exc).__name__} {exc}")
        return None


# --------------------------------------------------------------------------- #
# selection: cap at MAX_NODES, balanced across protocols, prefer VLESS+Reality
# --------------------------------------------------------------------------- #


def select_nodes(nodes: list[dict], cap: int = MAX_NODES) -> list[dict]:
    """Pick the best `cap` nodes from latency-sorted reachable nodes.

    Strategy: reserve quota per protocol so one giant vmess dump cannot crowd
    out everything else, always keep every VLESS+Reality node we can (they
    work best against Iran's filtering), then fill remaining slots fastest-first.
    """
    if len(nodes) <= cap:
        return list(nodes)

    reality = [n for n in nodes if n["proto"] == "vless" and n.get("tls") == "reality"]
    picked: list[dict] = []
    picked_ids: set[int] = set()

    # 1. VLESS+Reality first (up to 35% of the cap).
    reality_quota = min(len(reality), max(5, cap * 35 // 100))
    for n in reality[:reality_quota]:
        picked.append(n)
        picked_ids.add(id(n))

    # 2. Balanced pass over the rest: round-robin per protocol by latency.
    per_proto: dict[str, list[dict]] = {p: [] for p in PROTOCOLS}
    for n in nodes:
        if id(n) in picked_ids:
            continue
        per_proto.setdefault(n["proto"], []).append(n)

    quotas = {"vless": cap * 30 // 100, "vmess": cap * 25 // 100,
              "trojan": cap * 20 // 100, "ss": cap * 15 // 100,
              "hysteria2": cap * 8 // 100, "tuic": cap * 2 // 100}
    taken = {p: 0 for p in per_proto}
    progressed = True
    while len(picked) < cap and progressed:
        progressed = False
        for p in per_proto:
            if len(picked) >= cap:
                break
            if taken.get(p, 0) >= quotas.get(p, 0):
                continue
            pool = per_proto[p]
            if taken.get(p, 0) < len(pool):
                picked.append(pool[taken[p]])
                taken[p] += 1
                progressed = True

    # 3. If quotas left slots empty (some protocol had too few nodes),
    #    fill with the fastest remaining nodes overall.
    if len(picked) < cap:
        chosen_ids = {id(n) for n in picked}
        for n in nodes:
            if len(picked) >= cap:
                break
            if id(n) not in chosen_ids:
                picked.append(n)
                chosen_ids.add(id(n))

    picked.sort(key=lambda n: n.get("latency", 1e9))
    log(f"select: {len(picked)} nodes chosen of {len(nodes)} reachable "
        f"(reality kept: {min(len(reality), reality_quota)})")
    return picked


# --------------------------------------------------------------------------- #
# artifact writers
# --------------------------------------------------------------------------- #


def build_clash_yaml(nodes: list[dict], template_path: Path) -> str:
    """Merge converted proxies into the template; validate; return YAML text."""
    template = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    if not isinstance(template, dict):
        raise SystemExit("build: clash template is not a mapping — aborting")

    proxies: list[dict] = []
    seen_names: set[str] = set()
    for node in nodes:
        p = _node_to_proxy(node)
        if p and p["name"] not in seen_names:
            seen_names.add(p["name"])
            proxies.append(p)

    doc = dict(template)
    doc["proxies"] = proxies

    # inject TOP20 group members (fastest TOP_N already sorted by latency)
    top_names = [n["name"] for n in nodes[:TOP_N] if n["name"] in seen_names]
    groups = []
    for g in doc.get("proxy-groups", []):
        g = dict(g)
        if g.get("name") == "TOP20":
            g["proxies"] = top_names or ["REJECT_PLACEHOLDER"]
        groups.append(g)
    doc["proxy-groups"] = groups

    if not proxies:
        # keep the file loadable by mihomo even when zero nodes survived
        doc["proxies"] = [{
            "name": "PLACEHOLDER-DIRECT",
            "type": "direct",
            "server": "127.0.0.1",
            "port": 1,
        }]
        for g in doc["proxy-groups"]:
            if g.get("name") == "TOP20":
                g["proxies"] = ["PLACEHOLDER-DIRECT"]
            g.pop("include-all", None) if g.get("proxies") == ["REJECT_PLACEHOLDER"] else None

    text = yaml.dump(doc, allow_unicode=True, sort_keys=False,
                     default_flow_style=False, width=1000)

    # hard validation gate — fail loudly if the produced config is invalid
    try:
        reparsed = yaml.safe_load(text)
        assert isinstance(reparsed, dict) and "proxies" in reparsed \
            and "proxy-groups" in reparsed and "rules" in reparsed
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"build: generated clash.yaml is INVALID — aborting: {exc}")
    log(f"build: clash.yaml validated OK ({len(proxies)} proxies)")
    return text


def build_sub_txt(nodes: list[dict]) -> str:
    """Plain URI lines followed by ONE single-line base64 blob of all URIs."""
    uris = []
    for n in nodes:
        raw = n.get("raw", "")
        if raw.startswith("clash://"):
            continue  # pseudo-scheme, not a real share link
        uris.append(raw)
    joined = "\n".join(uris)
    encoded = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    assert "\n" not in encoded and "\r" not in encoded
    body = joined + "\n" + encoded + "\n" if uris else encoded + "\n"
    return body.replace("\r\n", "\n").replace("\r", "\n")


def build_report_md(source_stats: dict, nodes: list[dict], totals: dict) -> str:
    """Markdown run report: per-source, per-protocol, top-20, timestamp."""
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# iran-v2ray-finder run report",
        "",
        f"**Run timestamp:** {now}",
        "",
        "## Subscription publisher",
        "",
        "- Telegram channel: [@aghorbani_84](https://t.me/aghorbani_84)",
        "- Each regional Mihomo profile includes a clearly labelled, non-functional DEMO entry for channel attribution.",
        "- The Base64 subscription remains protocol-clean; no promotional text is injected into its payload.",
        "",
        "## Pipeline totals",
        "",
        "| Stage | Count |",
        "|---|---|",
        f"| Raw configs fetched | {totals.get('fetched', 0)} |",
        f"| Parsed successfully | {totals.get('parsed', 0)} |",
        f"| After cleaning/dedupe | {totals.get('cleaned', 0)} |",
        f"| TCP-reachable | {totals.get('alive', 0)} |",
        f"| Selected for output | {totals.get('selected', 0)} |",
        "",
        "## Per-source results",
        "",
        "| Source | Configs | URLs ok | URLs failed |",
        "|---|---|---|---|",
    ]
    for name, st in sorted(source_stats.items()):
        lines.append(f"| {name} | {st.get('configs', 0)} | "
                     f"{st.get('urls_ok', 0)} | {st.get('urls_failed', 0)} |")

    by_proto: dict[str, int] = {}
    for n in nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    lines += ["", "## Protocols in final selection", "",
              "| Protocol | Nodes |", "|---|---|"]
    for proto in PROTOCOLS:
        if by_proto.get(proto):
            lines.append(f"| {proto} | {by_proto[proto]} |")

    lines += ["", f"## Top {TOP_N} fastest nodes (TCP connect, ms)", "",
              "| # | Name | Protocol | Server | Port | Latency (ms) |",
              "|---|---|---|---|---|---|"]
    for i, n in enumerate(nodes[:TOP_N], 1):
        lines.append(f"| {i} | {n['name']} | {n['proto']} | {n['server']} | "
                     f"{n['port']} | {n.get('latency', '-')} |")
    lines += ["", "_Latency is coarse TCP-handshake time measured from GitHub "
              "runners; actual usable ranking happens client-side via the "
              "`AUTO`/`TOP20` url-test groups._", ""]
    return "\n".join(lines).replace("\r\n", "\n")


README_START = "<!-- STATS:START -->"
README_END = "<!-- STATS:END -->"


def update_readme_stats(readme_path: Path, nodes: list[dict], totals: dict) -> None:
    """Rewrite the marked stats block inside README.md (creates markers if absent)."""
    if not readme_path.exists():
        return
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_proto: dict[str, int] = {}
    for n in nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    proto_line = ", ".join(f"{p}: {c}" for p, c in sorted(by_proto.items())) or "none"
    block = (
        f"{README_START}\n"
        f"## 📊 Pipeline stats (last automated run)\n\n"
        f"- **Last run:** {now}\n"
        f"- **Raw configs fetched:** {totals.get('fetched', 0)}\n"
        f"- **Reachable after testing:** {totals.get('alive', 0)}\n"
        f"- **Nodes shipped in this repo:** **{totals.get('selected', 0)}** "
        f"({proto_line})\n"
        f"{README_END}"
    )
    text = readme_path.read_text(encoding="utf-8")
    if README_START in text and README_END in text:
        new = re.sub(
            re.escape(README_START) + r".*?" + re.escape(README_END),
            lambda _m: block,
            text,
            flags=re.DOTALL,
        )
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"
    readme_path.write_text(new.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
    log("build: README stats section updated")


def write_outputs(out_dir: Path, clash_text: str, sub_text: str,
                  report_text: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    telegram_text = (
        "Ray Finder — subscription information\\n"
        "Telegram channel: https://t.me/aghorbani_84\\n"
        "The DEMO entry in Clash profiles is intentionally non-functional.\\n"
        "Use real nodes from the generated subscription; never treat the DEMO entry as a server.\\n"
    )
    for name, content in (("clash.yaml", clash_text), ("sub.txt", sub_text),
                          ("report.md", report_text), ("telegram.txt", telegram_text)):
        path = out_dir / name
        path.write_text(content.replace("\r\n", "\n").replace("\r", "\n"),
                        encoding="utf-8", newline="\n")
        log(f"build: wrote {path} ({len(content)} chars)")


if __name__ == "__main__":
    raise SystemExit("use scripts/main.py")
