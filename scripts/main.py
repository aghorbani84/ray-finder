"""iran-v2ray-finder orchestrator.

Pipeline: fetch -> parse -> clean -> TCP-test -> select -> build outputs
        (output/clash.yaml, output/sub.txt, output/report.md) + README stats.

Design rule: a run must ALWAYS produce the output files, even when every
source is dead. Each stage is wrapped so failures degrade gracefully; only
an invalid generated clash.yaml aborts loudly (per requirements).

Usage:  python scripts/main.py            # full live run
        python scripts/main.py --demo     # offline simulated run (no network)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# allow running both as `python scripts/main.py` and from inside scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_output  # noqa: E402
import build_profiles  # noqa: E402
import clean  # noqa: E402
import fetch  # noqa: E402
import parse  # noqa: E402
import test_nodes  # noqa: E402
from common import MIN_PUBLISH_NODES, log  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def demo_nodes() -> list[dict]:
    """A handful of well-formed node dicts for an offline simulated run."""
    import base64 as b64
    import json as js

    def vmess_uri(name, host, port):
        obj = {"v": "2", "ps": name, "add": host, "port": port,
               "id": "b831381d-6328-4d53-a41a-7c60eeaa980e",
               "aid": "0", "net": "ws", "type": "none", "host": "",
               "path": "/ws", "tls": "tls", "sni": host}
        return "vmess://" + b64.b64encode(js.dumps(obj).encode()).decode()

    items = [
        ("demo", "vless://114f3e3f-7c7e-4f8b-9a3d-2c8e6b9a1f2e"
                 "@speed.cloudflare.com:443?security=reality&type=tcp"
                 "&sni=www.speedtest.net&pbk=SbVKOEMjK0sIlAFgVL3hNfEJ"
                 "GqdaBBxXUdVdHmZnCTg&sid=1357&fp=chrome&flow=xtls-rprx-vision#DE-Reality"),
        ("demo", vmess_uri("NL-🇳🇱 Demo VMess", "speed.cloudflare.com", 443)),
        ("demo", "trojan://deadbeef-cafe-babe-feed-acab12345678"
                 "@www.wikipedia.org:443?sni=www.wikipedia.org&security=tls&type=tcp#US-Demo-Trojan"),
        ("demo", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ="
                 "@203.0.113.10:8388#SS-Demo"),
        ("demo", "hy2://password123@www.github.com:8443?sni=www.github.com#FI-Hysteria2"),
        ("demo", "vless://bad-node-not-a-uuid@127.0.0.1:22#should-be-dropped"),
        ("demo", "trojan://x@localhost:443#localhost-dropped"),
        ("demo", "garbage line that is not a config at all"),
    ]
    return parse.parse_all(items)


def main() -> int:
    ap = argparse.ArgumentParser(description="iran-v2ray-finder pipeline")
    ap.add_argument("--demo", action="store_true",
                    help="offline simulated run with built-in sample nodes")
    args = ap.parse_args()

    log("=== iran-v2ray-finder run started ===")
    totals: dict[str, int] = {}
    source_stats: dict[str, dict] = {}

    # ---- 1. fetch ----------------------------------------------------------
    if args.demo:
        log("main: DEMO mode — skipping network fetch")
        cleaned = clean.clean_nodes(demo_nodes())
        totals.update(fetched=len(cleaned), parsed=len(cleaned),
                      cleaned=len(cleaned))
    else:
        try:
            items, source_stats = fetch.fetch_all(ROOT / "sources.json")
        except Exception as exc:  # noqa: BLE001 - fetch itself never raises
            log(f"main: fetch stage crashed unexpectedly: {exc}")
            items, source_stats = [], {}
        totals["fetched"] = len(items)

        # ---- 2. parse ------------------------------------------------------
        try:
            nodes = parse.parse_all(items)
        except Exception as exc:  # noqa: BLE001
            log(f"main: parse stage crashed: {exc}")
            nodes = []
        totals["parsed"] = len(nodes)

        # ---- 3. clean ------------------------------------------------------
        try:
            cleaned = clean.clean_nodes(nodes)
        except Exception as exc:  # noqa: BLE001
            log(f"main: clean stage crashed: {exc}")
            cleaned = nodes
    totals["cleaned"] = len(cleaned)

    # ---- 4. TCP reachability test -----------------------------------------
    if args.demo:
        # Demo mode is genuinely offline and deterministic; do not resolve or
        # connect to the sample hostnames during CI validation.
        alive = list(cleaned)
        for index, node in enumerate(alive, 1):
            node["latency"] = float(index)
        log("main: DEMO mode — skipping network reachability tests")
    else:
        try:
            alive = test_nodes.test_all(cleaned)
        except Exception as exc:  # noqa: BLE001
            log(f"main: test stage crashed: {exc}")
            alive = []
    totals["alive"] = len(alive)

    # ---- 5. selection -------------------------------------------------------
    try:
        selected = build_output.select_nodes(alive)
    except Exception as exc:  # noqa: BLE001
        log(f"main: select stage crashed: {exc}")
        selected = alive[:150]
    totals["selected"] = len(selected)

    # Fail closed: a source outage or mass node rejection must not overwrite
    # the last known-good subscriptions with empty/near-empty placeholder data.
    if not args.demo and len(selected) < MIN_PUBLISH_NODES:
        raise SystemExit(
            f"main: refusing to publish only {len(selected)} nodes; "
            f"minimum is {MIN_PUBLISH_NODES}. Existing outputs are preserved."
        )

    # ---- 6. outputs ----------------------------------------------------------
    out_dir = ROOT / "output"
    try:
        clash_text = build_output.build_clash_yaml(
            selected, ROOT / "templates" / "clash_template.yaml")
    except SystemExit:
        raise  # invalid clash.yaml must fail loudly per spec
    sub_text = build_output.build_sub_txt(selected)
    report_text = build_output.build_report_md(source_stats, selected, totals)
    build_output.write_outputs(out_dir, clash_text, sub_text, report_text)
    try:
        profile_counts = build_profiles.build_profiles(clash_text, out_dir)
        log(f"main: region profiles generated: {profile_counts}")
    except Exception as exc:  # noqa: BLE001
        log(f"main: region profile generation failed: {type(exc).__name__}: {exc}")
        raise
    build_output.update_readme_stats(ROOT / "README.md", selected, totals)

    log(f"=== run finished: {len(selected)} nodes in output/ ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
