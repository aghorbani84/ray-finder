"""Build independent, country-tuned Mihomo profiles from a shared node pool.

The AUTO-<REGION> url-test group measures latency on the end user's device,
so node ranking adapts to the user's actual network instead of GitHub runner
geography. These are country-specific routing/DNS profiles, not guarantees
that proxy servers physically reside in the selected country.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

from region_labels import display_name

REGIONS = {
    "iran": {
        "label": "Iran",
        "code": "IR",
        "suffix": "ir",
        "dns": ["178.22.122.100", "185.51.200.2"],
        "policy_key": "+.ir",
    },
    "china": {
        "label": "China",
        "code": "CN",
        "suffix": "cn",
        "dns": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
        "bootstrap_dns": ["223.5.5.5", "119.29.29.29"],
        "policy_key": "geosite:cn",
    },
    "russia": {
        "label": "Russia",
        "code": "RU",
        "suffix": "ru",
        "dns": ["77.88.8.8", "77.88.8.1"],
        "policy_key": "+.ru",
    },
}


def _country_group(profile: dict, region: str) -> None:
    """Make the primary selector use client-side latency tests for this profile."""
    group_name = f"AUTO-{region.upper()}"
    groups = profile.get("proxy-groups", [])
    selector = next((g for g in groups
                     if isinstance(g, dict) and g.get("name") == "PROXY"), None)
    if selector is None:
        raise ValueError("base Clash configuration is missing PROXY selector")

    # Keep existing alternatives but make the region-specific AUTO test first.
    choices = selector.setdefault("proxies", [])
    choices[:] = [x for x in choices if x not in ("AUTO", group_name)]
    choices.insert(0, group_name)

    auto_group = {
        "name": group_name,
        "type": "url-test",
        "include-all": True,
        "url": "https://cp.cloudflare.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "lazy": True,
    }
    # Insert immediately after the PROXY selector for easier inspection.
    insert_at = groups.index(selector) + 1
    groups[:] = [g for g in groups if not (
        isinstance(g, dict) and g.get("name") == group_name
    )]
    groups.insert(insert_at, auto_group)


def build_profiles(base_text: str, out_dir: Path) -> dict[str, int]:
    """Write three country-specific profiles; return proxy counts."""
    base = yaml.safe_load(base_text)
    if not isinstance(base, dict):
        raise ValueError("base Clash configuration must be a YAML mapping")
    if not isinstance(base.get("proxies"), list):
        raise ValueError("base Clash configuration has no proxies list")
    if not isinstance(base.get("proxy-groups"), list):
        raise ValueError("base Clash configuration has no proxy-groups list")

    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for region, cfg in REGIONS.items():
        doc = copy.deepcopy(base)
        # Country labels are inferred only from explicit source-name tokens.
        for proxy in doc["proxies"]:
            if isinstance(proxy, dict):
                proxy["name"] = display_name(str(proxy.get("name", "")))[0]
        doc["rules"] = [
            "GEOSITE,private,DIRECT",
            "GEOIP,private,DIRECT,no-resolve",
            f"DOMAIN-SUFFIX,{cfg['suffix']},DIRECT",
            f"GEOIP,{cfg['code']},DIRECT",
            "MATCH,PROXY",
        ]
        if region == "china":
            doc["rules"].insert(1, "GEOSITE,cn,DIRECT")
            doc["rules"].insert(2, "DOMAIN-SUFFIX,中国,DIRECT")
        elif region == "russia":
            doc["rules"].insert(1, "DOMAIN-SUFFIX,рф,DIRECT")

        dns = doc.setdefault("dns", {})
        dns["default-nameserver"] = cfg.get("bootstrap_dns", cfg["dns"])
        dns["nameserver"] = list(cfg["dns"])
        dns["proxy-server-nameserver"] = list(cfg.get("bootstrap_dns", cfg["dns"]))
        dns["nameserver-policy"] = {cfg["policy_key"]: list(cfg["dns"])}
        dns["enable"] = True
        dns["enhanced-mode"] = "fake-ip"
        dns.setdefault("fake-ip-filter", ["*.lan", "*.local"])

        # Never ship a profile that disables TLS certificate verification.
        for proxy in doc["proxies"]:
            if isinstance(proxy, dict) and "skip-cert-verify" in proxy:
                proxy["skip-cert-verify"] = False

        _country_group(doc, region)
        rendered = yaml.safe_dump(
            doc, allow_unicode=True, sort_keys=False, default_flow_style=False,
            width=1000,
        )
        checked = yaml.safe_load(rendered)
        expected_group = f"AUTO-{region.upper()}"
        if not isinstance(checked, dict):
            raise ValueError(f"{region} profile is not a YAML mapping")
        if checked.get("rules", [])[-1:] != ["MATCH,PROXY"]:
            raise ValueError(f"{region} profile has no final proxy fallback")
        if checked["dns"].get("nameserver") != cfg["dns"]:
            raise ValueError(f"{region} profile DNS validation failed")
        if not any(g.get("name") == expected_group and g.get("type") == "url-test"
                   for g in checked["proxy-groups"] if isinstance(g, dict)):
            raise ValueError(f"{region} profile missing {expected_group} client-side test")

        filename = f"clash-{region}.yaml"
        (out_dir / filename).write_text(rendered, encoding="utf-8", newline="\n")
        counts[region] = len(checked["proxies"])

        # Keep the established clash.yaml URL as the Iran-default profile.
        if region == "iran":
            (out_dir / "clash.yaml").write_text(
                rendered, encoding="utf-8", newline="\n"
            )
    if len({tuple(REGIONS[r]["dns"]) for r in REGIONS}) != len(REGIONS):
        raise ValueError("country profiles must not share identical DNS configuration")
    return counts
