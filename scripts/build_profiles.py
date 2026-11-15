"""Build region-specific Mihomo profiles from the validated base config.

These profiles route traffic local to the selected country DIRECT and all
other traffic through the selected proxy group. They do not claim that proxy
servers themselves are located in that country.
"""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

REGIONS = {
    "iran": {
        "label": "Iran",
        "geosite": "category-ir",
        "suffix": "ir",
        "geoip": "IR",
        "dns": ["178.22.122.100", "185.51.200.2"],
    },
    "china": {
        "label": "China",
        "geosite": "cn",
        "suffix": "cn",
        "geoip": "CN",
        "dns": ["223.5.5.5", "119.29.29.29"],
    },
    "russia": {
        "label": "Russia",
        "geosite": "ru",
        "suffix": "ru",
        "geoip": "RU",
        "dns": ["77.88.8.8", "77.88.8.1"],
    },
}


def build_profiles(base_text: str, out_dir: Path) -> dict[str, int]:
    """Write three validated region-routing profiles; return proxy counts."""
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
        doc["rules"] = [
            f"GEOSITE,{cfg['geosite']},DIRECT",
            f"DOMAIN-SUFFIX,{cfg['suffix']},DIRECT",
            "GEOIP,private,DIRECT,no-resolve",
            f"GEOIP,{cfg['geoip']},DIRECT",
            "MATCH,PROXY",
        ]

        # Never ship an output that disables certificate verification.
        for proxy in doc["proxies"]:
            if isinstance(proxy, dict) and "skip-cert-verify" in proxy:
                proxy["skip-cert-verify"] = False

        groups = doc["proxy-groups"]
        proxy_group = next((g for g in groups
                            if isinstance(g, dict) and g.get("name") == "PROXY"), None)
        if proxy_group is None:
            raise ValueError("base Clash configuration is missing PROXY selector")
        choices = proxy_group.setdefault("proxies", [])
        if "DIRECT" not in choices:
            choices.append("DIRECT")

        dns = doc.setdefault("dns", {})
        policy = dns.setdefault("nameserver-policy", {})
        policy[f"geosite:{cfg['geosite']},+.{cfg['suffix']}"] = cfg["dns"]

        rendered = yaml.safe_dump(
            doc, allow_unicode=True, sort_keys=False, default_flow_style=False,
            width=1000,
        )
        checked = yaml.safe_load(rendered)
        if not isinstance(checked, dict) or not isinstance(checked.get("rules"), list):
            raise ValueError(f"{region} profile failed YAML validation")
        if checked["rules"][-1] != "MATCH,PROXY":
            raise ValueError(f"{region} profile has no final proxy fallback")

        filename = f"clash-{region}.yaml"
        (out_dir / filename).write_text(rendered, encoding="utf-8", newline="\n")
        counts[region] = len(checked["proxies"])

        # Keep the established clash.yaml URL as the Iran-default profile.
        if region == "iran":
            (out_dir / "clash.yaml").write_text(
                rendered, encoding="utf-8", newline="\n"
            )
    return counts
