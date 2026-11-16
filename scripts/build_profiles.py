"""Build independent, country-tuned Mihomo profiles from a shared node pool.

The AUTO-<REGION> url-test group measures latency on the end user's device,
so node ranking adapts to the user's actual network instead of GitHub runner
geography. These are country-specific routing/DNS profiles, not guarantees
that proxy servers physically reside in the selected country.
"""
from __future__ import annotations

import copy
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
    """Create valid selectors for the renamed node labels.

    AUTO-<REGION> means automatic client-side selection for this profile;
    it intentionally tests the shared node pool, not servers geolocated there.
    """
    group_name = f"AUTO-{region.upper()}"
    groups = profile.get("proxy-groups", [])
    selector = next((g for g in groups
                     if isinstance(g, dict) and g.get("name") == "PROXY"), None)
    if selector is None:
        raise ValueError("base Clash configuration is missing PROXY selector")

    regional_groups = [
        {"name": "🌍 اروپا", "type": "url-test", "include-all": True,
         "filter": r"(?i)· اروپا", "url": "https://cp.cloudflare.com/generate_204",
         "interval": 300, "tolerance": 50, "lazy": True},
        {"name": "🌏 آسیا", "type": "url-test", "include-all": True,
         "filter": r"(?i)· آسیا", "url": "https://cp.cloudflare.com/generate_204",
         "interval": 300, "tolerance": 50, "lazy": True},
        {"name": "🌎 آمریکا", "type": "url-test", "include-all": True,
         "filter": r"(?i)· آمریکا", "url": "https://cp.cloudflare.com/generate_204",
         "interval": 300, "tolerance": 50, "lazy": True},
        {"name": "🌏 اقیانوسیه", "type": "url-test", "include-all": True,
         "filter": r"(?i)· اقیانوسیه", "url": "https://cp.cloudflare.com/generate_204",
         "interval": 300, "tolerance": 50, "lazy": True},
        {"name": "🌐 سایر", "type": "url-test", "include-all": True,
         "filter": r"(?i)· سایر", "url": "https://cp.cloudflare.com/generate_204",
         "interval": 300, "tolerance": 50, "lazy": True},
    ]
    regional_names = [g["name"] for g in regional_groups]
    auto_group = {
        "name": group_name,
        "type": "url-test",
        "include-all": True,
        "url": "https://cp.cloudflare.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "lazy": True,
    }

    # Remove legacy filters: they matched the old node names and became empty
    # after proxies were renamed to flag + region labels.
    obsolete = {"AUTO", "DE", "NL", "TR", "AE", "FI", "UK", "US", "OTHER"}
    obsolete.update(regional_names)
    obsolete.add(group_name)
    groups[:] = [g for g in groups if not (
        isinstance(g, dict) and g.get("name") in obsolete
    )]

    selector["proxies"] = [group_name, "TOP20", *regional_names]
    insert_at = groups.index(selector) + 1
    groups[insert_at:insert_at] = [auto_group, *regional_groups]

    available_groups = {
        g.get("name") for g in groups if isinstance(g, dict)
    }
    missing = [name for name in selector["proxies"] if name not in available_groups]
    if missing:
        raise ValueError(f"PROXY selector references missing groups: {missing}")


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
        label_counts = {}
        renamed = {}
        for proxy in doc["proxies"]:
            if isinstance(proxy, dict):
                old_name = str(proxy.get("name", ""))
                label = display_name(old_name)[0]
                label_counts[label] = label_counts.get(label, 0) + 1
                new_name = f"{label} {label_counts[label]:02d}"
                renamed[old_name] = new_name
                proxy["name"] = new_name
        # Keep explicit group references (notably TOP20) valid after renaming.
        for group in doc["proxy-groups"]:
            if isinstance(group, dict) and isinstance(group.get("proxies"), list):
                group["proxies"] = [renamed.get(name, name) for name in group["proxies"]]
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
        # Ensure DNS requests obey the profile routing policy; bootstrap DNS above
        # prevents a proxy-DNS bootstrap loop while resolving proxy endpoints.
        dns["respect-rules"] = True
        dns["nameserver-policy"] = {cfg["policy_key"]: list(cfg["dns"])}
        dns["enable"] = True
        dns["enhanced-mode"] = "fake-ip"
        dns.setdefault("fake-ip-filter", ["*.lan", "*.local"])

        # Preserve per-protocol certificate settings from the node converter.
        # Forcing skip-cert-verify=False breaks nodes whose source lacks SNI.

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
        proxy_names = [p.get("name") for p in checked.get("proxies", [])
                       if isinstance(p, dict)]
        if len(proxy_names) != len(set(proxy_names)):
            raise ValueError(f"{region} profile contains duplicate proxy names")
        if any(p.get("skip-cert-verify") is True
               for p in checked.get("proxies", []) if isinstance(p, dict)):
            raise ValueError(f"{region} profile contains a proxy with TLS verification disabled")
        if checked["dns"].get("respect-rules") is not True:
            raise ValueError(f"{region} profile DNS does not respect routing rules")
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
