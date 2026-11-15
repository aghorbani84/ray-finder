"""Regression tests for generated country-tuned Mihomo profiles."""
from pathlib import Path
import tempfile
import unittest

import yaml

from build_profiles import build_profiles


BASE = {
    "proxies": [
        {"name": "DE-node", "type": "vless", "skip-cert-verify": True},
        {"name": "US-node", "type": "trojan"},
        {"name": "unclassified-node", "type": "ss"},
    ],
    "proxy-groups": [
        {"name": "PROXY", "type": "select",
         "proxies": ["AUTO", "TOP20", "DE", "NL", "OTHER"]},
        {"name": "AUTO", "type": "url-test", "include-all": True},
        {"name": "TOP20", "type": "url-test", "proxies": ["DE-node"]},
        {"name": "DE", "type": "url-test", "include-all": True,
         "filter": "(?i)DE|Germany"},
        {"name": "NL", "type": "url-test", "include-all": True,
         "filter": "(?i)NL|Netherlands"},
        {"name": "OTHER", "type": "select", "include-all": True},
    ],
    "rules": ["MATCH,PROXY"],
}


class RegionalProfileTests(unittest.TestCase):
    def test_all_profiles_have_valid_group_references_and_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            counts = build_profiles(yaml.safe_dump(BASE, allow_unicode=True), Path(tmp))
            self.assertEqual(counts, {"iran": 3, "china": 3, "russia": 3})

            shared_groups = {
                "TOP20", "🌍 اروپا", "🌏 آسیا", "🌎 آمریکا",
                "🌏 اقیانوسیه", "🌐 سایر",
            }
            for region, code, auto_name in (
                ("iran", "IR", "AUTO-IR"),
                ("china", "CN", "AUTO-CHINA"),
                ("russia", "RU", "AUTO-RUSSIA"),
            ):
                doc = yaml.safe_load((Path(tmp) / f"clash-{region}.yaml").read_text())
                group_names = {g["name"] for g in doc["proxy-groups"]}
                missing = (shared_groups | {auto_name}) - group_names
                self.assertFalse(
                    missing,
                    f"{region} missing groups: {sorted(missing)}; actual: {sorted(group_names)}",
                )
                self.assertFalse({"DE", "NL", "OTHER", "AUTO"} & group_names)

                selector = next(g for g in doc["proxy-groups"] if g["name"] == "PROXY")
                self.assertTrue(set(selector["proxies"]).issubset(group_names))
                self.assertEqual(doc["rules"][-1], "MATCH,PROXY")
                self.assertIn(f"GEOIP,{code},DIRECT", doc["rules"])

                top20 = next(g for g in doc["proxy-groups"] if g["name"] == "TOP20")
                self.assertIn("🇩🇪 · اروپا 01", top20["proxies"])
                german = next(p for p in doc["proxies"] if p["name"] == "🇩🇪 · اروپا 01")
                self.assertIs(german["skip-cert-verify"], True)

                for group in doc["proxy-groups"]:
                    if group["name"] in {"🌍 اروپا", "🌏 آسیا", "🌎 آمریکا",
                                         "🌏 اقیانوسیه", "🌐 سایر"}:
                        self.assertTrue(group.get("filter"))
                        self.assertTrue(group.get("include-all"))

            china = yaml.safe_load((Path(tmp) / "clash-china.yaml").read_text())
            self.assertIn("GEOSITE,cn,DIRECT", china["rules"])
            self.assertIn("DOMAIN-SUFFIX,中国,DIRECT", china["rules"])
            russia = yaml.safe_load((Path(tmp) / "clash-russia.yaml").read_text())
            self.assertIn("DOMAIN-SUFFIX,рф,DIRECT", russia["rules"])


if __name__ == "__main__":
    unittest.main()
