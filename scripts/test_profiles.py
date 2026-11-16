"""Regression tests for generated country-tuned Mihomo profiles."""
from pathlib import Path
import tempfile
import unittest

import yaml

from build_profiles import build_profiles
from build_output import _node_to_proxy
from parse import parse_line


BASE = {
    "proxies": [
        {"name": "DE-node", "type": "vless", "skip-cert-verify": False},
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

    def test_explicit_insecure_tls_uri_is_rejected(self):
        uri = (
            "vless://45948c7b-cd85-4040-92b2-9e634e9ddd52@example.com:443"
            "?security=tls&sni=example.com&allowInsecure=1#unsafe"
        )
        self.assertIsNone(parse_line(uri, "test"))

    def test_insecure_vmess_and_clash_entries_are_rejected(self):
        import base64
        import json

        vmess = {
            "add": "example.com", "port": 443,
            "id": "45948c7b-cd85-4040-92b2-9e634e9ddd52",
            "net": "ws", "tls": "tls", "skip-cert-verify": True,
        }
        vmess_uri = "vmess://" + base64.b64encode(json.dumps(vmess).encode()).decode()
        self.assertIsNone(parse_line(vmess_uri, "test"))

        clash = {
            "name": "unsafe", "type": "trojan", "server": "example.com",
            "port": 443, "password": "secret", "tls": True,
            "skip-cert-verify": True,
        }
        clash_uri = "clash://" + base64.b64encode(json.dumps(clash).encode()).decode()
        self.assertIsNone(parse_line(clash_uri, "test"))

    def test_hysteria2_and_tuic_keep_certificate_verification_enabled(self):
        hy2 = _node_to_proxy({
            "proto": "hysteria2", "name": "hy2", "server": "hy2.example.com",
            "port": 443, "password": "secret", "sni": "",
        })
        tuic = _node_to_proxy({
            "proto": "tuic", "name": "tuic", "server": "tuic.example.com",
            "port": 443, "uuid": "45948c7b-cd85-4040-92b2-9e634e9ddd52",
            "password": "secret", "sni": "",
        })
        self.assertNotIn("skip-cert-verify", hy2)
        self.assertNotIn("skip-cert-verify", tuic)
        self.assertEqual(hy2["sni"], "hy2.example.com")
        self.assertEqual(tuic["sni"], "tuic.example.com")

    def test_reality_without_public_key_or_sni_is_rejected(self):
        proxy = _node_to_proxy({
            "proto": "vless", "name": "bad-reality", "server": "example.com",
            "port": 443, "uuid": "45948c7b-cd85-4040-92b2-9e634e9ddd52",
            "tls": "reality", "pbk": "", "sni": "",
        })
        self.assertIsNone(proxy)

    def test_all_profiles_have_valid_group_references_and_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            counts = build_profiles(yaml.safe_dump(BASE, allow_unicode=True), Path(tmp))
            self.assertEqual(counts, {"iran": 4, "china": 4, "russia": 4})

            protocol_groups = {
                "TEST-VLESS", "TEST-VMESS", "TEST-TROJAN",
                "TEST-SS", "TEST-HYSTERIA2", "TEST-TUIC",
            }
            shared_groups = {
                "TOP20", "🌍 اروپا", "🌏 آسیا", "🌎 آمریکا",
                "🌏 اقیانوسیه", "🌐 سایر", *protocol_groups,
            }
            for region, code, auto_name in (
                ("iran", "IR", "AUTO-IRAN"),
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
                # AI/work sites must use PROXY before regional DIRECT policies.
                for domain in ("muse.ai", "manus.im", "chatgpt.com", "openai.com",
                               "claude.ai", "anthropic.com", "perplexity.ai",
                               "gemini.google.com", "aistudio.google.com", "ai.google.dev"):
                    route = f"DOMAIN-SUFFIX,{domain},PROXY"
                    self.assertIn(route, doc["rules"])
                    self.assertLess(doc["rules"].index(route),
                                    doc["rules"].index(f"DOMAIN-SUFFIX,{region[:2]},DIRECT")
                                    if region in {"iran", "russia"} else doc["rules"].index("GEOSITE,cn,DIRECT"))
                self.assertIs(doc["dns"]["respect-rules"], True)
                self.assertEqual(len(doc["proxies"]), len({p["name"] for p in doc["proxies"]}))
                self.assertFalse(any(p.get("skip-cert-verify") is True for p in doc["proxies"]))
                demo = next(p for p in doc["proxies"] if "(DEMO - غیرقابل اتصال)" in p["name"])
                self.assertEqual(demo["server"], "192.0.2.1")
                self.assertEqual(demo["password"], "NOT-A-REAL-PASSWORD")
                demo_group = next(g for g in doc["proxy-groups"] if g["name"] == "📢 کانال تلگرام")
                self.assertEqual(demo_group["proxies"], [demo["name"]])
                self.assertIn(f"GEOIP,{code},DIRECT", doc["rules"])

                top20 = next(g for g in doc["proxy-groups"] if g["name"] == "TOP20")
                self.assertIn("[VLESS] 🇩🇪 · اروپا 01", top20["proxies"])
                german = next(p for p in doc["proxies"] if p["name"] == "[VLESS] 🇩🇪 · اروپا 01")
                self.assertIs(german["skip-cert-verify"], False)

                for group in doc["proxy-groups"]:
                    if group["name"] in {"🌍 اروپا", "🌏 آسیا", "🌎 آمریکا",
                                         "🌏 اقیانوسیه", "🌐 سایر", *protocol_groups}:
                        self.assertTrue(group.get("filter"))
                        self.assertTrue(group.get("include-all"))
                        self.assertEqual(group.get("expected-status"), 204)
                        self.assertEqual(group.get("timeout"), 5000)
                        self.assertEqual(group.get("max-failed-times"), 3)

                vless_group = next(g for g in doc["proxy-groups"] if g["name"] == "TEST-VLESS")
                self.assertRegex("[VLESS] 🇩🇪 · اروپا 01", vless_group["filter"])
                self.assertNotRegex("[TROJAN] 🇺🇸 · آمریکا 01", vless_group["filter"])

            china = yaml.safe_load((Path(tmp) / "clash-china.yaml").read_text())
            self.assertIn("GEOSITE,cn,DIRECT", china["rules"])
            self.assertIn("DOMAIN-SUFFIX,中国,DIRECT", china["rules"])
            russia = yaml.safe_load((Path(tmp) / "clash-russia.yaml").read_text())
            self.assertIn("DOMAIN-SUFFIX,рф,DIRECT", russia["rules"])


if __name__ == "__main__":
    unittest.main()
