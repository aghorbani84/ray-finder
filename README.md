# ray-finder

> An automated pipeline that collects public V2Ray / Clash Meta (mihomo) node links, validates them, and publishes ready-to-import subscription files.

[![Update configs](https://github.com/aghorbani84/ray-finder/actions/workflows/update.yml/badge.svg?branch=iran-v2ray-config-aggregator-a43af)](https://github.com/aghorbani84/ray-finder/actions/workflows/update.yml)
[![Validate profiles](https://github.com/aghorbani84/ray-finder/actions/workflows/validate.yml/badge.svg?branch=iran-v2ray-config-aggregator-a43af)](https://github.com/aghorbani84/ray-finder/actions/workflows/validate.yml)
![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

ray-finder is a Python pipeline run on a schedule by GitHub Actions. Every 6 hours it downloads node URIs from the public sources listed in [`sources.json`](sources.json), parses `vmess`, `vless`, `trojan`, `ss`, `hysteria2`, and `tuic` links, removes invalid and duplicate entries, runs a coarse TCP reachability pre-filter, and commits the resulting subscription files to `output/`. No manual steps are needed after the workflow is enabled.

The primary target client is [FlClash](https://github.com/chen08209/FlClash) (mihomo kernel); the plain Base64 subscription also works with v2rayN / v2rayNG and other Clash-based apps.

## Features

- **Multi-format fetching** – plain URI lists, Base64 blobs, and Clash YAML sources
- **Protocol parsing** – vmess, vless (including Reality), trojan, ss (SIP002 and legacy), hysteria2, tuic
- **Cleaning** – drops private IPs, localhost, and `.ir` hosts; deduplicates and renames nodes
- **Selection** – caps output at 150 nodes with a Reality-first, balanced protocol mix
- **Regional profiles** – separate Clash/mihomo profiles for Iran, China, and Russia with region-specific DNS and direct-routing rules
- **On-device health checks** – `AUTO-*` and per-protocol `TEST-*` url-test groups measured from the user's own network
- **Fail-closed publishing** – if fewer than 20 nodes survive validation, the last known-good files are kept
- **CI safeguards** – unit tests, mihomo profile validation, and `pip-audit` dependency checks on every run
- **Offline demo mode** – `--demo` generates output from built-in sample nodes without network access

## Output files

| File | Contents |
| --- | --- |
| [`output/clash-iran.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-iran.yaml) | Iran DNS, `.ir` / IR direct routing, `AUTO-IRAN` group |
| [`output/clash-china.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-china.yaml) | China DoH DNS, CN geosite/GeoIP direct routing, `AUTO-CHINA` group |
| [`output/clash-russia.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-russia.yaml) | Russia DNS, `.ru` / RU direct routing, `AUTO-RUSSIA` group |
| [`output/clash.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash.yaml) | Alias of the Iran profile, kept for backward compatibility |
| [`output/sub.txt`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/sub.txt) | Base64 node subscription for v2rayN / v2rayNG |
| [`output/report.md`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/report.md) | Source stats, protocol mix, selected nodes, run time |
| [`output/telegram.txt`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/telegram.txt) | Publisher information |

All three regional profiles currently share the same node pool. The region names describe the DNS and routing rules, not where proxy exits are located: a single GitHub runner cannot measure latency from inside each country.

Each Clash profile also includes a clearly labelled, intentionally non-functional `DEMO` entry (TEST-NET-1 address, dummy credentials) and a publisher-channel selector. The Base64 subscription contains no comments or placeholder nodes so imports stay valid.

### Subscription URLs

| Client | URL |
| --- | --- |
| Clash / mihomo / FlClash | `https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash.yaml` |
| v2rayN / v2rayNG (Base64) | `https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/sub.txt` |
| jsDelivr mirror (if `raw.githubusercontent.com` is unreachable) | `https://cdn.jsdelivr.net/gh/aghorbani84/ray-finder@iran-v2ray-config-aggregator-a43af/output/clash.yaml` |

**Importing into FlClash:** Profiles → **+** → **URL** → paste a Clash link → **Save**, then select the profile and connect.

## How it works

```
sources.json ─► fetch.py         download lists / base64 blobs / Clash YAML
             ─► parse.py         vmess, vless, trojan, ss, hysteria2, tuic
             ─► clean.py         drop private / localhost / .ir hosts, dedupe, rename
             ─► test_nodes.py    coarse TCP connect pre-filter
             ─► build_output.py  select up to 150 nodes, write output/* and README stats
             ─► build_profiles.py regional Clash/mihomo profiles
```

- **Schedule:** cron `17 */6 * * *` plus manual `workflow_dispatch` ([`update.yml`](.github/workflows/update.yml))
- **Sources:** add or remove them by editing [`sources.json`](sources.json); no code changes needed
- **Resilience:** a dead source or malformed node never crashes the run

### Client-side health and routing

- `AUTO-IRAN`, `AUTO-CHINA`, and `AUTO-RUSSIA` compare all imported nodes from the user's own network.
- `TEST-VLESS`, `TEST-VMESS`, `TEST-TROJAN`, `TEST-SS`, `TEST-HYSTERIA2`, and `TEST-TUIC` isolate each protocol.
- Groups request `https://www.gstatic.com/generate_204` and require HTTP 204; checks run every 180 s with a 5 s timeout and mark a node unavailable after three failures. This measures reachability and latency, not throughput or packet loss.
- A set of AI and work domains (for example `openai.com`, `claude.ai`, `gemini.google.com`) is routed through the `PROXY` group before regional DIRECT rules. Edit `PROXY_DOMAIN_SUFFIXES` in `scripts/build_profiles.py` to change the list. Routing does not guarantee a service is reachable through a given node.

## Getting started

### Run locally

Requires Python 3.11+.

```bash
git clone https://github.com/aghorbani84/ray-finder.git
cd ray-finder
pip install -r requirements.txt
python scripts/main.py          # full live run (needs internet)
python scripts/main.py --demo   # offline run with built-in sample nodes
python -m unittest discover -s scripts -p 'test_*.py' -v   # tests
```

### Enable automation on a fork

1. **Settings → Actions → General → Workflow permissions** → *Read and write permissions*.
2. **Actions** tab → *Update configs* → **Enable workflow** (or **Run workflow** once).

## Project structure

```
├── sources.json              # public source URLs
├── requirements.txt          # requests, PyYAML
├── scripts/
│   ├── main.py               # pipeline orchestrator (--demo for offline runs)
│   ├── fetch.py · parse.py · clean.py · test_nodes.py
│   ├── build_output.py       # node selection, output files, README stats
│   ├── build_profiles.py     # regional Clash/mihomo profiles
│   ├── validate_mihomo.sh    # validates generated profiles with mihomo
│   └── test_*.py             # unit tests
├── templates/clash_template.yaml
└── output/                   # generated files (committed by CI)
```

## Security notes and disclaimer

- Subscription entries that disable TLS certificate verification are rejected; generated Hysteria2/TUIC entries keep verification on.
- DNS is configured to follow profile routing rules. This reduces, but does not rule out, DNS leaks; enable your client's system-proxy/TUN protections and test your own setup.
- Public sources are untrusted input and are not cryptographically attested.
- Free public nodes are unvetted and short-lived, and their operators can observe traffic metadata. Do not send passwords, banking data, or other secrets over them. Use infrastructure you control for meaningful privacy.

Provided under the [MIT License](LICENSE), as is, without warranty.

## Author

Maintained by [aghorbani84](https://github.com/aghorbani84).

<!-- STATS:START -->
## 📊 Pipeline stats (last automated run)

- **Last run:** 2026-11-25 21:15 UTC
- **Raw configs fetched:** 6259
- **Reachable after testing:** 1251
- **Nodes shipped in this repo:** **150** (hysteria2: 1, ss: 22, trojan: 25, vless: 77, vmess: 25)
<!-- STATS:END -->
