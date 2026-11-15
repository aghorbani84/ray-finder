# iran-v2ray-finder

Fully automated, Iran-optimized aggregator of **free V2Ray / Clash Meta (mihomo)** configs.
A GitHub Actions workflow runs every 6 hours, pulls node URIs from public free-proxy
sources, parses `vmess` / `vless` / `trojan` / `ss` / `hysteria2` / `tuic` links,
deduplicates them, TCP-tests reachability, and commits ready-to-use subscription files
back into this repo. **No manual steps after the initial push.**

Target client: [FlClash](https://github.com/chen08209/FlClash) (Clash Meta / mihomo kernel),
but any v2rayN/v2rayNG/Clash-based app works.

## What you get (regenerated automatically)

Each country has its own Clash/Mihomo profile with country-specific DNS, local-traffic DIRECT rules, and a client-side AUTO group. The AUTO group measures the nodes from the user's actual device/network; it is not ranked from GitHub's runner location. All three profiles currently use the same validated public node pool, because a single GitHub runner cannot truthfully benchmark latency from Iran, China, and Russia simultaneously.

| File | Purpose |
|---|---|
| [`output/clash-iran.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-iran.yaml) | Iran DNS, .ir and IR direct routing, AUTO-IRAN client-side node test |
| [`output/clash-china.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-china.yaml) | China DoH DNS, CN geosite/GeoIP direct routing, AUTO-CHINA client-side node test |
| [`output/clash-russia.yaml`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash-russia.yaml) | Russia DNS, .ru and RU direct routing, AUTO-RUSSIA client-side node test |
| [`output/sub.txt`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/sub.txt) | Universal v2rayN/v2rayNG node subscription (unchanged) |
| [`output/report.md`](https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/report.md) | Source stats, protocol mix, selected nodes and run time |

The default `output/clash.yaml` URL remains an alias of the Iran profile for backwards compatibility. The three Clash files are separate configurations; they are not claims that proxy exits are physically located in those countries. True country-origin benchmarking requires runners/probes inside each country.

## How it works

```
sources.json ──► fetch.py   download lists / base64 blobs / clash-yaml (v2rayNG UA)
             ──► parse.py   vmess, vless, trojan, ss (SIP002+legacy), hy2, tuic
             ──► clean.py   drop private IPs / localhost / .ir hosts, dedupe, rename
             ──► test_nodes.py  TCP connect, 3 s timeout, 150 workers, 2 attempts
             ──► build_output.py  cap ~150 nodes (Reality-first, balanced mix)
             ──► output/* + README stats  committed by github-actions[bot]
```

- Schedule: cron `17 */6 * * *` (off-the-hour, less throttled) + manual `workflow_dispatch`.
- Add/remove sources by editing [`sources.json`](sources.json) only — no code changes needed.
- The pipeline never crashes on a dead source or bad node; it always produces output files.

## Enable automation after forking/pushing

1. Push this repo to GitHub.
2. Open **Settings → Actions → General → Workflow permissions** → *Read and write permissions*.
3. Open the **Actions** tab → select *Update configs* → **Enable workflow** (or run
   "Run workflow" once manually). After that it updates itself every 6 hours.

## Subscription Links

The links below point to the default branch of this repository:

- **Clash (mihomo/FlClash):**
  `https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/clash.yaml`
- **Base64 (v2rayN/v2rayNG):**
  `https://raw.githubusercontent.com/aghorbani84/ray-finder/iran-v2ray-config-aggregator-a43af/output/sub.txt`
- **jsDelivr mirror** (use when `raw.githubusercontent.com` is blocked/unreachable from Iran):
  `https://cdn.jsdelivr.net/gh/aghorbani84/ray-finder@iran-v2ray-config-aggregator-a43af/output/clash.yaml`

### FlClash import steps

1. Open FlClash → **Profiles**.
2. Tap **+** → choose **URL**.
3. Paste the Clash link above (or the jsDelivr mirror) → **Save**.
4. Tap the new profile to **select** it, then press the **▶ / Connect** button.

## Run locally

```bash
pip install -r requirements.txt
python scripts/main.py          # full live run (needs internet)
python scripts/main.py --demo   # offline simulated run, generates output/ anyway
```

## Disclaimer

Free proxy nodes are public, unvetted and short-lived. They provide **no privacy guarantee** —
never transmit secrets over them. For real security use your own server. MIT licensed;
use at your own risk.

<!-- STATS:START -->
## 📊 Pipeline stats (last automated run)

- **Last run:** 2026-11-15 21:32 UTC
- **Raw configs fetched:** 6579
- **Reachable after testing:** 2191
- **Nodes shipped in this repo:** **150** (ss: 22, trojan: 25, vless: 78, vmess: 25)
<!-- STATS:END -->
