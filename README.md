# iran-v2ray-finder

Fully automated, Iran-optimized aggregator of **free V2Ray / Clash Meta (mihomo)** configs.
A GitHub Actions workflow runs every 6 hours, pulls node URIs from public free-proxy
sources, parses `vmess` / `vless` / `trojan` / `ss` / `hysteria2` / `tuic` links,
deduplicates them, TCP-tests reachability, and commits ready-to-use subscription files
back into this repo. **No manual steps after the initial push.**

Target client: [FlClash](https://github.com/chen08209/FlClash) (Clash Meta / mihomo kernel),
but any v2rayN/v2rayNG/Clash-based app works.

## What you get (regenerated automatically)

| File | Purpose |
|---|---|
| [`output/clash.yaml`](https://raw.githubusercontent.com/YOUR_USERNAME/iran-v2ray-finder/main/output/clash.yaml) | Full mihomo config: proxies + AUTO/TOP20/regional groups + Iran routing rules |
| [`output/sub.txt`](https://raw.githubusercontent.com/YOUR_USERNAME/iran-v2ray-finder/main/output/sub.txt) | Node URIs, plain + base64 (universal v2rayN/v2rayNG subscription) |
| [`output/report.md`](https://raw.githubusercontent.com/YOUR_USERNAME/iran-v2ray-finder/main/output/report.md) | Per-source stats, protocol mix, top-20 fastest nodes |

The Clash config is Iran-optimized: Iranian domains/IPs go **DIRECT** (GEOSITE/GEOIP rules),
split DNS with Iranian resolvers for `.ir`, fake-ip mode, and a `url-test` group that picks
the fastest exit client-side. Ports `7890/7891/9090` on localhost match common UFW setups.

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

Replace `YOUR_USERNAME` with your GitHub username:

- **Clash (mihomo/FlClash):**
  `https://raw.githubusercontent.com/YOUR_USERNAME/iran-v2ray-finder/main/output/clash.yaml`
- **Base64 (v2rayN/v2rayNG):**
  `https://raw.githubusercontent.com/YOUR_USERNAME/iran-v2ray-finder/main/output/sub.txt`
- **jsDelivr mirror** (use when `raw.githubusercontent.com` is blocked/unreachable from Iran):
  `https://cdn.jsdelivr.net/gh/YOUR_USERNAME/iran-v2ray-finder@main/output/clash.yaml`

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

- **Last run:** 2026-11-15 20:33 UTC
- **Raw configs fetched:** 6579
- **Reachable after testing:** 2192
- **Nodes shipped in this repo:** **150** (ss: 22, trojan: 25, vless: 78, vmess: 25)
<!-- STATS:END -->
