# iran-v2ray-finder run report

**Run timestamp:** 2026-11-22 06:58:00 UTC

## Subscription publisher

- Telegram channel: [@aghorbani_84](https://t.me/aghorbani_84)
- Each regional Mihomo profile includes a clearly labelled, non-functional DEMO entry for channel attribution.
- The Base64 subscription remains protocol-clean; no promotional text is injected into its payload.

## Pipeline totals

| Stage | Count |
|---|---|
| Raw configs fetched | 6395 |
| Parsed successfully | 4705 |
| After cleaning/dedupe | 3723 |
| TCP-reachable | 1288 |
| Selected for output | 150 |

## Per-source results

| Source | Configs | URLs ok | URLs failed |
|---|---|---|---|
| PSG | 338 | 2 | 0 |
| R3ZARAHIMI | 1461 | 2 | 0 |
| mahdibland | 4596 | 4 | 0 |

## Protocols in final selection

| Protocol | Nodes |
|---|---|
| vless | 78 |
| vmess | 25 |
| trojan | 25 |
| ss | 22 |

## Top 20 fastest nodes (TCP connect, ms)

| # | Name | Protocol | Server | Port | Latency (ms) |
|---|---|---|---|---|---|
| 1 | 🇽🇽 XX | VLESS | @nepo_v2ray #2 [fast] | vless | 172.67.183.230 | 443 | 5.0 |
| 2 | 🏁RELAY-172.64.145.93-0455 | vmess | 172.64.145.93 | 443 | 5.1 |
| 3 | 🏳️ 💥Config_jo-191#1 | vless | tulip.amydoodles.com | 443 | 5.1 |
| 4 | 🇺🇸 US | VLESS | @manstervpn #1 [fast] | vless | 151.101.3.8 | 80 | 5.1 |
| 5 | 🏁RELAY-104.16.174.37-0920 | trojan | 104.16.174.37 | 443 | 5.2 |
| 6 | 🏁RELAY-141.193.213.20-0441 | vmess | news.microsoft.com | 443 | 5.2 |
| 7 | 🏁RELAY-104.17.177.143-0926 | trojan | 104.17.177.143 | 443 | 5.2 |
| 8 | 🏳️ 💥Config_jo-197#2 | vless | ipfast.kingmna.com | 443 | 5.2 |
| 9 | 🇺🇸 US | VLESS | @msv2raynp #1 [fast] | vless | 151.101.64.155 | 80 | 5.2 |
| 10 | 🇽🇽 XX | VLESS | @kesslervpn #4 [fast] | vless | 172.64.149.54 | 443 | 5.2 |
| 11 | 🇽🇽 XX | VLESS | @nepo_v2ray #5 [fast] | vless | 198.41.202.5 | 2083 | 5.2 |
| 12 | 🏁RELAY-141.101.114.134-0389 | vmess | 141.101.114.134 | 443 | 5.3 |
| 13 | 🏁RELAY-104.18.152.143-1054 | trojan | 104.18.152.143 | 443 | 5.3 |
| 14 | 🏁RELAY-104.18.6.82-0415 | vmess | 104.18.6.82 | 443 | 5.3 |
| 15 | 🏁RELAY-104.26.3.161-1215 | vmess | America.com | 443 | 5.3 |
| 16 | 🏳️ 💥Config_jo-189 | vless | 167.82.76.31 | 443 | 5.3 |
| 17 | 🏳️ 💥Config_jo-201 | vless | midjourney.com | 443 | 5.3 |
| 18 | 🇺🇸 💥Config_jo-274#1 | vless | 216.24.57.1 | 2087 | 5.3 |
| 19 | 🇺🇸 US | VLESS | @garnet_free #2 [fast] | vless | discord.gg | 8080 | 5.3 |
| 20 | 🇽🇽 XX | VLESS | @merdesert #1 [fast] | vless | 104.21.60.171 | 443 | 5.3 |

_Latency is coarse TCP-handshake time measured from GitHub runners; actual usable ranking happens client-side via the `AUTO`/`TOP20` url-test groups._
