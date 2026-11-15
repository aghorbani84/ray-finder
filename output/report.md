# iran-v2ray-finder run report

**Run timestamp:** 2026-11-15 21:02:13 UTC

## Pipeline totals

| Stage | Count |
|---|---|
| Raw configs fetched | 6579 |
| Parsed successfully | 6477 |
| After cleaning/dedupe | 5222 |
| TCP-reachable | 2183 |
| Selected for output | 150 |

## Per-source results

| Source | Configs | URLs ok | URLs failed |
|---|---|---|---|
| PSG | 343 | 2 | 0 |
| R3ZARAHIMI | 1569 | 2 | 0 |
| mahdibland | 4667 | 4 | 0 |

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
| 1 | 🏳️ 💥Config_jo-211#1 | vless | 167.82.64.46 | 443 | 5.0 |
| 2 | 🏳️ 💥Config_jo-218 | vless | 199.232.78.120 | 443 | 5.0 |
| 3 | 🏳️ 💥Config_jo-227#1 | vless | 199.232.78.159 | 443 | 5.0 |
| 4 | 🏳️ 💥Config_jo-236#1 | vless | 199.232.78.159 | 443 | 5.0 |
| 5 | 🏁RELAY-172.67.81.238-8355 | vmess | 172.67.81.238 | 443 | 5.1 |
| 6 | 🏁RELAY-172.67.128.37-8412 | vmess | 172.67.128.37 | 2095 | 5.1 |
| 7 | 🏁RELAY-172.67.115.6-8417 | vmess | 172.67.115.6 | 2095 | 5.1 |
| 8 | 🏁RELAY-162.159.248.31-8475 | vmess | 162.159.248.31 | 2095 | 5.1 |
| 9 | 🏳️ 💥Config_jo-197 | vless | 199.232.78.159 | 443 | 5.1 |
| 10 | 🏳️ 💥Config_jo-196 | vless | 199.232.78.120 | 443 | 5.1 |
| 11 | 🏳️ 💥Config_jo-197#1 | vless | 199.232.78.159 | 443 | 5.1 |
| 12 | 🏳️ 💥Config_jo-236 | vless | 199.232.78.160 | 443 | 5.1 |
| 13 | 🏳️ 💥Config_jo-193 | vless | 199.232.78.159 | 443 | 5.1 |
| 14 | 🏳️ 💥Config_jo-236#2 | vless | 167.82.64.47 | 443 | 5.1 |
| 15 | 🏳️ 💥Config_jo-252 | vless | 167.82.76.31 | 443 | 5.1 |
| 16 | 🇺🇸 US | VLESS | @minovpnch #2 [fast] | vless | 151.101.66.219 | 443 | 5.1 |
| 17 | 🏁RELAY-104.16.174.37-0997 | trojan | 104.16.174.37 | 443 | 5.2 |
| 18 | 🏁RELAY-104.16.174.117-1093 | trojan | 104.16.174.117 | 443 | 5.2 |
| 19 | 🏁RELAY-104.17.77.77-0344 | vmess | 104.17.77.77 | 8443 | 5.2 |
| 20 | 🏁RELAY-104.19.42.49-0811 | vmess | 104.19.42.49 | 2082 | 5.2 |

_Latency is coarse TCP-handshake time measured from GitHub runners; actual usable ranking happens client-side via the `AUTO`/`TOP20` url-test groups._
