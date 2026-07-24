# tools/

Standalone operational scripts. None are imported by the app — run them directly.

| file | machine | purpose |
|------|---------|---------|
| `sync-clock.ps1` | both (attacker + victim) | Sync both clocks to a shared NTP source before a two-machine capture, so the attacker's timeline epochs and the victim's packet timestamps line up. Run as Administrator: `powershell -ExecutionPolicy Bypass -File .\tools\sync-clock.ps1` |
| `attacker_flood.py` | attacker (2nd machine) | Lab DDoS generator. Floods a private-range victim with SYN/UDP/ACK/HTTP and writes the `attack_timeline_*.csv` the pipeline grades against. `python tools/attacker_flood.py --target 192.168.1.123` |
| `ddos_attack_simulator.py` | attacker | Older multi-attack simulator (SYN/UDP/ACK/HTTP/Slowloris/port-scan). Writes a `ddos_training_log_*.csv` (different schema from attacker_flood). See `docs/guides/DDoS_TRAINING_GUIDE.md`. |

The **victim-side** capture + verify tool lives with the backend it shares code
with: `project/backend/capture_tool.py` (`list` / `benign` / `verify`).

## Two-machine capture workflow

1. `sync-clock.ps1` on **both** machines (Administrator).
2. Victim: `python project/backend/capture_tool.py benign --iface "<NIC>" --minutes 15 --out data/nsl_kdd/attack_recap.pcapng`
3. Attacker: `python tools/attacker_flood.py --target 192.168.1.123`
4. Copy the attacker's `attack_timeline_*.csv` into `data/attack_timelines/`.
5. Victim: `python project/backend/capture_tool.py verify --pcap data/nsl_kdd/attack_recap.pcapng` — must print **GOOD**.

Only use against hosts and networks you own.
