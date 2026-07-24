"""
Victim-side capture helper for building the Day-2 datasets.

Two jobs, both run ON THE MACHINE BEING PROTECTED (192.168.1.123):

  list      Show capture interfaces so you can pick the right one.

  benign    Record N minutes of normal traffic (no attacks running) -> the new
            training baseline. The current models were trained on a different
            network, which is why they misjudge this one.

  verify    THE IMPORTANT ONE. Reads a freshly-captured attack pcap plus the
            attack_timeline_*.csv the attacker tool emitted, and checks whether
            the capture actually recorded the inbound attack. It compares SYN
            packets arriving AT the victim against the timeline's packets_sent.
            The previous capture failed here: 11 SYNs recorded vs 3,301 sent,
            because scapy-injected frames bypassed the local capture path. If
            verify still shows a huge shortfall, the capture is broken and Day 2
            must not proceed on it.

Capture uses Wireshark's dumpcap (the lightweight capture engine, no GUI).
Default path is the standard Windows install; override with --dumpcap.

pandas/numpy import before scapy on purpose - the reverse order segfaults the
Anaconda build on this machine. scapy is only touched by `verify`.

Examples
--------
  python capture_tool.py list
  python capture_tool.py benign --iface "Ethernet 5" --minutes 60 \
      --out ..\\..\\data\\baseline_capture\\benign.pcapng
  python capture_tool.py verify \
      --pcap ..\\..\\data\\nsl_kdd\\attack_recap.pcapng --victim 192.168.1.123
"""
import os
import sys
import glob
import argparse
import subprocess
from collections import defaultdict

import pandas as pd

DUMPCAP_DEFAULT = r"C:\Program Files\Wireshark\dumpcap.exe"
TIMELINE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "attack_timelines"))


def _find_dumpcap(path):
    if os.path.isfile(path):
        return path
    for c in (r"C:\Program Files\Wireshark\dumpcap.exe",
              r"C:\Program Files (x86)\Wireshark\dumpcap.exe"):
        if os.path.isfile(c):
            return c
    sys.exit(f"[-] dumpcap not found. Install Wireshark or pass --dumpcap. Tried: {path}")


def cmd_list(args):
    dc = _find_dumpcap(args.dumpcap)
    print(f"[+] {dc} -D\n")
    subprocess.run([dc, "-D"], check=False)
    print("\n[i] Use the NAME in quotes (e.g. \"Ethernet 5\") as --iface.")


def cmd_benign(args):
    dc = _find_dumpcap(args.dumpcap)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    seconds = int(args.minutes * 60)
    # -a duration:N stops cleanly after N seconds; -w writes pcapng.
    cmd = [dc, "-i", args.iface, "-a", f"duration:{seconds}", "-w", args.out]
    print(f"[+] Capturing {args.minutes} min of BENIGN traffic on '{args.iface}'")
    print(f"    -> {os.path.abspath(args.out)}")
    print("[!] Make sure NO attack simulation is running during this capture.\n")
    print("    " + " ".join(f'"{c}"' if " " in c else c for c in cmd) + "\n")
    subprocess.run(cmd, check=False)
    if os.path.isfile(args.out):
        mb = os.path.getsize(args.out) / 1e6
        print(f"\n[+] Done: {os.path.abspath(args.out)} ({mb:.1f} MB)")
    else:
        print("\n[-] No output file produced - check the interface name with `list`.")


def _load_segments(timeline_dir):
    segs = []
    for path in sorted(glob.glob(os.path.join(timeline_dir, "attack_timeline_*.csv"))):
        df = pd.read_csv(path, keep_default_na=False)
        for _, r in df.iterrows():
            segs.append({
                "attack_type": str(r["attack_type"]).strip(),
                "target": str(r["target"]).strip(),
                "start": float(r["start_epoch"]),
                "end": float(r["end_epoch"]),
                "packets_sent": int(float(r.get("packets_sent", 0) or 0)),
            })
    return segs


def cmd_verify(args):
    from scapy.config import conf
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP])
    from scapy.all import PcapReader

    segs = [s for s in _load_segments(args.timeline_dir) if s["target"] == args.victim]
    if not segs:
        sys.exit(f"[-] No attack_timeline segments for victim {args.victim} in {args.timeline_dir}")
    t_lo = min(s["start"] for s in segs) - 5
    t_hi = max(s["end"] for s in segs) + 5

    # Per segment: count packets whose timestamp falls in it and are TCP SYNs
    # arriving AT the victim (dst == victim, SYN set, ACK clear).
    inbound_syn = defaultdict(int)
    inbound_any = defaultdict(int)
    n_read = 0
    reader = PcapReader(args.pcap)
    try:
        for pkt in reader:
            n_read += 1
            ts = float(pkt.time)
            if ts > t_hi:
                break
            if ts < t_lo or not pkt.haslayer("IP"):
                continue
            if pkt["IP"].dst != args.victim:
                continue
            for i, s in enumerate(segs):
                if s["start"] <= ts <= s["end"]:
                    inbound_any[i] += 1
                    if pkt.haslayer("TCP"):
                        f = int(pkt["TCP"].flags)
                        if (f & 0x02) and not (f & 0x10):   # SYN and not ACK
                            inbound_syn[i] += 1
                    break
    except (EOFError, StopIteration):
        pass
    finally:
        try:
            reader.close()
        except Exception:
            pass

    print(f"\n[+] Read {n_read:,} packets; {len(segs)} segments target {args.victim}\n")
    print(f"  {'#':>3} {'attack':<8} {'sent':>8} {'inbound@victim':>15} "
          f"{'inbound SYN':>12} {'SYN/sent':>9}  status")
    print("  " + "-" * 72)
    syn_segs = ok = 0
    for i, s in enumerate(segs):
        sent = s["packets_sent"]
        anyp = inbound_any.get(i, 0)
        syn = inbound_syn.get(i, 0)
        is_syn_attack = s["attack_type"].upper().startswith("SYN")
        # For SYN attacks compare SYN count; for others compare total inbound.
        ref = syn if is_syn_attack else anyp
        ratio = ref / sent if sent else 0.0
        if is_syn_attack:
            syn_segs += 1
        status = "OK" if ratio >= 0.5 else ("LOW" if ratio > 0.05 else "MISSING")
        if ratio >= 0.5:
            ok += 1
        print(f"  {i:>3} {s['attack_type']:<8} {sent:>8,} {anyp:>15,} "
              f"{syn:>12,} {ratio:>8.1%}  {status}")

    print("  " + "-" * 72)
    print(f"\n  {ok}/{len(segs)} segments captured >=50% of sent packets.")
    if ok < len(segs):
        print("\n  [!] VERDICT: capture is INCOMPLETE. The attack traffic is not fully")
        print("      landing in the pcap (likely capturing the victim's replies, not the")
        print("      inbound flood). Do NOT use this file for Day-2 training/eval.")
        print("      Fix: run the attacker from a SEPARATE host and capture on the victim's")
        print("      NIC that actually receives the flood.")
    else:
        print("\n  [+] VERDICT: capture looks GOOD. Inbound attack traffic is present.")
        print("      Safe to proceed to Day-2 (retrain + re-evaluate).")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dumpcap", default=DUMPCAP_DEFAULT, help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list capture interfaces").set_defaults(func=cmd_list)

    p = sub.add_parser("benign", help="record N minutes of benign traffic")
    p.add_argument("--iface", required=True, help='interface NAME from `list`, e.g. "Ethernet 5"')
    p.add_argument("--minutes", type=float, default=60)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_benign)

    p = sub.add_parser("verify", help="check an attack capture against the timelines")
    p.add_argument("--pcap", required=True)
    p.add_argument("--victim", default="192.168.1.123")
    p.add_argument("--timeline-dir", default=TIMELINE_DIR)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
