"""
Train the AGGREGATE volumetric-DDoS detector on a benign capture.

Why a separate model from the 10-feature per-flow pipeline: measured on real
captured traffic, per-flow detection is chance (0.49 balanced accuracy) because
a spoofed-source flood decomposes into 1-packet flows that look normal. The
signal lives at the window level - peer cardinality, rate, flag ratios - which
flow_aggregator.py exposes. This trainer fits an unsupervised IsolationForest on
those aggregate features over benign windows only, then sets a decision
threshold from the benign score distribution at a target false-positive rate.

Runs entirely on the protected host's own traffic, so the baseline reflects THIS
network (the old per-flow baseline was from a different one - 45x off on rate).

Artifacts land in project/models/aggregate/ so the existing production models are
untouched:
    agg_scaler.pkl   StandardScaler over the aggregate feature set
    agg_iforest.pkl  IsolationForest (unsupervised, benign-only)
    agg_meta.pkl     feature list, log-transform cols, medians, threshold, config

Usage:
    python train_aggregate.py --pcap ..\\..\\data\\baseline_capture\\benign.pcapng \
        --victim 192.168.1.123 --window-sec 5
"""
import os
import sys
import time
import pickle
import argparse

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import flow_aggregator

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "aggregate"))

# Model input features. flow_duration_s is dropped (constant = window length ->
# zero variance -> StandardScaler NaN). unique_src_ips/src_ip_entropy are dropped
# in favour of the direction-agnostic unique_peers/peer_entropy (a capture may
# record replies, not the inbound flood - see flow_aggregator).
MODEL_FEATURES = [
    "flow_byts_s", "flow_pkts_s", "total_pkts", "pkt_len_mean",
    "fwd_bytes", "bwd_bytes", "syn_flag", "rst_flag", "fin_flag", "ack_flag",
    "unique_peers", "peer_entropy", "unique_src_ports", "dst_port_entropy",
    "inbound_pkt_ratio", "rst_rate", "syn_to_ack_ratio",
]
# Heavy-tailed counts/rates get log1p; entropies and ratios are already in [0,1].
LOG_FEATURES = [
    "flow_byts_s", "flow_pkts_s", "total_pkts", "fwd_bytes", "bwd_bytes",
    "syn_flag", "rst_flag", "fin_flag", "ack_flag", "unique_peers", "unique_src_ports",
]


def restrict_dissection():
    try:
        from scapy.config import conf
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        conf.layers.filter([Ether, ARP, IP, IPv6, TCP, UDP, ICMP])
    except Exception as e:
        print(f"[!] Could not restrict scapy layers ({e}); continuing.")


def build_benign_records(pcap, victim, window_sec):
    """
    Streams the benign capture and returns a DataFrame of aggregate records.
    Packets are bucketed by window and flushed once >2 windows behind newest, so
    each flush hands flow_aggregator exactly one window's packets and RAM stays
    bounded regardless of capture size.
    """
    from scapy.all import PcapReader

    victim_ips = [victim] if victim else None
    buckets = {}          # win_id -> [packets]
    max_win = None
    frames = []
    n = 0
    t0 = time.time()

    def flush(pkts):
        df = flow_aggregator.aggregate_packets(pkts, window_sec=window_sec, victim_ips=victim_ips)
        if not df.empty:
            frames.append(df)

    reader = PcapReader(pcap)
    try:
        for pkt in reader:
            n += 1
            wid = int(float(pkt.time) // window_sec)
            buckets.setdefault(wid, []).append(pkt)
            if max_win is None or wid > max_win:
                max_win = wid
                for old in [w for w in buckets if w < max_win - 1]:
                    flush(buckets.pop(old))
            if n % 250000 == 0:
                print(f"    {n:,} packets ({n / (time.time() - t0):,.0f} pkt/s), "
                      f"{sum(len(f) for f in frames):,} records so far")
    except (EOFError, StopIteration):
        pass
    finally:
        try:
            reader.close()
        except Exception:
            pass
    for w in sorted(buckets):
        flush(buckets.pop(w))

    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    print(f"[+] {n:,} packets -> {len(df):,} aggregate records "
          f"({time.time() - t0:.0f}s)")
    return df


def transform(df, medians):
    """df[MODEL_FEATURES] -> cleaned, log-transformed float matrix (pre-scaling)."""
    X = df.reindex(columns=MODEL_FEATURES).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(medians)
    for c in LOG_FEATURES:
        X[c] = np.log1p(X[c].clip(lower=0))
    return X


def main():
    ap = argparse.ArgumentParser(description="Train aggregate volumetric-DDoS detector")
    ap.add_argument("--pcap", required=True, help="benign-only capture")
    ap.add_argument("--victim", default="192.168.1.123",
                    help="protected host to aggregate around (matches inference)")
    ap.add_argument("--window-sec", type=int, default=5)
    ap.add_argument("--contamination", type=float, default=0.02,
                    help="IsolationForest contamination (benign anomaly fraction)")
    ap.add_argument("--target-fpr", type=float, default=0.02,
                    help="benign false-positive rate the threshold is set to")
    args = ap.parse_args()

    restrict_dissection()
    print(f"[+] Building benign aggregate records (victim {args.victim}, "
          f"{args.window_sec}s windows)...")
    df = build_benign_records(args.pcap, args.victim, args.window_sec)
    # Keep the cardinality-bearing scope for training; the port scope exists for
    # Stage 2 rules, not for the anomaly baseline.
    df = df[df["scope"] == "victim_proto"].reset_index(drop=True)
    if len(df) < 50:
        sys.exit(f"[-] Only {len(df)} training records - capture too small or victim IP absent.")
    print(f"[+] {len(df):,} benign 'victim_proto' records for training")

    medians = transform(df, 0.0).median()
    X = transform(df, medians)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X.values)

    print(f"[+] Fitting IsolationForest (contamination={args.contamination})...")
    iforest = IsolationForest(n_estimators=200, contamination=args.contamination,
                              random_state=42, n_jobs=-1)
    iforest.fit(Xs)

    # Higher = more anomalous. Threshold at the (1 - target_fpr) benign quantile,
    # so on data like the training baseline only ~target_fpr fires.
    benign_scores = -iforest.score_samples(Xs)
    threshold = float(np.quantile(benign_scores, 1.0 - args.target_fpr))
    realized_fpr = float((benign_scores > threshold).mean())
    print(f"[+] Threshold {threshold:.5f} at target FPR {args.target_fpr:.3f} "
          f"(realized {realized_fpr:.3f} on benign)")

    os.makedirs(MODELS_DIR, exist_ok=True)
    artifacts = {
        "agg_scaler.pkl": scaler,
        "agg_iforest.pkl": iforest,
        "agg_meta.pkl": {
            "features": MODEL_FEATURES, "log_features": LOG_FEATURES,
            "medians": medians.to_dict(), "threshold": threshold,
            "window_sec": args.window_sec, "victim": args.victim,
            "contamination": args.contamination, "target_fpr": args.target_fpr,
            "realized_benign_fpr": realized_fpr, "training_records": int(len(df)),
            "benign_score_p50": float(np.quantile(benign_scores, 0.50)),
            "benign_score_p99": float(np.quantile(benign_scores, 0.99)),
        },
    }
    for name, obj in artifacts.items():
        with open(os.path.join(MODELS_DIR, name), "wb") as f:
            pickle.dump(obj, f)
        print(f"[+] Saved {os.path.join(MODELS_DIR, name)}")
    print(f"\n[+] Done. {len(df):,} benign records, threshold {threshold:.5f}.")


if __name__ == "__main__":
    main()
