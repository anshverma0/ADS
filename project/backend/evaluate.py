"""
Unified evaluation CLI for the detection stack. Replaces the former
eval_captured_pcap / eval_captured_aggregate / eval_cicds_csv / flows_to_cicds /
eval_main_dataset scripts with one entry point and a shared code path.

Every mode runs the SAME production pipeline (preprocessing.preprocess_dataset ->
anomaly_detector IF+AE ensemble -> ddos_classifier rule engine) so results are
comparable across datasets; only the ingestion differs.

Subcommands
-----------
  pcap          Replay a capture per-flow (exactly as packet_capture.py sees it),
                score, and grade against attack_timeline_*.csv ground truth.
                --unlabeled skips grading and reports flag rates only.
  aggregate     Same capture, but collapse all victim traffic per (window,
                protocol) into one record. Measures how much attack signal is
                recoverable above the flow level (see flow_aggregator.py).
  convert       Emit a capture as a CICDDoS2019 / CICFlowMeter-schema CSV
                (10 trained features + ground-truth Label) for schema-parity tests.
  cicds         Score any CICDDoS2019-schema CSV (e.g. convert's output) through
                the identical path as the CICDDoS2019 benchmark.
  main-dataset  Join the CICDDoS2019 *-testing.parquet files and evaluate, the
                original benchmark number in project/models/main_dataset_eval.json.

Note: pandas/numpy import before scapy on purpose - the reverse order segfaults
the Anaconda build on this machine (DLL clash). scapy is imported lazily inside
the capture-reading functions so CSV-only modes never touch it.

Examples
--------
  python evaluate.py pcap --pcap ..\\..\\data\\nsl_kdd\\capture.pcapng \
      --out ..\\models\\captured_pcap_eval.json
  python evaluate.py aggregate --pcap ..\\..\\data\\nsl_kdd\\capture.pcapng \
      --out ..\\models\\captured_aggregate_eval.json
  python evaluate.py convert --pcap ..\\..\\data\\nsl_kdd\\capture.pcapng \
      --window-sec 5 --out ..\\..\\data\\captured_cicds\\captured_flows_cicds.csv
  python evaluate.py cicds --csv ..\\..\\data\\captured_cicds\\captured_flows_cicds.csv \
      --out ..\\models\\captured_cicds_eval.json
  python evaluate.py main-dataset
"""
import os
import sys
import glob
import json
import time
import argparse
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score,
                             balanced_accuracy_score)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import flow_generator
import feature_extractor
import preprocessing
import anomaly_detector
import ddos_classifier
import flow_aggregator
import aggregate_detector

THRESHOLD = 0.5
RULE_MIN_CONF = 0.4          # packet_capture.py:476
WINDOWS = (30, 5)
PAD_SEC = 120.0              # capture kept this far around the labelled region

TIMELINE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "attack_timelines"))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))

# Verdict family each simulated attack should land in. None = no dedicated rule
# signature, so detection is scored but subtype match is not asserted.
EXPECTED_FAMILY = {
    "SYN": "SYN Flood", "UDP": "UDP Flood", "HTTP": "HTTP Flood",
    "EXFIL": "Data Exfiltration",
    "ACK": None, "XMAS": None, "NULL": None, "C2": None,
    "PULSE": None, "FRAG": None,
}
PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1}
# Wire protocol each simulated attack rides on - used to label aggregate records
# without counting benign cross-protocol traffic inside an attack window.
ATTACK_PROTOCOL = {"SYN": "TCP", "ACK": "TCP", "HTTP": "TCP", "XMAS": "TCP",
                   "NULL": "TCP", "UDP": "UDP", "ICMP": "ICMP"}


# ─────────────────────────── ground truth ───────────────────────────

def load_segments(timeline_dir):
    """Reads every attack_timeline_*.csv into a list of labelled time segments."""
    segs = []
    for path in sorted(glob.glob(os.path.join(timeline_dir, "attack_timeline_*.csv"))):
        df = pd.read_csv(path, keep_default_na=False)   # "NULL" attack_type stays a string
        for _, r in df.iterrows():
            segs.append({
                "attack_type": str(r["attack_type"]).strip(),
                "target": str(r["target"]).strip(),
                "start": float(r["start_epoch"]),
                "end": float(r["end_epoch"]),
                "source": os.path.basename(path),
            })
    segs.sort(key=lambda s: s["start"])
    return segs


def label_flow(t_start, t_end, src_ip, dst_ip, segments):
    """ATTACK if victim IP is an endpoint and >50% of the flow's span is in a segment."""
    span = max(t_end - t_start, 1e-6)
    best_type, best_frac = None, 0.0
    for s in segments:
        if s["target"] != src_ip and s["target"] != dst_ip:
            continue
        if t_end < s["start"] or t_start > s["end"]:
            continue
        overlap = min(t_end, s["end"]) - max(t_start, s["start"])
        frac = max(overlap, 0.0) / span
        if t_end - t_start < 1.0:
            mid = (t_start + t_end) / 2.0
            frac = 1.0 if s["start"] <= mid <= s["end"] else 0.0
        if frac > best_frac:
            best_frac, best_type = frac, s["attack_type"]
    if best_frac > 0.5:
        return 1, best_type
    return 0, "Benign"


def label_window(t_start, t_end, segments, victim):
    """Dominant attack type overlapping an aggregate window's span, or Benign."""
    best, best_ov = "Benign", 0.0
    for s in segments:
        if s["target"] != victim:
            continue
        ov = min(t_end, s["end"]) - max(t_start, s["start"])
        if ov > best_ov:
            best_ov, best = ov, s["attack_type"]
    return (1, best) if best_ov > 0 else (0, "Benign")


# ─────────────────────────── shared scoring ───────────────────────────

def score(df_flows):
    """Runs the production pipeline; returns (probs, verdicts, rule_is_attack)."""
    X_scaled, _, canon = preprocessing.preprocess_dataset(df_flows)
    probs, _, _ = anomaly_detector.score_flows(X_scaled)

    recs = preprocessing.extract_features(canon).to_dict("records")
    protos = canon["protocol"].values
    sports = canon["src_port"].values
    dports = canon["dst_port"].values
    acks = canon["ack_count"].values if "ack_count" in canon.columns else np.zeros(len(canon))

    verdicts = np.empty(len(df_flows), dtype=object)
    rule_hit = np.zeros(len(df_flows), dtype=bool)
    for i, rec in enumerate(recs):
        rec["protocol"] = protos[i]
        rec["src_port"] = sports[i]
        rec["dst_port"] = dports[i]
        rec["ack_flag"] = acks[i]
        v = ddos_classifier.classify_flow(rec)
        verdicts[i] = v["attack_type"]
        rule_hit[i] = (v["attack_type"] not in ("Normal", "Unknown Anomaly")
                       and v["confidence"] >= RULE_MIN_CONF)
    return probs, verdicts, rule_hit


def binary_metrics(y_true, y_pred, probs=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    m = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
    }
    if probs is not None and len(set(y_true)) == 2:
        m["roc_auc"] = float(roc_auc_score(y_true, probs))
    return m


def print_stage1(y_true, preds, probs_for):
    """preds: dict name->pred array; probs_for: dict name->probs|None. Returns metrics dict."""
    out = {}
    print(f"  {'rule':<8} {'acc':>7} {'bal.acc':>8} {'prec':>7} {'rec':>7} {'f1':>7} "
          f"{'FPR':>7} {'TP':>7} {'FP':>7} {'FN':>7} {'TN':>7}")
    for name, pred in preds.items():
        m = binary_metrics(y_true, pred, probs_for.get(name))
        out[name] = m
        print(f"  {name:<8} {m['accuracy']:>7.4f} {m['balanced_accuracy']:>8.4f} "
              f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f} "
              f"{m['false_positive_rate']:>7.4f} {m['tp']:>7,} {m['fp']:>7,} "
              f"{m['fn']:>7,} {m['tn']:>7,}")
    if "roc_auc" in out.get("ml", {}):
        print(f"  ML ROC-AUC (threshold-free): {out['ml']['roc_auc']:.4f}")
    return out


# ─────────────────────────── capture replay (per-flow) ───────────────────────────

def restrict_dissection():
    try:
        from scapy.config import conf
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP])
    except Exception as e:
        print(f"[!] Could not restrict scapy dissection ({e}); continuing (slower).")


def _flush_flow_window(packets, window_sec, win_id, rows):
    flows = flow_generator.group_packets_into_flows(packets)
    if not flows:
        return
    df = feature_extractor.extract_flow_features(flows)
    times = [(min(p["time"] for p in pkts), max(p["time"] for p in pkts))
             for pkts in flows.values()]
    df["t_start"] = [t[0] for t in times]
    df["t_end"] = [t[1] for t in times]
    df["window_sec"] = window_sec
    df["window_id"] = win_id
    rows.append(df)


def replay(pcap_path, t_lo, t_hi, windows=WINDOWS):
    """One streaming pass; returns {window_sec: DataFrame of flows}."""
    from scapy.all import PcapReader

    buckets = {w: {} for w in windows}
    rows = {w: [] for w in windows}
    maxwin = {w: None for w in windows}
    n_read = n_kept = 0
    t0 = time.time()

    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            n_read += 1
            ts = float(pkt.time)
            if t_hi is not None and ts > t_hi:
                break
            if t_lo is not None and ts < t_lo:
                continue
            n_kept += 1
            for w in windows:
                wid = int(ts // w)
                buckets[w].setdefault(wid, []).append(pkt)
                if maxwin[w] is None or wid > maxwin[w]:
                    maxwin[w] = wid
                    for old in [k for k in buckets[w] if k < maxwin[w] - 1]:
                        _flush_flow_window(buckets[w].pop(old), w, old, rows[w])
            if n_read % 250000 == 0:
                print(f"    {n_read:,} read / {n_kept:,} in range  "
                      f"({n_read / (time.time() - t0):,.0f} pkt/s)")
    except (EOFError, StopIteration):
        pass
    except Exception as e:
        print(f"[!] Stopped reading early after {n_read:,} packets: {e}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    for w in windows:
        for wid in sorted(buckets[w]):
            _flush_flow_window(buckets[w].pop(wid), w, wid, rows[w])

    out = {}
    for w in windows:
        out[w] = pd.concat(rows[w], ignore_index=True) if rows[w] else pd.DataFrame()
        print(f"[+] {w:>2}s windows -> {len(out[w]):,} flows")
    print(f"[+] Replay done: {n_read:,} packets read, {n_kept:,} in range, "
          f"{time.time() - t0:.0f}s")
    return out


# ─────────────────────────── subcommand: pcap ───────────────────────────

def evaluate_window(df, segments, window_sec):
    print("\n" + "=" * 78)
    print(f"  PER-FLOW  WINDOW = {window_sec}s   ({len(df):,} flows)")
    print("=" * 78)

    labels = [label_flow(r.t_start, r.t_end, r.src_ip, r.dst_ip, segments)
              for r in df.itertuples()]
    y_true = np.array([l[0] for l in labels])
    atk_type = np.array([l[1] for l in labels], dtype=object)
    print(f"  Ground truth: {int(y_true.sum()):,} attack / "
          f"{int((y_true == 0).sum()):,} benign flows")
    if y_true.sum() == 0:
        print("  [!] No attack flows matched the timelines - check time alignment.")
        return None

    probs, verdicts, rule_hit = score(df)
    ml = (probs >= THRESHOLD).astype(int)
    hyb = (ml | rule_hit.astype(int)).astype(int)
    print()
    stage1 = print_stage1(y_true, {"ml": ml, "rule": rule_hit.astype(int), "hybrid": hyb},
                          {"ml": probs})
    res = {"flows": int(len(df)), "attack_flows": int(y_true.sum()),
           "benign_flows": int((y_true == 0).sum()), "stage1": stage1}

    print()
    print(f"  {'attack':<8} {'flows':>7} {'det(hyb)':>9} {'rate':>7}  "
          f"{'dominant verdict':<34} {'family':>7}")
    per_type = {}
    for t in sorted(set(atk_type) - {"Benign"}):
        mask = atk_type == t
        n = int(mask.sum())
        det = mask & (hyb == 1)
        ndet = int(det.sum())
        vs = pd.Series(verdicts[det])
        exp = EXPECTED_FAMILY.get(t)
        fam = float(vs.str.contains(exp, regex=False).mean()) if (ndet and exp) else None
        per_type[t] = {
            "flows": n, "detected": ndet, "detection_rate": ndet / n,
            "dominant_verdict": str(vs.value_counts().idxmax()) if ndet else "-",
            "expected_family": exp, "family_match_rate_among_detected": fam,
            "verdict_breakdown": vs.value_counts().to_dict(),
            "mean_prob": float(probs[mask].mean()),
        }
        print(f"  {t:<8} {n:>7,} {ndet:>9,} {ndet / n:>7.3f}  "
              f"{per_type[t]['dominant_verdict']:<34} "
              f"{'-' if fam is None else f'{fam * 100:.1f}%':>7}")
    res["per_attack_type"] = per_type

    fp_mask = (y_true == 0) & (hyb == 1)
    res["false_positive_verdicts"] = dict(Counter(verdicts[fp_mask]).most_common(10))
    ct = pd.crosstab(pd.Series(atk_type, name="truth"),
                     pd.Series(verdicts, name="verdict"))
    res["crosstab"] = ct.to_dict()
    print("\n  Ground truth vs Stage 2 verdict:")
    print("  " + ct.to_string().replace("\n", "\n  "))
    return res


def evaluate_unlabeled(df, window_sec):
    print("\n" + "=" * 78)
    print(f"  PER-FLOW  WINDOW = {window_sec}s   ({len(df):,} flows)  [UNLABELLED]")
    print("=" * 78)
    probs, verdicts, rule_hit = score(df)
    ml = (probs >= THRESHOLD).astype(int)
    hyb = (ml | rule_hit.astype(int))
    print(f"  ML flagged     : {int(ml.sum()):,} / {len(df):,} ({ml.mean() * 100:.1f}%)")
    print(f"  Rule flagged   : {int(rule_hit.sum()):,} ({rule_hit.mean() * 100:.1f}%)")
    print(f"  Hybrid flagged : {int(hyb.sum()):,} ({hyb.mean() * 100:.1f}%)")
    mix = Counter(verdicts[hyb == 1])
    print("  Verdict mix on flagged flows:")
    for k, v in mix.most_common(15):
        print(f"    {k:<40} {v:>7,}")
    return {"flows": int(len(df)), "ml_flagged": int(ml.sum()),
            "rule_flagged": int(rule_hit.sum()), "hybrid_flagged": int(hyb.sum()),
            "hybrid_flag_rate": float(hyb.mean()), "verdict_mix": dict(mix.most_common()),
            "mean_prob": float(probs.mean())}


def cmd_pcap(args):
    restrict_dissection()
    segments = [] if args.unlabeled else load_segments(args.timeline_dir)
    if args.unlabeled:
        t_lo = t_hi = None
    else:
        if not segments:
            print("[-] No attack_timeline_*.csv found."); sys.exit(1)
        t_lo = min(s["start"] for s in segments) - PAD_SEC
        t_hi = max(s["end"] for s in segments) + PAD_SEC
        print(f"[+] {len(segments)} segments, "
              f"{pd.to_datetime(t_lo, unit='s')} .. {pd.to_datetime(t_hi, unit='s')}")

    frames = replay(args.pcap, t_lo, t_hi)
    report = {"pcap": os.path.basename(args.pcap), "threshold": THRESHOLD,
              "labelled": not args.unlabeled, "segments": len(segments), "windows": {}}
    for w in WINDOWS:
        df = frames[w]
        if df.empty:
            continue
        report["windows"][str(w)] = (evaluate_unlabeled(df, w) if args.unlabeled
                                     else evaluate_window(df, segments, w))
    _write(report, args.out)


# ─────────────────────────── subcommand: aggregate ───────────────────────────

def aggregate_records(pcap_path, victim, t_lo, t_hi, window_sec_list):
    """One streaming pass -> {window_sec: DataFrame}, one row per (window, protocol)."""
    from scapy.all import PcapReader

    acc = {w: defaultdict(lambda: {
        "fwd_bytes": 0.0, "bwd_bytes": 0.0, "fwd_packets": 0, "bwd_packets": 0,
        "syn": 0, "rst": 0, "fin": 0, "ack": 0, "t_min": None, "t_max": None,
        "peers": set(), "dports": Counter(),
    }) for w in window_sec_list}
    n_read = n_kept = 0
    t0 = time.time()

    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            n_read += 1
            ts = float(pkt.time)
            if ts > t_hi:
                break
            if ts < t_lo or not pkt.haslayer("IP"):
                continue
            ip = pkt["IP"]
            if ip.src != victim and ip.dst != victim:
                continue
            n_kept += 1
            if pkt.haslayer("TCP"):
                proto, l4 = "TCP", pkt["TCP"]
            elif pkt.haslayer("UDP"):
                proto, l4 = "UDP", pkt["UDP"]
            elif pkt.haslayer("ICMP"):
                proto, l4 = "ICMP", None
            else:
                proto, l4 = "Other", None
            inbound = ip.dst == victim
            peer = ip.src if inbound else ip.dst
            dport = int(l4.dport) if l4 is not None else 0
            plen = len(pkt)
            f = int(l4.flags) if proto == "TCP" else 0
            for w in window_sec_list:
                a = acc[w][(int(ts // w), proto)]
                if inbound:
                    a["fwd_bytes"] += plen; a["fwd_packets"] += 1
                else:
                    a["bwd_bytes"] += plen; a["bwd_packets"] += 1
                a["syn"] += 1 if f & 0x02 else 0
                a["rst"] += 1 if f & 0x04 else 0
                a["fin"] += 1 if f & 0x01 else 0
                a["ack"] += 1 if f & 0x10 else 0
                a["t_min"] = ts if a["t_min"] is None else min(a["t_min"], ts)
                a["t_max"] = ts if a["t_max"] is None else max(a["t_max"], ts)
                a["peers"].add(peer)
                if inbound:
                    a["dports"][dport] += 1
            if n_read % 250000 == 0:
                print(f"    {n_read:,} read / {n_kept:,} victim pkts "
                      f"({n_read / (time.time() - t0):,.0f} pkt/s)")
    except (EOFError, StopIteration):
        pass
    finally:
        try:
            reader.close()
        except Exception:
            pass

    out = {}
    for w in window_sec_list:
        rows = []
        for (wid, proto), a in acc[w].items():
            pkts = a["fwd_packets"] + a["bwd_packets"]
            byts = a["fwd_bytes"] + a["bwd_bytes"]
            dur = max(a["t_max"] - a["t_min"], 1e-4)
            rows.append({
                "src_ip": "aggregate", "dst_ip": victim, "src_port": 0,
                "dst_port": a["dports"].most_common(1)[0][0] if a["dports"] else 0,
                "protocol": proto, "flow_byts_s": byts / dur, "flow_pkts_s": pkts / dur,
                "fwd_bytes": a["fwd_bytes"], "bwd_bytes": a["bwd_bytes"],
                "fwd_packets": a["fwd_packets"], "bwd_packets": a["bwd_packets"],
                "total_pkts": pkts, "syn_flag": a["syn"], "rst_flag": a["rst"],
                "fin_flag": a["fin"], "ack_flag": a["ack"], "flow_duration_s": dur,
                "pkt_len_mean": byts / max(pkts, 1), "t_start": a["t_min"], "t_end": a["t_max"],
                "unique_peers": len(a["peers"]), "window_id": wid,
            })
        out[w] = pd.DataFrame(rows).sort_values("window_id").reset_index(drop=True) if rows else pd.DataFrame()
        print(f"[+] {w:>2}s windows -> {len(out[w]):,} aggregate records")
    print(f"[+] {n_read:,} packets read, {n_kept:,} involving {victim}, {time.time() - t0:.0f}s")
    return out


def cmd_aggregate(args):
    restrict_dissection()
    segments = load_segments(args.timeline_dir)
    if not segments:
        print("[-] No attack_timeline_*.csv found."); sys.exit(1)
    t_lo = min(s["start"] for s in segments) - PAD_SEC
    t_hi = max(s["end"] for s in segments) + PAD_SEC
    print(f"[+] {len(segments)} segments; victim {args.victim}")

    frames = aggregate_records(args.pcap, args.victim, t_lo, t_hi, WINDOWS)
    report = {"pcap": os.path.basename(args.pcap), "victim": args.victim,
              "mode": "victim-aggregate", "windows": {}}
    for w in WINDOWS:
        df = frames[w]
        if df.empty:
            continue
        print("\n" + "=" * 78)
        print(f"  AGGREGATE  WINDOW = {w}s   ({len(df):,} records)")
        print("=" * 78)
        lab = [label_window(r.t_start, r.t_end, segments, args.victim) for r in df.itertuples()]
        y_true = np.array([l[0] for l in lab])
        atk = np.array([l[1] for l in lab], dtype=object)
        print(f"  {int(y_true.sum())} attack / {int((y_true == 0).sum())} benign records")

        probs, verdicts, rule_hit = score(df)
        ml = (probs >= THRESHOLD).astype(int)
        hyb = (ml | rule_hit.astype(int))
        print()
        stage1 = print_stage1(y_true, {"ml": ml, "rule": rule_hit.astype(int), "hybrid": hyb},
                              {"ml": probs})
        res = {"records": int(len(df)), "attack": int(y_true.sum()),
               "benign": int((y_true == 0).sum()), "stage1": stage1}

        print(f"\n  {'attack':<8} {'recs':>6} {'det':>5} {'rate':>7}  "
              f"{'dominant verdict':<32} {'peers/rec':>10}")
        per = {}
        for t in sorted(set(atk) - {"Benign"}):
            m = atk == t
            d = m & (hyb == 1)
            vs = pd.Series(verdicts[d])
            per[t] = {"records": int(m.sum()), "detected": int(d.sum()),
                      "dominant_verdict": str(vs.value_counts().idxmax()) if d.sum() else "-",
                      "verdict_breakdown": vs.value_counts().to_dict(),
                      "mean_unique_peers": float(df.loc[m, "unique_peers"].mean()),
                      "mean_prob": float(probs[m].mean())}
            print(f"  {t:<8} {per[t]['records']:>6} {per[t]['detected']:>5} "
                  f"{per[t]['detected'] / per[t]['records']:>7.3f}  "
                  f"{per[t]['dominant_verdict']:<32} {per[t]['mean_unique_peers']:>10.1f}")
        res["per_attack_type"] = per
        res["benign_mean_unique_peers"] = float(df.loc[atk == "Benign", "unique_peers"].mean())
        print(f"  benign mean unique peers/record: {res['benign_mean_unique_peers']:.1f}")
        report["windows"][str(w)] = res
    _write(report, args.out)


# ─────────────────────────── subcommand: convert ───────────────────────────

CICDS_COLUMNS = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
    "Flow Packets/s", "Average Packet Size", "SYN Flag Count", "RST Flag Count",
    "FIN Flag Count", "ACK Flag Count", "Label",
]


def to_cicds(df, segments):
    """feature_extractor output -> CICFlowMeter column names + ground-truth Label."""
    out = pd.DataFrame(index=df.index)
    out["Flow ID"] = (df["src_ip"].astype(str) + "-" + df["dst_ip"].astype(str) + "-"
                      + df["src_port"].astype(str) + "-" + df["dst_port"].astype(str)
                      + "-" + df["protocol"].astype(str))
    out["Source IP"] = df["src_ip"]
    out["Source Port"] = df["src_port"].astype(int)
    out["Destination IP"] = df["dst_ip"]
    out["Destination Port"] = df["dst_port"].astype(int)
    out["Protocol"] = df["protocol"].map(PROTO_NUM).fillna(0).astype(int)
    out["Timestamp"] = pd.to_datetime(df["t_start"], unit="s").dt.strftime("%d/%m/%Y %I:%M:%S %p")
    # CICFlowMeter reports Flow Duration in MICROSECONDS; preprocessing rescales
    # the exact column name "Flow Duration" by 1e6, so emit microseconds.
    out["Flow Duration"] = (df["flow_duration_s"] * 1e6).round().astype("int64")
    out["Total Fwd Packets"] = df["fwd_packets"].astype(int)
    out["Total Backward Packets"] = df["bwd_packets"].astype(int)
    out["Total Length of Fwd Packets"] = df["fwd_bytes"].astype(float)
    out["Total Length of Bwd Packets"] = df["bwd_bytes"].astype(float)
    out["Flow Bytes/s"] = df["flow_byts_s"].astype(float)
    out["Flow Packets/s"] = df["flow_pkts_s"].astype(float)
    out["Average Packet Size"] = df["pkt_len_mean"].astype(float)
    out["SYN Flag Count"] = df["syn_flag"].astype(int)
    out["RST Flag Count"] = df["rst_flag"].astype(int)
    out["FIN Flag Count"] = df["fin_flag"].astype(int)
    out["ACK Flag Count"] = df["ack_flag"].astype(int)
    labels = [label_flow(r.t_start, r.t_end, r.src_ip, r.dst_ip, segments)
              for r in df.itertuples()]
    out["Label"] = [("Benign" if l[0] == 0 else l[1]) for l in labels]
    return out[CICDS_COLUMNS]


def cmd_convert(args):
    restrict_dissection()
    segments = load_segments(args.timeline_dir)
    if not segments:
        print("[-] No attack_timeline_*.csv found."); sys.exit(1)
    t_lo = min(s["start"] for s in segments) - PAD_SEC
    t_hi = max(s["end"] for s in segments) + PAD_SEC
    print(f"[+] {len(segments)} segments; window {args.window_sec}s")

    frames = replay(args.pcap, t_lo, t_hi, windows=(args.window_sec,))
    df = frames[args.window_sec]
    if df.empty:
        print("[-] No flows produced."); sys.exit(1)

    out = to_cicds(df, segments)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    out.to_csv(args.out, index=False)
    print(f"[+] Wrote {len(out):,} flows -> {os.path.abspath(args.out)} "
          f"({os.path.getsize(args.out) / 1e6:.1f} MB)")
    print("[+] Label distribution:")
    for k, v in out["Label"].value_counts().items():
        print(f"      {k:<10} {v:>8,}")
    _, missing = preprocessing.map_to_canonical_schema(
        out, preprocessing.build_alias_dictionary())
    unresolved = [m for m in missing if m not in ("flow_id", "timestamp")]
    print(f"[+] Canonical mapping check - unresolved: "
          f"{unresolved if unresolved else 'none (full schema parity)'}")


# ─────────────────────────── subcommand: cicds ───────────────────────────

def cmd_cicds(args):
    print(f"[+] Reading {args.csv}")
    df = pd.read_csv(args.csv, keep_default_na=False)
    labels = df["Label"].astype(str).values
    y_true = (labels != "Benign").astype(int)
    print(f"    {len(df):,} flows ({int(y_true.sum()):,} attack / "
          f"{int((y_true == 0).sum()):,} benign)")

    probs, verdicts, rule_hit = score(df)
    ml = (probs >= args.threshold).astype(int)
    hyb = (ml | rule_hit.astype(int))
    print("\n" + "=" * 76)
    print("  STAGE 1 - binary attack detection (CICDDoS2019 schema)")
    print("=" * 76)
    stage1 = print_stage1(y_true, {"ml": ml, "rule": rule_hit.astype(int), "hybrid": hyb},
                          {"ml": probs})

    print("\n" + "=" * 76)
    print("  STAGE 2 - per-label detection and subtype segregation")
    print("=" * 76)
    print(f"  {'label':<10} {'flows':>8} {'detected':>9} {'det.rate':>9}  "
          f"{'dominant verdict':<34} {'family':>8}")
    per_label, fam_hits, fam_tot, e2e_tot = {}, 0, 0, 0
    for lab in sorted(set(labels)):
        mask = labels == lab
        n = int(mask.sum())
        det = mask & (hyb == 1)
        ndet = int(det.sum())
        vs = pd.Series(verdicts[det])
        exp = EXPECTED_FAMILY.get(lab)
        fam = float(vs.str.contains(exp, regex=False).mean()) if (ndet and exp) else None
        per_label[lab] = {"flows": n, "detected": ndet, "detection_rate": ndet / n,
                          "dominant_verdict": str(vs.value_counts().idxmax()) if ndet else "-",
                          "expected_family": exp, "family_match_rate_among_detected": fam,
                          "verdict_breakdown": vs.value_counts().to_dict(),
                          "mean_prob": float(probs[mask].mean())}
        if exp:
            e2e_tot += n
            fam_tot += ndet
            fam_hits += sum(v for k, v in per_label[lab]["verdict_breakdown"].items() if exp in k)
        print(f"  {lab:<10} {n:>8,} {ndet:>9,} {ndet / n:>9.4f}  "
              f"{per_label[lab]['dominant_verdict']:<34} "
              f"{'-' if fam is None else f'{fam * 100:.1f}%':>8}")

    seg = fam_hits / fam_tot if fam_tot else 0.0
    e2e = fam_hits / e2e_tot if e2e_tot else 0.0
    print(f"\n  Subtype segregation accuracy (correct family | detected): {seg:.4f} ({fam_hits}/{fam_tot})")
    print(f"  End-to-end accuracy (detected AND correct family):        {e2e:.4f} ({fam_hits}/{e2e_tot})")
    ct = pd.crosstab(pd.Series(labels, name="true_label"),
                     pd.Series(verdicts, name="model_verdict"))
    print("\n  Ground truth vs verdict:")
    print("  " + ct.to_string().replace("\n", "\n  "))

    report = {"dataset": os.path.basename(args.csv), "schema": "CICDDoS2019 / CICFlowMeter",
              "rows": int(len(df)), "threshold": args.threshold, "stage1_binary": stage1,
              "stage2_segregation_accuracy_among_detected": seg, "end_to_end_accuracy": e2e,
              "per_label": per_label, "crosstab": ct.to_dict()}
    _write(report, args.out)


# ─────────────────────────── subcommand: main-dataset ───────────────────────────

MAIN_EXPECTED_FAMILY = {
    "DrDoS_DNS": "Amplification", "DrDoS_LDAP": "Amplification", "DrDoS_MSSQL": "Amplification",
    "DrDoS_NTP": "Amplification", "DrDoS_NetBIOS": "Amplification", "DrDoS_SNMP": "Amplification",
    "DrDoS_UDP": "UDP Flood", "TFTP": "Amplification", "Syn": "SYN Flood",
    "UDP-lag": "UDP Flood", "WebDDoS": "HTTP Flood",
}


def cmd_main_dataset(args):
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "CICDDos2019"))
    main_csv = os.path.join(data_dir, "main_dataset.csv")
    files = sorted(glob.glob(os.path.join(data_dir, "*-testing.parquet")))
    if not files:
        print(f"[-] No *-testing.parquet in {data_dir} (dataset not present)."); sys.exit(1)
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df.to_csv(main_csv, index=False)
    print(f"[+] Joined {len(files)} parquet files -> {main_csv} ({len(df):,} rows)")
    df = pd.read_csv(main_csv)

    labels = df["Label"].astype(str).values
    y_true = (labels != "Benign").astype(int)
    X_scaled, _, canon = preprocessing.preprocess_dataset(df)
    probs, _, _ = anomaly_detector.score_flows(X_scaled)
    ml = (probs >= args.threshold).astype(int)

    print("\n  STAGE 1 - binary detection on main_dataset.csv")
    stage1 = print_stage1(y_true, {"ml": ml}, {"ml": probs})

    recs = preprocessing.extract_features(canon).to_dict("records")
    protos, sports, dports = canon["protocol"].values, canon["src_port"].values, canon["dst_port"].values
    verdicts = np.empty(len(df), dtype=object)
    for i in range(len(df)):
        if ml[i] == 0:
            verdicts[i] = "Normal"; continue
        rec = recs[i]; rec["protocol"] = protos[i]; rec["src_port"] = sports[i]; rec["dst_port"] = dports[i]
        verdicts[i] = ddos_classifier.classify_flow(rec)["attack_type"]

    attack_detected = (y_true == 1) & (ml == 1)
    fam_hits = sum(1 for i in np.where(attack_detected)[0]
                   if MAIN_EXPECTED_FAMILY.get(labels[i]) and MAIN_EXPECTED_FAMILY[labels[i]] in verdicts[i])
    seg = fam_hits / attack_detected.sum() if attack_detected.sum() else 0.0
    print(f"  Subtype segregation accuracy among detected: {seg:.4f} "
          f"({fam_hits}/{int(attack_detected.sum())})")
    report = {"dataset": "main_dataset.csv (CICDDoS2019 testing parquets)", "rows": int(len(df)),
              "threshold": args.threshold, "stage1_binary": stage1,
              "stage2_segregation_accuracy_among_detected": seg}
    _write(report, os.path.join(MODELS_DIR, "main_dataset_eval.json"))


# ─────────────────────────── subcommand: agg (trained aggregate model) ─────────

def build_agg_records(pcap, victim, window_sec, t_lo, t_hi):
    """
    Streams the capture within [t_lo, t_hi] into flow_aggregator records (both
    scopes), bucketed by window so each flush sees one window's packets.
    """
    from scapy.all import PcapReader

    buckets, max_win, frames, n_read, n_kept = {}, None, [], 0, 0
    t0 = time.time()

    def flush(pkts):
        d = flow_aggregator.aggregate_packets(pkts, window_sec=window_sec,
                                              victim_ips=[victim])
        if not d.empty:
            frames.append(d)

    reader = PcapReader(pcap)
    try:
        for pkt in reader:
            n_read += 1
            ts = float(pkt.time)
            if ts > t_hi:
                break
            if ts < t_lo:
                continue
            n_kept += 1
            wid = int(ts // window_sec)
            buckets.setdefault(wid, []).append(pkt)
            if max_win is None or wid > max_win:
                max_win = wid
                for old in [w for w in buckets if w < max_win - 1]:
                    flush(buckets.pop(old))
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
    print(f"[+] {n_read:,} read / {n_kept:,} in range -> {len(df):,} aggregate "
          f"records ({time.time() - t0:.0f}s)")
    return df


def cmd_agg(args):
    if not aggregate_detector.is_available():
        sys.exit("[-] Aggregate model not trained. Run train_aggregate.py first.")
    restrict_dissection()
    segments = load_segments(args.timeline_dir)
    if not segments:
        print("[-] No attack_timeline_*.csv found."); sys.exit(1)
    win = args.window_sec
    t_lo = min(s["start"] for s in segments) - PAD_SEC
    t_hi = max(s["end"] for s in segments) + PAD_SEC
    print(f"[+] {len(segments)} segments; victim {args.victim}; {win}s windows")

    df = build_agg_records(args.pcap, args.victim, win, t_lo, t_hi)
    if df.empty:
        sys.exit("[-] No aggregate records produced.")

    # Trained anomaly model scores the cardinality-bearing scope.
    det = aggregate_detector.score_records(df)
    df = df.assign(score=det["score"], ml_anom=det["is_anomaly"],
                   ml_conf=det["confidence"])

    # Stage 2 rule verdict per record (uses aggregate rates/flags/ports).
    verdicts, rule_hit = [], []
    for rec in df.to_dict("records"):
        v = ddos_classifier.classify_flow(rec)
        verdicts.append(v["attack_type"])
        rule_hit.append(v["attack_type"] not in ("Normal", "Unknown Anomaly")
                        and v["confidence"] >= RULE_MIN_CONF)
    df["verdict"] = verdicts
    df["rule_anom"] = rule_hit

    # Grade the cardinality scope (one row per window/protocol) - that is the
    # detection unit. Label each record by timeline overlap for its victim, but
    # PROTOCOL-AWARE: a TCP-based flood (SYN/ACK/HTTP) does not make the victim's
    # background UDP traffic in that same window an attack, and vice-versa.
    # Without this, benign cross-protocol records inside an attack window count
    # as missed detections and deflate recall.
    scoped = df[df["scope"] == "victim_proto"].copy()
    lab = [label_window(r.t_start, r.t_end, segments, args.victim)
           for r in scoped.itertuples()]
    protos = scoped["protocol"].values
    y_true = np.zeros(len(scoped), dtype=int)
    atk = np.array(["Benign"] * len(scoped), dtype=object)
    for i, (is_atk, atype) in enumerate(lab):
        if not is_atk:
            continue
        exp_proto = ATTACK_PROTOCOL.get(atype)
        if exp_proto is None or protos[i] == exp_proto:
            y_true[i] = 1
            atk[i] = atype
    ml = scoped["ml_anom"].astype(int).values
    rule = scoped["rule_anom"].astype(int).values
    hyb = (ml | rule)

    print("\n" + "=" * 78)
    print(f"  AGGREGATE MODEL  ({len(scoped):,} victim_proto records: "
          f"{int(y_true.sum())} attack / {int((y_true == 0).sum())} benign)")
    print("=" * 78 + "\n")
    stage1 = print_stage1(y_true, {"ml": ml, "rule": rule, "hybrid": hyb},
                          {"ml": scoped["score"].values})

    # Per attack type (hybrid)
    print(f"\n  {'attack':<8} {'recs':>6} {'det':>5} {'rate':>7}  "
          f"{'dominant verdict':<28} {'mean peers':>10}")
    per = {}
    for t in sorted(set(atk) - {"Benign"}):
        m = atk == t
        d = m & (hyb == 1)
        vs = pd.Series(scoped["verdict"].values[d])
        per[t] = {"records": int(m.sum()), "detected": int(d.sum()),
                  "detection_rate": float(d.sum() / m.sum()) if m.sum() else 0.0,
                  "dominant_verdict": str(vs.value_counts().idxmax()) if d.sum() else "-",
                  "verdict_breakdown": vs.value_counts().to_dict(),
                  "mean_unique_peers": float(scoped["unique_peers"].values[m].mean())}
        print(f"  {t:<8} {per[t]['records']:>6} {per[t]['detected']:>5} "
              f"{per[t]['detection_rate']:>7.3f}  {per[t]['dominant_verdict']:<28} "
              f"{per[t]['mean_unique_peers']:>10.1f}")
    benign_peers = float(scoped["unique_peers"].values[atk == "Benign"].mean()) \
        if (atk == "Benign").any() else 0.0
    print(f"  benign mean unique peers/record: {benign_peers:.1f}")

    report = {"pcap": os.path.basename(args.pcap), "mode": "aggregate-model",
              "victim": args.victim, "window_sec": win,
              "threshold": aggregate_detector._load()["meta"]["threshold"],
              "records": int(len(scoped)), "attack": int(y_true.sum()),
              "benign": int((y_true == 0).sum()), "stage1": stage1,
              "per_attack_type": per, "benign_mean_unique_peers": benign_peers}
    _write(report, args.out)


# ─────────────────────────── cli ───────────────────────────

def _write(report, out_path):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Wrote {os.path.abspath(out_path)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pcap", help="per-flow replay + grade against timelines")
    p.add_argument("--pcap", required=True)
    p.add_argument("--timeline-dir", default=TIMELINE_DIR)
    p.add_argument("--unlabeled", action="store_true")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("aggregate", help="victim-aggregate replay + grade")
    p.add_argument("--pcap", required=True)
    p.add_argument("--victim", default="192.168.1.123")
    p.add_argument("--timeline-dir", default=TIMELINE_DIR)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_aggregate)

    p = sub.add_parser("convert", help="capture -> CICDDoS2019-schema CSV")
    p.add_argument("--pcap", required=True)
    p.add_argument("--timeline-dir", default=TIMELINE_DIR)
    p.add_argument("--window-sec", type=int, default=5)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("cicds", help="score a CICDDoS2019-schema CSV")
    p.add_argument("--csv", required=True)
    p.add_argument("--threshold", type=float, default=THRESHOLD)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_cicds)

    p = sub.add_parser("main-dataset", help="join + evaluate CICDDoS2019 parquets")
    p.add_argument("--threshold", type=float, default=THRESHOLD)
    p.set_defaults(func=cmd_main_dataset)

    p = sub.add_parser("agg", help="evaluate the trained aggregate DDoS model")
    p.add_argument("--pcap", required=True)
    p.add_argument("--victim", default="192.168.1.123")
    p.add_argument("--timeline-dir", default=TIMELINE_DIR)
    p.add_argument("--window-sec", type=int, default=5)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_agg)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
