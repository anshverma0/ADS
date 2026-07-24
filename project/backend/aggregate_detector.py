"""
Aggregate volumetric-DDoS detector - inference side of train_aggregate.py.

Loads the benign-trained IsolationForest + scaler + threshold from
project/models/aggregate/ and scores window-level aggregate records
(flow_aggregator output). A record is anomalous when its IsolationForest score
exceeds the benign-calibrated threshold.

This is the volumetric track. It runs ALONGSIDE the existing per-flow pipeline,
which still handles session-shaped attacks. Kept intentionally small and
dependency-light so packet_capture.py can call score_records() per window.
"""
import os
import pickle
import threading

import numpy as np
import pandas as pd

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "aggregate"))

_cache = {}
_lock = threading.Lock()


def _load():
    """Loads and caches the three artifacts. Raises if training hasn't run."""
    if _cache:
        return _cache
    with _lock:
        if _cache:
            return _cache
        try:
            with open(os.path.join(MODELS_DIR, "agg_scaler.pkl"), "rb") as f:
                scaler = pickle.load(f)
            with open(os.path.join(MODELS_DIR, "agg_iforest.pkl"), "rb") as f:
                iforest = pickle.load(f)
            with open(os.path.join(MODELS_DIR, "agg_meta.pkl"), "rb") as f:
                meta = pickle.load(f)
        except FileNotFoundError as e:
            raise RuntimeError(
                "Aggregate model not found. Run train_aggregate.py first "
                f"(missing under {MODELS_DIR}: {e.filename})."
            )
        _cache.update(scaler=scaler, iforest=iforest, meta=meta)
        return _cache


def is_available():
    """True if the aggregate model has been trained and can be loaded."""
    try:
        _load()
        return True
    except RuntimeError:
        return False


def _matrix(df, meta):
    """df -> scaled feature matrix in the trained feature order."""
    feats, logs, medians = meta["features"], meta["log_features"], meta["medians"]
    X = df.reindex(columns=feats).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    for c in feats:
        X[c] = X[c].fillna(medians.get(c, 0.0))
    for c in logs:
        X[c] = np.log1p(X[c].clip(lower=0))
    return X.values


def score_records(df):
    """
    Scores aggregate records (a flow_aggregator DataFrame).

    Returns a dict:
        score:     raw IsolationForest anomaly score (higher = more anomalous)
        is_anomaly: bool array, score > benign-calibrated threshold
        threshold: the threshold used
        confidence: score mapped to [0,1] against the benign p50..p99 band
    Only the cardinality-bearing 'victim_proto' rows are scored if a 'scope'
    column is present; other rows return is_anomaly=False (they exist for the
    Stage 2 port rules, not the anomaly baseline).
    """
    assets = _load()
    scaler, iforest, meta = assets["scaler"], assets["iforest"], assets["meta"]

    n = len(df)
    scores = np.full(n, -np.inf)
    mask = (df["scope"].values == "victim_proto") if "scope" in df.columns else np.ones(n, bool)
    if mask.any():
        Xs = scaler.transform(_matrix(df.loc[mask], meta))
        scores[mask] = -iforest.score_samples(Xs)

    thr = meta["threshold"]
    is_anom = (scores > thr) & mask
    p50, p99 = meta.get("benign_score_p50", thr), meta.get("benign_score_p99", thr)
    denom = max(p99 - p50, 1e-9)
    confidence = np.clip((scores - p50) / denom, 0.0, 1.0)
    confidence[~mask] = 0.0
    return {"score": scores, "is_anomaly": is_anom, "threshold": thr,
            "confidence": confidence}
