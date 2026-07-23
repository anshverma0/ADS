# Wireshark Direct Training Report

**Dataset Location:** `wireshark_dataset`  
**Training Script:** [`train_from_wireshark.py`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/backend/train_from_wireshark.py)  
**Completion Status:** ✅ **SUCCESS**  
**Execution Time:** $461.0\,\text{seconds}$ ($\sim 7.68\,\text{minutes}$)  

---

## 1. Data Ingestion & Feature Metrics

- **Total PCAPNG Files Processed:** 2 (`capture.pcapng`, `packets.pcapng`)
- **Total Packets Ingested:** $1,627,485\,\text{packets}$
- **Total 30-Second Windows:** $325$ windows
- **Total Flow Features Generated:** $36,466$ flows
- **Training Samples:** $36,466$ benign local flow vectors ($100\%$ local network baseline)
- **Validation Samples:** Holdout quantile evaluation (50th & 99th percentiles of local benign flows used for score calibration anchors)

---

## 2. Model Training & Hyperparameters

### Isolation Forest
- **Status:** ✅ **Trained & Saved**
- **Contamination Rate:** $0.01$ ($1\%$)
- **Number of Estimators:** $100$
- **Random State:** $42$
- **Training Features:** 10 core features (`flow_byts_s`, `flow_pkts_s`, `fwd_bytes`, `bwd_bytes`, `total_pkts`, `syn_flag`, `rst_flag`, `fin_flag`, `flow_duration_s`, `pkt_len_mean`)

### Autoencoder
- **Status:** ✅ **Trained & Saved**
- **Architecture:** `MLPRegressor` ($10 \to 4 \to 10$)
- **Input Dimension:** $10$
- **Latent Dimension:** $4$ (hidden layer bottleneck)
- **Activation Function:** `ReLU`
- **Max Iterations:** $100$
- **Target:** Unsupervised self-reconstruction ($X \to X$) on benign local flows only

---

## 3. Score Anchor Calibration Results

| Detector Head | Low Anchor (`lo` $\to 0.0$) | Mid Anchor (`mid` $\to 0.5$) | High Anchor (`hi` $\to 1.0$) | Calibration Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Isolation Forest (`if`)** | $0.443024$ | $0.679826$ | $0.916629$ | Benign quantile ($50\%, 99\%$) + extrapolation |
| **Autoencoder (`ae`)** | $0.090181$ | $1.293566$ | $2.496951$ | Benign quantile ($50\%, 99\%$) + extrapolation |

---

## 4. Saved Artifact Locations & Backup

- **Saved Model Files:**
  - `scaler.pkl`: [`project/models/scaler.pkl`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/models/scaler.pkl)
  - `isolation_forest.pkl`: [`project/models/isolation_forest.pkl`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/models/isolation_forest.pkl)
  - `autoencoder.pkl`: [`project/models/autoencoder.pkl`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/models/autoencoder.pkl)
  - `meta.pkl`: [`project/models/meta.pkl`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/models/meta.pkl)
- **Training Metrics Report JSON:** [`project/models/wireshark_training_report.json`](file:///c:/Users/ADRIN/Downloads/anomaly-detection_v2/anomaly-detection_v2/project/models/wireshark_training_report.json)

---

## 5. Verification & Warnings

- **Errors Encountered:** **0 Errors**. Training pipeline executed end-to-end to clean completion.
- **Warnings Encountered:** Non-fatal `ConvergenceWarning` from `MLPRegressor` reaching max 100 iterations on Autoencoder bottleneck (expected behavior for bounded training time).
- **Backend Compatibility Check:** **PASS**. Model artifacts match exact schema expected by `preprocessing.py` and `anomaly_detector.py`.
