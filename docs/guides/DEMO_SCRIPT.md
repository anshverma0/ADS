# Anomaly Detection System — Demo Script

## Overview (1 min)

**Opening Statement:**
> "Today I'm showing you an AI-powered network anomaly detection system that identifies botnet traffic and DDoS attacks in real-time. We combine machine learning with rule-based detection to catch both stealthy command-and-control traffic and aggressive attacks."

**Key Points:**
- Built on CTU-13 dataset: 38,898 botnet flows + 53,314 normal flows
- Uses Isolation Forest ML model + DDoS rule engine
- Hybrid approach: catches hidden patterns ML finds + obvious attack signatures
- Real-time live packet capture & analysis
- SHAP explainability for every detection

---

## Part 1: Launch the System (2 mins)

### Step 1: Start the Application
```bash
cd "e:\Projects Internet room\anomaly-detection_v2"
python run_all.py
```

**What's happening:**
- Backend (FastAPI) trains ML models if needed → listens on `http://127.0.0.1:8000`
- Frontend (React/Vite) builds → opens browser on `http://127.0.0.1:5173`
- SQLite database initializes with baseline metadata

**Expected console output:**
```
[*] Backend listening on http://127.0.0.1:8000
[*] Starting frontend dev server...
  VITE v5.x.x  ready in xxx ms
  ➜  Local:   http://127.0.0.1:5173/
```

> **Timing tip:** Wait ~20 seconds for both services to be ready, then open the browser.

---

## Part 2: Dashboard Overview (2 mins)

### What you'll see first:
A dark-themed dashboard with 4 main sections:

#### **Top: System Status Bar**
- **Status indicator:** Green = system ready, captures running, or stopped
- **Sliding window:** 30 seconds of packets = 1 analysis batch
- **Traffic stats:** Packets/sec, bytes/sec, active flows

#### **Left Panel: Navigation**
- Dashboard (real-time stats)
- Online Detection (live capture)
- Model Training (retrain from scratch)
- Upload Dataset (batch analysis)
- Historical Data (view past runs)

#### **Main Area: Real-Time Metrics**
- **Anomaly Rate**: % of flows flagged as suspicious
- **Attack Confidence**: How certain the model is
- **SYN Flood Risk**: Rule-based DDoS detection
- **Flow Count**: Active flows in sliding window

#### **Bottom: Latest Alerts**
- Each detection shows: timestamp, src IP, dst IP, confidence score, attack type
- Click any alert to see SHAP feature importance breakdown

---

## Part 3: Run Live Packet Capture (3-4 mins)

### Step 1: Open "Online Detection" tab

You'll see capture options:

**Option 1: Live Network Interface** (requires admin)
- Select your network adapter (e.g., "Ethernet", "Wi-Fi")
- Optional: IP filter (e.g., `192.168.1.0/24`)
- Optional: Port filter (e.g., `80,443,22`)
- Click **"Start Capture"** → begins sniffing packets

**Option 2: Simulation Mode** (no admin needed)
- Generates synthetic traffic patterns
- Useful for demo when you can't sniff real packets
- Click **"Start Simulation"** → injects mock botnet flows

**Option 3: Wireshark Baseline Training** (setup once)
- Trains model specifically on your network's normal baseline
- Reduces false positives

**Option 4: Upload PCAP File** (offline analysis)
- Drag/drop a `.pcap` or `.pcapng` file
- System processes all packets and generates report

### Step 2: What happens during capture
- **Live anomaly detection** runs every 30 seconds
- Each batch extracts 12 network flow features (packet rates, byte counts, flag counts, etc.)
- **Stage 1 (ML):** Isolation Forest scores each flow (0–1, lower = more anomalous)
- **Stage 2 (Rules):** DDoS heuristics flag SYN floods, port scans, volumetric attacks
- Results appear in the **Latest Alerts** section

### Step 3: Demo Talking Points
**"What's the system looking for?"**
- ✅ **Isolation Forest anomaly score** → unsupervised, no labels needed
- ✅ **SYN flag ratio** → elevated SYN flags = port scan or connection attack
- ✅ **Packet rate patterns** → bimodal: quiet C&C beacons + sudden DDoS bursts
- ✅ **Byte rate anomalies** → legitimate traffic is noisy; botnet C&C is suspiciously quiet
- ✅ **FIN flag count** → many abruptly-closed connections = scan & move on

---

## Part 4: Analyze a Detection (2-3 mins)

### Step 1: Click on any "Latest Alert"
A modal pops up showing:
- **Flow Summary**: src IP, dst IP, src port, dst port, protocol, duration
- **Raw Features**: packet rate, byte rate, SYN/FIN/RST counts, etc.
- **SHAP Explanation**: which features pushed this flow toward "anomalous"

### Step 2: Interpret the SHAP Chart
**Example reading:**
```
Feature                      Impact on Anomaly Score
─────────────────────────────────────────────────
SYN Flag Count     ████░░░░░░  +0.32 (big red bar = anomalous direction)
Packet Rate        ███░░░░░░░  +0.18
Fwd Bytes          ░░░░░░░░░░  -0.05 (green = normal)
```

**Interpretation:**
> "This flow has 15 SYN flags in 10 seconds — way higher than normal. Combined with an odd packet rate pattern, Isolation Forest flagged it. Most likely: port scan or DDoS SYN flood setup."

### Step 3: Attack Type Classification
The system shows a label: `SYN_FLOOD`, `PORT_SCAN`, `C2_BEACON`, or `ANOMALY`

---

## Part 5: Historical Data & Exports (2 mins)

### Step 1: Open "Historical Data" tab
You'll see past detection runs with:
- **Timestamp** of capture
- **Total flows** analyzed
- **Attack rate** (%)
- **Export options**: CSV, JSON, PDF, XML, TXT

### Step 2: Export a Report
Click **"Export as PDF"** → generates analyst-ready report with:
- Timeline graph of anomaly rate over time
- Top 10 anomalous flows
- Attack type distribution pie chart
- Confusion matrix (if labeled data available)

### Step 3: CSV Download
Raw flow data + predictions → load into Excel or Jupyter for custom analysis

---

## Part 6: Model Training (optional, 5+ mins)

### If time permits: Show model retraining

Go to **"Model Training"** tab:

**Two options:**

#### **Option A: Retrain from CTU-13 Baseline**
- Uses built-in CTU-13 dataset (38K attack + 53K normal)
- Click **"Train Baseline Models"**
- Takes ~30–60 seconds
- Resets Isolation Forest + autoencoder weights
- Useful if you suspect model drift

#### **Option B: Fine-tune on Your Data**
- Upload a labeled CSV (columns: features + `label` column with 0/1)
- Click **"Train Custom Model"**
- System learns your network's normal baseline
- Reduces false positives on your specific environment

**Model Artifacts saved:**
```
project/models/
├── scaler.pkl           # Feature normalization
├── isolation_forest.pkl # Anomaly detector
├── autoencoder.pkl      # Dimensionality reduction
└── meta.pkl             # Calibration & thresholds
```

---

## Part 7: Under the Hood (for technical audience, 3-4 mins)

### The Two-Stage Pipeline

**Stage 1: Isolation Forest**
```
Raw Flow Features (packet_rate, byte_rate, syn_count, ...)
         ↓
  StandardScaler (normalize 0–1)
         ↓
  Isolation Forest (n_trees=200, contamination=0.40)
         ↓
  Anomaly Score (-1 to +1, lower = suspicious)
         ↓
  Threshold comparison → Flag or pass
```

**Why it works:**
- Doesn't need labels (unsupervised)
- Fast (O(n log n) per flow)
- Handles multivariate anomalies (e.g., "SYN + low bytes + high rate" is suspicious)

**Stage 2: DDoS Rule Engine**
```
Flow Features
         ↓
  SYN Flood Rule: if syn_count > threshold & packet_rate > floor → FLAG
         ↓
  Port Scan Rule: if unique_dsts > threshold & duration < 5s → FLAG
         ↓
  Volumetric Rule: if byte_rate > 1 Gbps && variety_low → FLAG
         ↓
  Combined Score (higher confidence if both stages agree)
```

### Key Metrics from CTU-13

| Metric | Value |
|--------|-------|
| **Attack Precision** | 0.695 |
| **Attack Recall** | 0.555 |
| **ROC-AUC** | 0.706 |
| **Overall Accuracy** | 0.656 |

> "We prioritize **catch-all detection** (high recall) over minimal false positives (precision). In cybersecurity, missing a real attack is costlier than investigating a false alarm."

---

## Appendix: Talking Points by Audience

### For Security Teams
- "This runs on-premise; no cloud API calls."
- "SHAP explanations mean analysts understand *why* a flow is flagged."
- "Integrates with SIEM (export to Splunk/ELK via CSV/JSON)."
- "Rule engine is tunable — adjust thresholds for your network."

### For Data Scientists
- "Isolation Forest is efficient for real-time detection."
- "Hybrid supervised + unsupervised reduces false positives."
- "Autoencoder learns network normal — drift detection next."
- "SHAP is model-agnostic; easy to swap in XGBoost or random forest."

### For Executives
- "Detects botnet C&C traffic and DDoS pre-attack reconnaissance."
- "Fully automated — no SOC analyst tuning required."
- "Scales: processes 1000s of flows/sec."
- "Trained on real-world data (CTU-13 botnet scenarios)."

### For Network Engineers
- "Works with tcpdump, Wireshark PCAP exports."
- "Minimal overhead: runs on edge device or forwarding box."
- "Live capture uses libpcap (works on Linux, Windows, macOS)."
- "Optional Wireshark direct integration for baseline training."

---

## Troubleshooting Cheat Sheet

| Issue | Fix |
|-------|-----|
| **Port 8000 already in use** | `netstat -ano \| findstr 8000` → kill the process |
| **Frontend won't connect to backend** | Check CORS is enabled (it is by default) |
| **No network interfaces found** | Run as admin, or use Simulation mode |
| **Slow model training** | Normal for first startup; models cache after |
| **No alerts showing** | Capture 30+ seconds of traffic; anomalies are rare by design |
| **High false positive rate** | Retrain on your network's baseline (Model Training tab) |

---

## Time Breakdown Summary

| Section | Time |
|---------|------|
| Opening (what we're building) | 1 min |
| Launch system | 2 min |
| Dashboard walkthrough | 2 min |
| Live packet capture | 3–4 min |
| Analyze a detection | 2–3 min |
| Historical data & exports | 2 min |
| Model training (optional) | 5+ min |
| Under the hood (optional) | 3–4 min |
| **Total** | **20–25 min** |

> **Pro tip:** For a 15-minute demo, skip "Model Training" and "Under the Hood" sections. Focus on Parts 1–5.

---

## Demo Script Variations

### Quick 10-minute Version
1. Launch app (2 min) → 2. Show dashboard (2 min) → 3. Start simulation (2 min) → 4. Click alert for SHAP (2 min) → 5. Export PDF (2 min)

### Deep Technical 30-minute Version
All sections + code walkthrough in VS Code (show ddos_classifier.py and isolation forest logic)

### Live Demo (Risky)
Use **Option 4: Upload PCAP file** with a pre-prepared pcap. Safer than live sniffing; still shows real detection.

---

## Recording Tips (if recording the demo)

- **Slow down mouse clicks** — audience needs time to read
- **Zoom browser** to 125–150% so text is readable
- **Pause after each alert** to let audience read the SHAP chart
- **Mute system sounds** before recording
- **Pre-load the frontend** before hitting record (avoids startup stutter)

