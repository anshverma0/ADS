# DDoS Attack Simulation Training Guide

Complete workflow to generate realistic DDoS attack data for model training.

## Overview

```
┌─────────────────────────────┐
│  Run Attack Simulator       │  ← Generates various DDoS attacks
│  (ddos_attack_simulator.py) │    Logs each attack with timestamp & type
└──────────────┬──────────────┘
               │
               ▼
┌──────────────────────────────┐
│  Ingest Attack Logs          │  ← Converts logs to labeled training data
│  (ingest_attack_logs.py)     │    CSV with attack types & statistics
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  Retrain Models              │  ← Updates Isolation Forest with new data
│  (train_models.py)           │    Reduces false positives on real attacks
└──────────────────────────────┘
```

---

## Step 1: Generate Attack Data

### Run the Attack Simulator

**For 1-hour training (quick test):**
```bash
cd "e:\Projects Internet room\anomaly-detection_v2\project\backend"
python ddos_attack_simulator.py --target 192.168.1.10 --duration 1 --intensity variable
```

**For 4-hour training (comprehensive):**
```bash
python ddos_attack_simulator.py --target 192.168.1.10 --duration 4 --intensity variable
```

**For heavy stress testing:**
```bash
python ddos_attack_simulator.py --target 192.168.1.10 --duration 2 --intensity heavy
```

### Parameters

| Param | Description | Examples |
|-------|-------------|----------|
| `--target` | Target IP address (must be yours!) | `192.168.1.10`, `10.0.0.1` |
| `--duration` | Hours to run | `0.5` (30 min), `1`, `4` |
| `--intensity` | Attack intensity | `light` (100-500 pps), `medium` (1k-5k), `heavy` (5k-20k), **`variable`** (recommended) |

### What It Does

1. **Generates 6 attack types** (in random order each 10-min window):
   - **SYN Flood** — Connection exhaustion (port scanner detection)
   - **UDP Flood** — Bandwidth exhaustion
   - **ACK Flood** — Reflection/amplification attack
   - **HTTP GET Flood** — Application layer attack
   - **Slowloris** — Resource starvation
   - **Port Scan** — Reconnaissance

2. **Logs each attack** with:
   - Timestamp (ISO format)
   - Attack type
   - Source/destination IPs
   - Packets sent
   - Duration
   - Intensity level
   - Packets per second (pps)

3. **Saves to CSV**: `ddos_training_log_YYYYMMDD_HHMMSS.csv`

### Safety Features

✓ **Requires confirmation** before starting (type "yes")
✓ **Stoppable** (Ctrl+C exits gracefully)
✓ **Only targets specified IP** (no collateral damage)
✓ **Logs everything** (audit trail)
✓ **Progress indicator** (shows window count and timing)

---

## Step 2: Convert Logs to Labeled Training Data

Once attack simulation finishes, ingest the logs:

```bash
python ingest_attack_logs.py ddos_training_log_20250721_143022.csv --integrate
```

### What It Does

1. **Reads** the attack simulation CSV
2. **Generates** flow-level training records from packet statistics
3. **Labels** each record: `label=1` (attack) or `label=0` (normal)
4. **Creates output CSV**: `training_data_with_labels.csv`
5. **Generates report**: `training_report.json`
6. **Copies to datasets folder** (if `--integrate` flag used)

### Output Example

```csv
timestamp,attack_type,label,src_ip,dst_ip,packet_count,byte_count,packet_rate,byte_rate,intensity
2025-07-21T14:30:45.123456,SYN_FLOOD,1,192.168.1.150,192.168.1.10,2450,156800,40.8,2613.3,medium
2025-07-21T14:31:02.456789,UDP_FLOOD,1,185.220.101.42,192.168.1.10,5120,7372800,85.3,122880.0,heavy
2025-07-21T14:35:18.789012,PORT_SCAN,1,203.0.113.45,192.168.1.10,890,56960,14.8,949.3,light
```

### Training Report

```json
{
  "total_records": 1200,
  "attack_records": 900,
  "normal_records": 300,
  "attack_types": {
    "SYN_FLOOD": 250,
    "UDP_FLOOD": 200,
    "HTTP_FLOOD": 150,
    "PORT_SCAN": 150,
    "ACK_FLOOD": 100,
    "SLOWLORIS": 50
  },
  "avg_packet_rate": 45.2,
  "avg_byte_rate": 52384.5,
  "time_range": {
    "start": "2025-07-21T14:30:00",
    "end": "2025-07-21T18:30:00"
  }
}
```

---

## Step 3: Retrain Your Models

Now that you have labeled attack data, retrain your Isolation Forest:

```bash
python train_models.py --use-custom-data training_data_with_labels.csv
```

This will:
1. Load your custom training data
2. Mix with CTU-13 baseline (optional)
3. Retrain Isolation Forest with the new distribution
4. Save updated models to `project/models/`
5. Reduce false positives on *your* network patterns

---

## Full Workflow Example (4-hour training)

```bash
# Step 1: Generate 4 hours of attacks (takes 4 hours real-time)
python ddos_attack_simulator.py --target 192.168.1.10 --duration 4 --intensity variable

# ✓ Produces: ddos_training_log_20250721_143022.csv

# Step 2: Convert to labeled training data (takes ~30 seconds)
python ingest_attack_logs.py ddos_training_log_20250721_143022.csv --integrate

# ✓ Produces:
#   - training_data_with_labels.csv
#   - training_report.json
#   - Copies to project/datasets/attack_logs/

# Step 3: Retrain models (takes ~60 seconds)
python train_models.py --use-custom-data training_data_with_labels.csv

# ✓ Models updated. Test immediately:
python -m uvicorn main:app --reload --port 8000
# → Open http://127.0.0.1:5173 in browser
# → Run online detection
# → Should see LOWER false positives on your network traffic
```

---

## Attack Types Explained

### 1. SYN Flood
- **What**: Sends many TCP SYN packets (connection initiation requests)
- **Effect**: Target's connection table fills up; can't accept new connections
- **Detection signal**: Elevated SYN flag count + short flow duration
- **ML pattern**: Isolation Forest catches the anomalous "almost-connections"

### 2. UDP Flood
- **What**: Sends many UDP packets to random destination ports
- **Effect**: Consumes bandwidth and processing resources
- **Detection signal**: High packet rate + high byte rate + random port distribution
- **ML pattern**: Unusual flow size and rate combination

### 3. ACK Flood
- **What**: Sends many TCP ACK packets (fake responses)
- **Effect**: Confuses stateless firewalls; wastes bandwidth on parsing
- **Detection signal**: Many ACK flags without prior SYN flags
- **ML pattern**: Stateless pattern detection

### 4. HTTP GET Flood
- **What**: Sends many HTTP GET requests (simulates legitimate web browsing at scale)
- **Effect**: Exhausts web server resources (threads, memory, disk I/O)
- **Detection signal**: Sustained high request rate from single/few sources
- **ML pattern**: Application-layer traffic anomaly

### 5. Slowloris
- **What**: Opens connections and sends partial HTTP requests; keeps connections alive
- **Effect**: Holds server resources open; server waits for completion
- **Detection signal**: Many long-lived connections with minimal data transfer
- **ML pattern**: Connection hold time + low throughput anomaly

### 6. Port Scan
- **What**: Sends SYN packets to many ports on target (reconnaissance)
- **Effect**: Identifies open ports; precursor to actual attack
- **Detection signal**: Many different destination ports from one source
- **ML pattern**: High cardinality (variety) in destination ports

---

## Intensity Levels Explained

| Intensity | Packets/sec | Duration | Best For |
|-----------|------------|----------|----------|
| **light** | 100–500 | Gradual ramp-up testing | Testing detection thresholds |
| **medium** | 1k–5k | Moderate stress | Production-like attack patterns |
| **heavy** | 5k–20k | Stress testing | Model robustness validation |
| **variable** | Mixed | Realistic training | Best for real-world deployment |

**Variable intensity recommendation:**
- Slowly ramps up (light → medium → heavy)
- Then back down (heavy → medium → light)
- Repeats over the training period
- Mimics real attack escalation patterns
- Best for training models to detect emerging threats

---

## CSV Column Reference

### Attack Simulator Output (`ddos_training_log_*.csv`)

| Column | Meaning |
|--------|---------|
| `timestamp` | ISO 8601 timestamp when attack started |
| `attack_type` | Type of attack (SYN_FLOOD, UDP_FLOOD, etc.) |
| `src_ip` | Source IP address (spoofed attacker) |
| `dst_ip` | Destination IP (target) |
| `packets_sent` | Total packets in this attack window |
| `duration_sec` | How long the attack lasted |
| `intensity` | Intensity level (light/medium/heavy/variable) |
| `pps` | Packets per second average |

### Training Data Output (`training_data_with_labels.csv`)

| Column | Meaning |
|--------|---------|
| `timestamp` | Flow start time |
| `attack_type` | Type of attack |
| `label` | 1=attack, 0=normal |
| `src_ip`, `dst_ip` | Flow endpoints |
| `packet_count` | Packets in flow |
| `byte_count` | Bytes in flow |
| `packet_rate` | Packets per second |
| `byte_rate` | Bytes per second |
| `intensity` | Attack intensity when created |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **"Permission denied" or "raw socket error"** | Run as Administrator (needed for scapy packet injection) |
| **"No module named scapy"** | `pip install scapy` |
| **Target IP doesn't match actual server** | Simulator sends spoofed packets; they must route to your target |
| **No alerts in detection dashboard** | Make sure simulator is running while checking the web UI |
| **Model retraining fails** | Ensure training CSV is in correct format (use ingest_attack_logs.py) |

---

## Advanced Usage

### Combine Multiple Training Sessions

```bash
# Session 1: 1 hour
python ddos_attack_simulator.py --target 192.168.1.10 --duration 1

# Session 2: 1 hour (different patterns)
python ddos_attack_simulator.py --target 192.168.1.10 --duration 1

# Merge logs
cat ddos_training_log_*.csv > combined_attacks.csv

# Ingest combined
python ingest_attack_logs.py combined_attacks.csv
```

### Create Custom Attack Mix

Modify `attack_types` list in `ddos_attack_simulator.py` to focus on specific attacks:

```python
# Only SYN and UDP floods
attack_types = [
    generator.syn_flood,
    generator.udp_flood,
]

# Run with variable intensity
python ddos_attack_simulator.py --target 192.168.1.10 --duration 2 --intensity variable
```

### Adjust Packet Rates

Modify `pps_by_intensity` dictionary:

```python
self.pps_by_intensity = {
    "light": (50, 200),        # Lower rates
    "medium": (500, 2000),     # Medium rates
    "heavy": (2000, 10000),    # High rates
}
```

---

## Expected Training Times

| Duration | Real Time | CPU Usage | Output Size |
|----------|-----------|-----------|-------------|
| 1 hour | 1 hour | ~40% (1 core for sniffing) | ~50 MB CSV |
| 4 hours | 4 hours | ~40% | ~200 MB CSV |

**Notes:**
- Most time is spent *waiting* between attack windows (intentional)
- Ingest and retraining are fast (< 1 min combined)
- Can run simulator in background while working

---

## After Training

1. **Evaluate new model** on historical data
2. **Monitor false positive rate** on your network
3. **Adjust thresholds** if needed
4. **Deploy updated models** to production

```bash
# Test new model on existing captures
python project/backend/api.py

# Open web UI → Upload Dataset → choose your historical PCAP
# Compare metrics against old model
```

---

## Questions?

- Check logs: `ddos_attack_simulator.py` prints progress every window
- Check CSV: Open `training_data_with_labels.csv` in Excel/Python
- Check report: View `training_report.json` for statistics
