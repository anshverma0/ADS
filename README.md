# Aegis-IDS: Unsupervised Network Anomaly & DDoS Detection System

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/node.js-18%2B-green.svg)](https://nodejs.org/)
[![Framework](https://img.shields.io/badge/backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Frontend](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61DAFB.svg)](https://vitejs.dev/)
[![ML Pipeline](https://img.shields.io/badge/ML-Isolation%20Forest%20%2B%20Autoencoder-orange.svg)](https://scikit-learn.org/)

**Aegis-IDS** is an enterprise-grade, real-time Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) dashboard. It combines **unsupervised machine learning** (Isolation Forest + Autoencoder ensemble) with a **rule-based DDoS subtype classifier** and a **window-level aggregate volumetric detector** to detect zero-day anomalies, stealthy botnet C&C traffic, and distributed volumetric flood attacks without relying solely on static signatures.

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Architecture & Detection Pipeline](#-architecture--detection-pipeline)
- [Prerequisites](#-prerequisites)
- [Quick Start Guide](#-quick-start-guide)
  - [1. Clone Repository & Setup Python Environment](#1-clone-repository--setup-python-environment)
  - [2. Launch Full Web Application (Recommended)](#2-launch-full-web-application-recommended)
  - [3. Accessing the User Interfaces & API](#3-accessing-the-user-interfaces--api)
  - [4. Alternative Execution Modes](#4-alternative-execution-modes)
- [Attack Classification Reference](#-attack-classification-reference)
  - [Volumetric Attacks](#volumetric-attacks)
  - [Unknown Anomalies](#unknown-anomalies)
  - [Targeted DDoS & Intrusion Subtypes](#targeted-ddos--intrusion-subtypes)
- [SecureAI Agent (CVE & MITRE ATT&CK Mapping)](#-secureai-agent-cve--mitre-attck-mapping)
- [Datasets & Research Papers](#-datasets--research-papers)
- [Project Directory Structure](#-project-directory-structure)
- [API Documentation](#-api-documentation)

---

## ⚡ Key Features

- **Unsupervised Ensemble Machine Learning:** Uses an Isolation Forest and Autoencoder trained on normal traffic patterns to spot zero-day anomalies without requiring prior labeled attack signatures.
- **Two-Stage Detection Pipeline:**
  - **Stage 1 (Anomaly Detection):** Continuous flow statistical scoring.
  - **Stage 2 (Threat Subtype Classification):** Rule-based engine determining specific attack types.
- **Aggregate Volumetric Track:** Window-level multi-source aggregation (5-second sub-windows) targeting distributed IP spoofing campaigns that bypass single-flow detectors.
- **Real-Time Live Capture & PCAP Ingestion:** Sniffs live traffic via Scapy/PyShark or ingests `.pcap` files and CSV logs.
- **Modern SOC Dashboard:** React frontend powered by Vite featuring live traffic feeds, anomaly charts, campaign aggregations, flow exploration, and system logs.
- **SecureAI Agent Layer:** GPT-4o / Ollama AI advisor for automated incident reports, CVE lookups, and MITRE ATT&CK tactic/technique mapping.

---

## 🏗 Architecture & Detection Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Network Traffic / Ingestion Source                   │
│         (Live Network Interface / Uploaded PCAP / CSV Dataset)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Feature Extractor (Flow Generator & Aggregator)           │
│        Extracts 10 core features: pps, bps, TCP flags, duration...     │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│       Stage 1: Unsupervised ML       │  │ Stage 1b: Window Aggregator  │
│ (Isolation Forest + Autoencoder)     │  │ (5s Window Multi-Source)     │
└───────────────────┬──────────────────┘  └──────────────┬───────────────┘
                    │                                    │
                    ▼                                    ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│      Stage 2: DDoS Classifier        │  │ Aggregate Volumetric Model   │
│ (Rule Engine & Subtype Fingerprint)  │  │ (Catches Distributed Floods) │
└───────────────────┬──────────────────┘  └──────────────┬───────────────┘
                    │                                    │
                    └───────────────────┬────────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Aegis SOC Dashboard & FastAPI Backend                  │
│       (Live Alerts, Incident Reports, History, SecureAI Advisor)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Prerequisites

Before installing, ensure you have the following installed on your machine:

1. **Python:** Version `3.10` or higher
2. **Node.js:** Version `18.0` or higher (includes `npm`)
3. **Packet Capture Driver (Optional for Live Sniffing):**
   - **Windows:** [Npcap](https://npcap.com/) (select "Install Npcap in WinPcap API-compatible Mode")
   - **Linux/macOS:** `libpcap-dev` (`sudo apt install libpcap-dev` or `brew install libpcap`)

---

## 🚀 Quick Start Guide

### 1. Clone Repository & Setup Python Environment

```bash
# Clone the repository
git clone https://github.com/akrishnash/anamoly_detection.git
cd anamoly_detection

# Create and activate a virtual environment (recommended)
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

---

### 2. Launch Full Web Application (Recommended)

To run the complete system (FastAPI backend + Vite React frontend + Orchestrator), simply run:

```bash
python run_all.py
```

#### What `run_all.py` automatically handles:
1. Checks and installs React dependencies (`npm install` inside `project/frontend`).
2. Scans for free local ports (defaults to Backend: `8000`, Frontend: `5173`).
3. Boots the FastAPI backend server and preloads the machine learning models.
4. Waits for the backend to be healthy before starting the Vite frontend.
5. Automatically opens your default web browser to the dashboard URL.

---

### 3. Accessing the User Interfaces & API

Once `run_all.py` completes startup, you can access the application at:

| Interface | URL | Description |
| :--- | :--- | :--- |
| **Aegis SOC Dashboard (Frontend)** | **`http://127.0.0.1:5173`** | Complete graphical dashboard (Live Monitoring, Sentinel, Flow Explorer, Incident History). |
| **FastAPI Swagger API Docs** | **`http://127.0.0.1:8000/docs`** | Interactive OpenAPI specification to test endpoints directly. |
| **FastAPI ReDoc API Docs** | **`http://127.0.0.1:8000/redoc`** | Alternative clean API documentation interface. |

---

### 4. Alternative Execution Modes

#### A. Standalone Lightweight Dashboard
If you prefer a lightweight single-process dashboard without React build steps:
```bash
python simple_dashboard/server.py
```
Access at `http://127.0.0.1:5000`.

#### B. Ingest Attack Logs / PCAP Files via CLI
To process a local dataset file or attack log directly:
```bash
python ingest_attack_logs.py
```

#### C. Run Research & Benchmark Experiments
```bash
# Isolation Forest on CTU-13 dataset
python research/run_ctu13.py

# Feature importance & Dataset comparison
python research/compare_datasets.py

# Isolation Forest visual decision-tree walkthrough
python research/explain_isolation_forest.py
```

---

## 🔍 Attack Classification Reference

The Stage 2 Classifier ([ddos_classifier.py](file:///c:/Users/ADRIN/ADS/project/backend/ddos_classifier.py)) assigns detailed threat signatures to anomalous flows:

### Volumetric Attacks
* **Volumetric Flood (Per-Flow):** Triggered when sustained flow packet rate exceeds **1,000 pkts/s** or byte rate exceeds **5 MB/s** without matching specific application protocol rules.
* **Volumetric DDoS (Aggregate):** Triggered when a window-level aggregate detects $\ge 10$ distinct source IPs bombarding a single target host simultaneously.

### Unknown Anomalies
* **Unknown Anomaly:** Triggered when Stage 1 ML models flag a flow's statistical behavior as highly anomalous (low Isolation Forest score / high Autoencoder reconstruction error), but the traffic pattern does not match any static attack signature rule.

### Targeted DDoS & Intrusion Subtypes
* **SYN Flood:** TCP traffic with $\ge 50\%$ SYN flags and minimal/no ACK replies (half-open connection flood).
* **UDP Flood:** Unidirectional high-rate UDP traffic ($>50\text{ pkts/s}$ or $>100$ packets with no response).
* **ICMP Flood:** Sustained high-frequency ICMP ping floods ($>20\text{ pkts/s}$).
* **Amplification Attack:** Abused UDP reflector services (DNS, NTP, SNMP, Memcached, SSDP) generating oversized responses ($>400\text{ bytes}$).
* **Slowloris (Slow HTTP):** Low-rate ($<2\text{ pkts/s}$), small-packet connections held open for extended durations ($>30\text{ seconds}$).
* **HTTP Flood:** Established web connections (ports 80/443) receiving request rates $>20\text{ pkts/s}$.
* **Brute Force:** High frequency of small packets targeting auth ports (SSH: 22, FTP: 21, RDP: 3389, SMB: 445).
* **Data Exfiltration:** Large one-way outbound data transfers exceeding $1\text{ MB}$.

---

## 🤖 SecureAI Agent (CVE & MITRE ATT&CK Mapping)

The project includes an AI Security Analyst agent ([research/agent/agent.py](file:///c:/Users/ADRIN/ADS/research/agent/agent.py)) capable of enriching detected anomalies with threat intelligence.

### Configuration
1. **Cloud Mode (OpenAI GPT-4o):**
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   python research/agent/agent.py
   ```
2. **Local Air-Gapped Mode (Ollama / Llama 3):**
   Edit `agent.py` to point to your local Ollama instance:
   ```python
   client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
   MODEL = "llama3.1"
   ```

---

## 📊 Datasets & Research Papers

The system is tested and benchmarked against standard NIDS datasets:
- **CTU-13 Botnet Dataset:** 38,898 attack flows & 53,314 normal flows across 13 botnet scenarios.
- **CIC-DDoS2019 Dataset:** Parquet flow captures used for volumetric flood benchmarking.
- **NSL-KDD Dataset:** Classical benchmark evaluation.

Research documentation and evaluation reports are available in the [`docs/`](file:///c:/Users/ADRIN/ADS/docs) directory:
- [TECHNICAL_REPORT.md](file:///c:/Users/ADRIN/ADS/docs/TECHNICAL_REPORT.md): Field evaluation, benchmark failure analysis, and aggregate detector architecture.
- [leakage_report.md](file:///c:/Users/ADRIN/ADS/docs/leakage_report.md): Analysis of data leakage risks in standard NIDS machine learning benchmarks.

---

## 📁 Project Directory Structure

```
anamoly_detection/
├── run_all.py                # 🚀 One-command system launcher (Backend + Frontend)
├── ingest_attack_logs.py     # Log ingestion CLI script
├── requirements.txt          # Root Python dependencies
├── README.md                 # Project documentation
│
├── project/                  # Aegis Production Application
│   ├── backend/              # FastAPI Server & ML Detection Engine
│   │   ├── main.py           # FastAPI entrypoint
│   │   ├── api.py            # API routes and endpoints
│   │   ├── anomaly_detector.py # Isolation Forest & Autoencoder ensemble
│   │   ├── ddos_classifier.py  # Stage 2 DDoS Rule Engine
│   │   ├── flow_aggregator.py  # Sub-window traffic aggregation
│   │   ├── packet_capture.py # Live Scapy network interface sniffer
│   │   └── database.py       # SQLite incident logging store
│   │
│   ├── frontend/             # React (Vite) Security Operations Center
│   │   ├── src/pages/        # Dashboard, Live Detection, Sentinel, History
│   │   ├── package.json      # Node dependencies
│   │   └── vite.config.js    # Vite configuration & proxy settings
│   │
│   └── models/               # Trained ML models & scalers (.pkl, .pt)
│
├── research/                 # Model Training, Benchmark & AI Agent Scripts
│   ├── agent/                # SecureAI Agent (GPT-4o / Ollama)
│   ├── run_ctu13.py          # CTU-13 benchmark runner
│   ├── compare_datasets.py   # Statistical feature significance tests
│   └── explain_isolation_forest.py # IF decision tree visualizer
│
├── docs/                     # Technical Reports, Papers & Graphs
└── data/                     # Datasets (CTU-13, CIC-DDoS2019, NSL-KDD)
```

---

## 🔌 API Documentation

When the backend is running at `http://127.0.0.1:8000`, the following core REST endpoints are available:

- **`GET /api/online/status`** — System status and active network interface.
- **`POST /api/online/start`** — Start real-time live network packet sniffing.
- **`POST /api/online/stop`** — Stop real-time live network sniffing.
- **`GET /api/logs`** — Retrieve historical anomaly logs and threat verdicts.
- **`POST /api/detect`** — Submit flow records or PCAP files for on-demand analysis.
- **`GET /api/stats`** — Overall threat statistics, attack distribution, and protocol breakdown.

---

## 📄 License & Attribution

Distributed under the MIT License. See `LICENSE` for more information.

Dataset & Data Source Citations:
- **CTU-13 Dataset:** Stratosphere IPS Project, CTU University Prague.
- **CIC-DDoS2019 Dataset:** Canadian Institute for Cybersecurity (UNB).
- **NSL-KDD Dataset:** University of New Brunswick (UNB) / Tavallaee et al. (improved version of KDD Cup 99).
- **Live Captured Network Data:** Real-time live network traffic captured via Wireshark / TShark / Scapy packet engine.

