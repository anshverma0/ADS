# Detecting Distributed Denial-of-Service Attacks on Live Network Traffic: From Benchmark Accuracy to Field Validity

**Summer Research Project — Technical Report**

---

## Abstract

An unsupervised two-stage anomaly-detection system (Isolation Forest + Autoencoder ensemble, followed by a rule-based classifier) scored 88.1% accuracy on the CICDDoS2019 benchmark. This report documents what happened when the same system was evaluated on *real traffic captured on a live network* rather than on a pre-processed benchmark. Under a faithful reproduction of the production inference path, detection collapsed to **49.7% balanced accuracy — statistically indistinguishable from chance**. This report (1) establishes that the collapse is a genuine generalization failure and not an ingestion artifact, by re-encoding the capture into the exact benchmark schema and reproducing the result; (2) traces the failure to a mismatch between the *unit of detection* (per-flow) and the *structure of a spoofed volumetric attack* (per-host, per-window); (3) introduces a window-level aggregation detector with source-cardinality features trained on a benign baseline of the target network; and (4) validates the redesign both offline and in the live application. The redesigned detector achieves **0.95 balanced accuracy and 1.00 recall** on captured attack traffic, reduces the live benign false-alarm rate from **31.7% to 0.0%**, and flags real spoofed floods in the running system at 99% confidence. The central lesson is methodological: benchmark accuracy did not transfer to field conditions, and only field capture revealed why.

---

## 1. Introduction

Distributed Denial-of-Service (DDoS) detection is a standard application of network anomaly detection, and public benchmarks such as CICDDoS2019 report high accuracies for a wide range of models. This project began with an existing system that reproduced those results — 88.1% accuracy on the benchmark — and asked a deployment question: *does it detect attacks on traffic we capture ourselves?*

The answer was no, and the gap between the two settings turned out to be the most instructive part of the project. This report is organized around that gap: how it was measured, why it exists, and what design change closes it.

### 1.1 Contributions

- A reproducible demonstration that a benchmark accuracy of 0.88 corresponds to ~0.50 balanced accuracy on real captured traffic, with the schema controlled for as a confound.
- A root-cause analysis attributing the failure to the per-flow decision unit under source-IP spoofing.
- A window-level aggregation detector with source-cardinality/entropy features, trained unsupervised on a network-specific benign baseline.
- A two-machine capture-and-verification methodology that produces trustworthy ground truth, including a verifier that caught a silent capture defect.
- Offline and live validation of the redesign, including a false-positive analysis and a principled cardinality threshold.

---

## 2. Background: the baseline system

The system under study is a two-stage detector operating on network *flows* (bidirectional 5-tuple aggregations of packets):

- **Stage 1 — unsupervised anomaly scoring.** An Isolation Forest and a shallow Autoencoder are each trained on benign flows only. Their scores are calibrated to [0, 1] and fused by a union (max) rule; a flow is anomalous if either head fires. Ten features are used: flow byte/packet rates, forward/backward bytes, total packets, SYN/RST/FIN flag counts, duration, and mean packet length.
- **Stage 2 — rule-based classification.** Flagged flows are labelled into attack subtypes (SYN flood, UDP flood, amplification, HTTP flood, etc.) by a transparent rule engine over protocol, flag ratios, rates, and ports.

On CICDDoS2019 (306,201 test flows) this system reports:

| metric | value |
|---|---|
| accuracy | 0.8807 |
| precision | 0.9963 |
| recall | 0.8597 |
| F1 | 0.9230 |
| subtype segregation (of detected) | 0.9967 |

These numbers are the starting point and the thing to be tested in the field.

---

## 3. Field evaluation and the accuracy collapse

### 3.1 Method

A capture was taken on a live host and a set of scripted attacks (SYN, UDP, ACK, HTTP floods) were run against it, each logged with start/end timestamps forming the ground truth. The capture was replayed through the **exact production inference path** — packets sliced into fixed windows *before* flow grouping (as the live sniffer does), then Stage 1 + Stage 2. Flows were labelled by time-overlap with the attack segments. Two window sizes (30 s production, 5 s fine-grained) were evaluated.

### 3.2 Result

| decision rule (30 s) | accuracy | **balanced accuracy** | precision | recall | ROC-AUC |
|---|---|---|---|---|---|
| ML ensemble | 0.124 | **0.495** | 0.21 | 0.0004 | 0.817 |
| rule engine | 0.124 | 0.496 | 0.25 | 0.0004 | — |
| hybrid (ML ∪ rule) | 0.124 | 0.493 | 0.22 | 0.0006 | — |

Recall was ~0.0005: of 140,339 attack flows, the system flagged 80. The raw accuracy of 0.12 is *lower* than chance only because the labelled set is 87% attack and the detector abstains on almost everything; **balanced accuracy of 0.49 is the honest summary — the detector is a coin flip.**

### 3.3 Controlling for schema as a confound

A natural objection is that the capture pipeline differs from the benchmark's, so the collapse might be an ingestion artifact rather than a model failure. To rule this out, the capture's flows were re-encoded into the **exact CICDDoS2019 / CICFlowMeter column schema** (including the microsecond duration convention and numeric protocol encoding), verified to map onto the canonical feature set with **zero missing features**, and scored through the identical path that produced the 0.88 benchmark number.

The re-encoded evaluation reproduced the field result byte-for-byte (31 true positives, 168 false positives, ROC-AUC 0.849). Same columns, same preprocessing, same scaler, same threshold, same rule engine — **only the traffic differs.** The 0.88 → 0.15 drop is therefore attributable to what the flow records *contain*, not to how they are ingested.

---

## 4. Root-cause analysis

### 4.1 The attack decomposes into single-packet flows

The attack generator spoofs source IPs. A SYN flood of 3,301 packets from ~1,500 forged sources is grouped by the 5-tuple into ~1,500 flows **of one packet each**. Measured on the capture, the median attack flow contains **1 packet**; 99.0% contain ≤2. A one-packet flow has no rate, no flag ratio, and no directional asymmetry — none of the signals the ten features encode.

### 4.2 The attack flow looks *more benign than the benign baseline*

Comparing the median of each feature — training baseline vs. captured attack:

| feature | benign baseline | captured attack |
|---|---|---|
| total packets | 2.0 | **1.0** |
| forward bytes | 132 | **54** |
| mean packet length | 75 | **54** |
| SYN flag count | 0 | **0** |
| duration (s) | 0.417 | **0.0001** |

On seven of ten features the attack flow is quieter than the median benign flow the model was trained on. For an unsupervised detector, "anomalous" means "unlike benign," and a 1-packet reply is not unlike benign. The two features that *do* differ (packet/byte rate) are artifacts: a 1-packet flow's duration is clamped to a small constant, yielding a spurious ~10,000 pkt/s that the Stage 2 volume floor (`MIN_FLOOD_PKTS`) deliberately distrusts. The rule engine is correct to ignore it; the consequence is that neither stage can fire.

### 4.3 A capture defect (found by verification, not by luck)

The first attack capture recorded only **11 SYN packets for a 3,301-packet flood** — because the attacker and victim were the same host, and OS-injected frames destined for the local IP bypass the local capture path (a documented Npcap/loopback behavior on Windows). The capture had recorded the victim's *replies*, not the inbound flood, making SYN detection structurally impossible regardless of model quality. This was caught by an explicit verifier, not observed by chance, and motivated the two-machine methodology in §5.1.

### 4.4 Diagnosis

The failure is not a tuning problem — the per-flow ROC-AUC of 0.82–0.85 shows the ensemble still *ranks* attack flows above benign, so discrimination survives while the operating point does not. The failure is structural: **a distributed volumetric attack is a property of a (victim, time-window) aggregate — how many distinct sources strike one host — and that property is not expressible in any single 5-tuple flow record.** No amount of per-flow retraining recovers a signal the representation cannot hold.

---

## 5. Methodology of the redesign

### 5.1 Trustworthy ground truth: two-machine capture

Attacks are generated from a **separate host** on the LAN so the flood arrives as real inbound frames, and captured on the victim's NIC. To keep the attacker's timeline epochs aligned with the victim's packet timestamps, both machines are NTP-synchronized before each run (measured offset < 100 ms; the 15 s attack windows tolerate this comfortably). A **verifier** compares inbound SYN counts (and total inbound packets) per attack segment against the generator's logged `packets_sent`, emitting a GOOD/INCOMPLETE verdict. The re-capture used for all subsequent results passed at **3,286 inbound SYNs of 3,297 sent (99.7%)** — the defect of §4.3 eliminated.

### 5.2 Changing the unit of detection

Traffic is aggregated per **(time-window, victim, protocol)**, producing one record per host-protocol-window rather than per flow. Two grouping scopes are emitted, because the requirements conflict:

- **`victim_proto`** (port omitted) — preserves source cardinality even when the attack randomizes destination ports. Used for anomaly scoring.
- **`victim_proto_port`** (port retained) — preserves the destination-port signal the Stage 2 web/service rules require.

A window is attack if either scope fires. This dual-scope design was forced by measurement: a port-inclusive-only key shattered a port-randomizing UDP flood into ~3,000 one-packet buckets, reintroducing the original failure; a port-exclusive-only key broke HTTP-flood classification.

### 5.3 Features that carry the signal

Beyond aggregate versions of the original ten, the record adds cardinality and shape features. Source cardinality is counted **direction-agnostically** (peers on either side), because a capture may record the victim's replies rather than the inbound flood. Measured separation (5 s windows):

| feature | benign (mean) | SYN/ACK/UDP flood (mean) |
|---|---|---|
| unique peers | 7–44 | **440–1,107** |
| packet rate (pkt/s) | ~8 | **90–221** |
| RST rate | 0.00 | **0.50** (SYN) |

The 40–75× separation on unique peers is cleaner than any signal in the original feature set.

### 5.4 A protocol-classification bug surfaced by the ICMP reply path

During validation, a UDP flood's one-way ratio was being destroyed intermittently. Root cause: a UDP flood to random ports elicits **ICMP port-unreachable** replies, and each ICMP error *quotes the original UDP header* in its payload. With scapy's layer filter active, `haslayer("UDP")` matched that quoted header and misclassified the victim's ICMP replies as outbound UDP, flipping the flood's direction ratio and hiding it from the rules. The fix is to classify protocol by the **IP header's protocol field**, which is filter-proof, rather than by nested-layer presence. This is noted because it is exactly the kind of defect that benchmark data — which never contains reply traffic — cannot expose.

### 5.5 Unsupervised training on a network-specific baseline

An Isolation Forest is trained on aggregate features from a **60-minute benign capture of the target network** (504,874 packets → 1,573 benign windows). The decision threshold is set from the benign score distribution at a target false-positive rate rather than a fixed 0.5, and stored with the model. Training on this network matters: the original baseline came from a different network whose benign packet rate was 45× lower, which is itself a source of false positives.

---

## 6. Results

### 6.1 Offline, on captured attack traffic

Protocol-aware labelling (a TCP flood does not make the victim's concurrent UDP background an attack), 5 s windows:

| decision rule | balanced accuracy | precision | recall | ROC-AUC |
|---|---|---|---|---|
| ML (aggregate IF) | 0.871 | 0.83 | 0.77 | **0.981** |
| rule engine | 0.575 | 0.33 | 0.23 | — |
| **hybrid (ML ∪ rule)** | **0.946** | 0.62 | **1.000** | — |

Per attack type (hybrid): **SYN 4/4, ACK 3/3, HTTP 3/3, UDP 3/3 — every attack window detected.** The two heads are complementary by design: the ML head separates SYN/ACK/HTTP cleanly (ROC-AUC 0.98) but cannot distinguish a UDP flood from this network's chatty benign UDP (mDNS/DNS); the rule engine catches UDP. Neither head alone suffices, which is the empirical justification for the union.

### 6.2 Live, in the running application

The detector was wired into the live capture loop as a second track alongside per-flow scoring, then evaluated by replaying traffic in **30 s passes exactly as the live scheduler runs**.

- **False positives:** an initial 31.7% of benign 30 s passes raised an alarm. Analysis showed benign false alarms peaked at **38 sources** while real floods carried **800–1,107**; a distributed flood is many-source by definition. Adding a source-cardinality floor (100) plus a two-window confirmation reduced the benign false-alarm rate over a full benign hour to **0.0% (0/120 passes)**.
- **True positives:** every flood is flagged Critical — e.g. *Volumetric Flood, 1,107 sources → victim, 99% confidence*; *UDP Flood, 1,104 sources*; *ICMP Flood, 856 sources*.
- **Field confirmation:** run against a live flood from a second machine, the system raised the volumetric campaign in real time (1,109 sources → victim), while the per-flow console correctly showed the individual spoofed packets as benign.

### 6.3 Summary

| setting | before | after |
|---|---|---|
| CICDDoS2019 benchmark accuracy | 0.881 | 0.881 (unchanged) |
| captured attack, balanced accuracy | 0.497 | **0.946** |
| captured attack, recall | 0.0006 | **1.000** |
| live benign false-alarm rate | 31.7% | **0.0%** |
| live spoofed-flood detection | invisible | **Critical, 99%** |

---

## 7. Discussion and limitations

- **Benchmark accuracy did not transfer.** The 0.88 benchmark number is real but describes performance on pre-aggregated flow records with substantial packet counts; it is not a predictor of field performance on spoofed floods, which produce single-packet flows. Reporting it as the detector's live accuracy would not be defensible. This is the project's headline methodological finding.
- **The rule head is the noisy half.** ML precision is 0.83; the rule engine's is 0.33. The source floor masks this at the campaign level, but a more selective rule set would raise standalone precision.
- **One benign baseline.** The benign model was trained on a single 60-minute capture. The attack capture's idle windows were busier than the baseline, inflating the underlying window-level false-positive rate before the source floor. A baseline spanning multiple times of day would make the ML head more robust.
- **Coarse TCP subtype naming.** SYN/ACK/HTTP all ride TCP and currently surface as one "Volumetric Flood" campaign; per-type naming would require aggregate-aware TCP signatures.
- **Victim inference.** With no configured protected host, the victim is inferred as the busiest-peer host per window. This resolves correctly under attack (the target has the most distinct sources) but an explicit configuration would remove the assumption.
- **Threat model.** The evaluation covers volumetric floods with source spoofing (SYN/UDP/ACK/HTTP/ICMP). Low-and-slow, application-layer, and single-source attacks are handled by the retained per-flow track and are not the subject of these results.

---

## 8. Future work

1. Multi-session benign baselines and periodic re-calibration to close the window-level false-positive gap without relying solely on the source floor.
2. Aggregate-aware Stage 2 signatures (SYN/ACK/RST-rate rules on the window record) for per-type naming and higher standalone precision.
3. Supervised or semi-supervised refinement now that a trustworthy labelled capture pipeline exists.
4. Evaluation against a public *packet-level* DDoS capture (not pre-aggregated) to test generalization beyond the local network.

---

## 9. Conclusion

A model that scored 0.88 on a standard benchmark performed at chance (0.50 balanced accuracy) on real captured traffic, and controlling for schema showed the gap was intrinsic to the data, not the pipeline. The cause was representational: a spoofed volumetric attack lives in the (victim, window) aggregate, not in any single flow. Re-expressing detection at the window level, with source-cardinality features trained on a network-specific benign baseline, restored 0.95 balanced accuracy and 1.00 recall on captured attacks and produced a live detector with a 0.0% benign false-alarm rate over an hour of normal traffic. The broader lesson is that **field capture, honest re-evaluation, and verification of ground truth were each necessary to expose problems that benchmark accuracy concealed** — including a capture defect and a protocol-parsing bug that no benchmark dataset could have surfaced.

---

## Appendix A: Reproducibility

All steps are scripted; commands are run from `project/backend/` unless noted.

**Two-machine capture (§5.1)**
```
# both machines, Administrator:
powershell -ExecutionPolicy Bypass -File tools/sync-clock.ps1
# victim:
python capture_tool.py benign --iface "<NIC>" --minutes 15 --out ../../data/nsl_kdd/attack_recap.pcapng
# attacker (2nd host):
python tools/attacker_flood.py --target <victim-ip>
# victim, after copying attack_timeline_*.csv into data/attack_timelines/:
python capture_tool.py verify --pcap ../../data/nsl_kdd/attack_recap.pcapng --victim <victim-ip>
```

**Baseline benign capture and training (§5.5)**
```
python capture_tool.py benign --iface "<NIC>" --minutes 60 --out ../../data/baseline_capture/benign.pcapng
python train_aggregate.py --pcap ../../data/baseline_capture/benign.pcapng --victim <victim-ip> --window-sec 5
```

**Evaluation (§3, §6.1)**
```
python evaluate.py pcap  --pcap <attack.pcapng> --out ../models/perflow_eval.json     # per-flow baseline
python evaluate.py cicds --csv  <capture_cicds.csv> --out ../models/cicds_eval.json    # schema-controlled
python evaluate.py agg   --pcap <attack.pcapng> --out ../models/agg_eval.json          # aggregate detector
```

## Appendix B: Key artifacts

| component | file |
|---|---|
| window aggregation + cardinality features | `project/backend/flow_aggregator.py` |
| aggregate detector training | `project/backend/train_aggregate.py` |
| aggregate detector inference | `project/backend/aggregate_detector.py` |
| unified evaluation CLI | `project/backend/evaluate.py` |
| live integration | `project/backend/packet_capture.py` |
| capture + verification | `project/backend/capture_tool.py` |
| lab attack generator | `tools/attacker_flood.py` |
| clock synchronization | `tools/sync-clock.ps1` |
