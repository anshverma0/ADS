"""
Window-level traffic aggregation - the detection unit for volumetric DDoS.

WHY THIS EXISTS
---------------
The per-flow pipeline (flow_generator -> feature_extractor) keys flows on the
5-tuple. A spoofed-source flood therefore decomposes into thousands of ONE-PACKET
flows: 3,301 attack packets from ~1,536 forged source IPs became ~1,536 flows of
1 packet each in the 2026-07-22 capture. Measured against ground truth, per-flow
detection scored 0.4969 balanced accuracy - chance - because a 1-packet flow is
statistically indistinguishable from (in fact smaller than) the benign training
median of 2 packets / 132 bytes / no flags.

DDoS is a many-flows phenomenon. The signal lives in how many distinct peers hit
one victim in one window, which no 5-tuple record can express. Aggregating by
(window, victim, protocol, dst_port) recovers it: on the same capture, benign
windows average 11.3 unique peers while SYN/ACK/UDP flood windows average
460-528. That 40-50x separation is cleaner than anything in the original
10-feature set.

TWO TRACKS, NOT A REPLACEMENT
-----------------------------
Aggregation is the right unit for volumetric floods and the WRONG unit for
session-shaped attacks, where the flow genuinely is the object of interest
(Slowloris, brute force, data exfiltration, C2 beaconing). Callers run both:
per-flow records through the existing path, aggregate records through this one.

TWO GROUPING SCOPES, BOTH EMITTED
---------------------------------
Port cannot simply be added to or dropped from the key - the two requirements
conflict, and measurement settled it:

  - Drop dst_port, group by (window, victim, protocol): source cardinality is
    preserved (460-528 unique peers per flood window vs 11.3 benign), but
    ddos_classifier's web rules never fire because they need
    `dst_port in WEB_PORTS`. 36 HTTP flood records fell through to
    "Unknown Anomaly" in the prototype that did this.

  - Keep dst_port, group by (window, victim, protocol, dst_port): the port
    survives, but an attack that randomizes DESTINATION ports shatters the
    grouping. Measured on the 2026-07-22 UDP flood: 4,108 packets became 3,029
    buckets of ~1 packet each, and mean unique_src_ips fell to 0.017 - the exact
    per-flow failure this module exists to fix, reintroduced.

So both scopes are emitted, tagged in the `scope` column:
    "victim_proto"      - cardinality-bearing; catches spoofed/port-spraying floods
    "victim_proto_port" - service-bearing; lets the Stage 2 port rules work
A window is attack if EITHER scope fires. Port-randomizing attacks additionally
show as high dst_port_entropy on the victim_proto record, which is the signature
the port-scoped view cannot express.

TRAIN/SERVE PARITY
------------------
train_from_wireshark.py and packet_capture.py must both build records with
aggregate_packets() so training and inference see identically-shaped objects.
That parity is the one thing the existing pipeline gets right; do not fork it.
"""
import math
from collections import defaultdict, Counter

import pandas as pd

# Aggregate feature columns produced by this module, in a stable order. The first
# ten are the original per-flow features (so the existing rule engine and any
# legacy model keep working); the rest are the cardinality/entropy terms that
# make a distributed flood visible at all.
LEGACY_FEATURES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean",
]
AGGREGATE_FEATURES = [
    # Peer cardinality is DIRECTION-AGNOSTIC on purpose. Counting inbound source
    # IPs alone misses the case where the capture point records the victim's
    # replies rather than the incoming flood (Npcap does exactly this when the
    # attacker injects raw frames): the 1,536 spoofed hosts then appear as
    # destinations of outbound RST-ACKs, and inbound-only counting saw 6.9 unique
    # sources for a flood vs 5.8 for benign - no separation at all.
    "unique_peers", "peer_entropy",
    "unique_src_ips", "src_ip_entropy", "unique_src_ports", "dst_port_entropy",
    "inbound_pkt_ratio", "rst_rate", "syn_to_ack_ratio",
]
FEATURE_COLUMNS = LEGACY_FEATURES + AGGREGATE_FEATURES


def _entropy(counter) -> float:
    """
    Normalized Shannon entropy of a distribution, in [0, 1].

    Mirrors ddos_classifier._entropy so a value means the same thing in Stage 1
    and Stage 2. 1.0 = perfectly uniform (a spoofed flood spraying unique
    sources), 0.0 = all mass on one key (a single peer talking normally).
    """
    total = sum(counter.values())
    if total <= 0 or len(counter) <= 1:
        return 0.0
    h = -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)
    return h / math.log2(len(counter))


def _packet_meta(pkt):
    """
    Extracts the fields aggregation needs from a scapy packet.
    Returns None for non-IP packets. Mirrors flow_generator's parsing so the two
    tracks agree on protocol and flag semantics.
    """
    if not pkt.haslayer("IP"):
        return None
    ip = pkt["IP"]

    if pkt.haslayer("TCP"):
        proto, l4 = "TCP", pkt["TCP"]
    elif pkt.haslayer("UDP"):
        proto, l4 = "UDP", pkt["UDP"]
    elif pkt.haslayer("ICMP"):
        proto, l4 = "ICMP", None
    else:
        proto, l4 = "Other", None

    sport = int(l4.sport) if l4 is not None else 0
    dport = int(l4.dport) if l4 is not None else 0

    syn = rst = fin = ack = 0
    if proto == "TCP":
        f = int(l4.flags)
        syn = 1 if f & 0x02 else 0
        rst = 1 if f & 0x04 else 0
        fin = 1 if f & 0x01 else 0
        ack = 1 if f & 0x10 else 0

    return {
        "src_ip": ip.src, "dst_ip": ip.dst, "src_port": sport, "dst_port": dport,
        "protocol": proto, "len": len(pkt), "time": float(pkt.time),
        "syn": syn, "rst": rst, "fin": fin, "ack": ack,
    }


def _new_bucket():
    return {
        "in_bytes": 0.0, "in_pkts": 0, "out_bytes": 0.0, "out_pkts": 0,
        "syn": 0, "rst": 0, "fin": 0, "ack": 0,
        "t_min": None, "t_max": None,
        "peers": Counter(),
        "src_ips": Counter(), "src_ports": Counter(), "dst_ports": Counter(),
    }


def _resolve_victims(metas, victim_ips=None):
    """
    Determines which host each packet is aggregated against.

    An explicit victim list is preferred (live deployments know the assets they
    protect). Without one, the victim is inferred as the endpoint receiving
    traffic from the most distinct peers in this batch - which is precisely the
    host under a distributed flood, and for benign traffic simply resolves to the
    busiest local host.
    """
    if victim_ips:
        return set(victim_ips)

    peers = defaultdict(set)
    for m in metas:
        peers[m["dst_ip"]].add(m["src_ip"])
    if not peers:
        return set()
    top = max(peers.items(), key=lambda kv: len(kv[1]))
    return {top[0]}


SCOPES = ("victim_proto", "victim_proto_port")


def _fill_buckets(metas, victims, window_sec, scope):
    """Accumulates packet stats into buckets under one grouping scope."""
    buckets = defaultdict(_new_bucket)

    for m in metas:
        inbound = m["dst_ip"] in victims
        outbound = m["src_ip"] in victims
        if not (inbound or outbound):
            continue
        victim = m["dst_ip"] if inbound else m["src_ip"]
        peer_port = m["dst_port"] if inbound else m["src_port"]

        # victim_proto deliberately omits the port so that a flood spraying
        # random destination ports still lands in ONE bucket, keeping its source
        # cardinality visible.
        if scope == "victim_proto":
            key = (int(m["time"] // window_sec), victim, m["protocol"], -1)
        else:
            key = (int(m["time"] // window_sec), victim, m["protocol"], peer_port)
        b = buckets[key]

        # The peer is whichever endpoint is not the victim, whichever way the
        # packet travelled.
        b["peers"][m["src_ip"] if inbound else m["dst_ip"]] += 1

        if inbound:
            b["in_bytes"] += m["len"]; b["in_pkts"] += 1
            b["src_ips"][m["src_ip"]] += 1
            b["src_ports"][m["src_port"]] += 1
            b["dst_ports"][m["dst_port"]] += 1
        else:
            b["out_bytes"] += m["len"]; b["out_pkts"] += 1

        b["syn"] += m["syn"]; b["rst"] += m["rst"]
        b["fin"] += m["fin"]; b["ack"] += m["ack"]
        b["t_min"] = m["time"] if b["t_min"] is None else min(b["t_min"], m["time"])
        b["t_max"] = m["time"] if b["t_max"] is None else max(b["t_max"], m["time"])

    return buckets


def _buckets_to_rows(buckets, window_sec, scope):
    """Turns accumulated buckets into feature rows."""
    rows = []
    for (win_id, victim, proto, port), b in buckets.items():
        pkts = b["in_pkts"] + b["out_pkts"]
        byts = b["in_bytes"] + b["out_bytes"]

        # Rate denominator is the WINDOW, not the observed packet span. The
        # per-flow path divides by an observed span clamped to 1e-4 s, which
        # turns every 1-packet flow into a fake 10,000 pkts/s - the artifact that
        # MIN_FLOOD_PKTS exists to suppress downstream. A fixed window makes the
        # rate a real measurement: 1 packet in a 5 s window is 0.2 pkts/s.
        duration = float(window_sec)

        rows.append({
            "scope": scope,
            "victim_ip": victim, "protocol": proto,
            # -1 marks "all ports" on the cardinality-bearing scope; Stage 2 port
            # rules must ignore those records and use the port-scoped ones.
            "dst_port": int(port),
            "window_id": int(win_id),
            "t_start": b["t_min"], "t_end": b["t_max"],

            # ---- legacy 10, computed over the aggregate ----
            # fwd = toward the victim, matching the attack's direction of travel.
            "flow_byts_s": byts / duration,
            "flow_pkts_s": pkts / duration,
            "fwd_bytes": b["in_bytes"],
            "bwd_bytes": b["out_bytes"],
            "total_pkts": pkts,
            "syn_flag": b["syn"],
            "rst_flag": b["rst"],
            "fin_flag": b["fin"],
            "flow_duration_s": duration,
            "pkt_len_mean": byts / pkts if pkts else 0.0,

            # ---- cardinality / shape: where the DDoS signal actually lives ----
            "unique_peers": len(b["peers"]),
            "peer_entropy": _entropy(b["peers"]),
            "unique_src_ips": len(b["src_ips"]),
            "src_ip_entropy": _entropy(b["src_ips"]),
            "unique_src_ports": len(b["src_ports"]),
            "dst_port_entropy": _entropy(b["dst_ports"]),
            "inbound_pkt_ratio": b["in_pkts"] / pkts if pkts else 0.0,
            "rst_rate": b["rst"] / pkts if pkts else 0.0,
            # Half-open floods send SYNs that are never ACKed, so this runs high;
            # +1 keeps it finite when no ACK is present at all.
            "syn_to_ack_ratio": b["syn"] / (b["ack"] + 1.0),

            # Carried for Stage 2 and reporting, not model inputs.
            "ack_flag": b["ack"],
            "fwd_packets": b["in_pkts"],
            "bwd_packets": b["out_pkts"],
        })
    return rows


def aggregate_packets(packets, window_sec=5, victim_ips=None, scopes=SCOPES):
    """
    Groups packets into aggregate records under both grouping scopes.

    Args:
        packets:    iterable of scapy packets
        window_sec: aggregation window in seconds; MUST match between training
                    and inference or the rate/cardinality features shift meaning
        victim_ips: optional explicit list of protected hosts; inferred if omitted
        scopes:     which grouping scopes to emit (see module docstring)

    Returns:
        DataFrame with FEATURE_COLUMNS plus identifiers (scope, victim_ip,
        protocol, dst_port, window_id) and timing (t_start, t_end) for labelling.
        dst_port is -1 on "victim_proto" records, which cover all ports.
    """
    metas = [m for m in (_packet_meta(p) for p in packets) if m is not None]
    if not metas:
        return pd.DataFrame(columns=["scope", "victim_ip", "protocol", "dst_port",
                                     "window_id", "t_start", "t_end"] + FEATURE_COLUMNS)

    victims = _resolve_victims(metas, victim_ips)

    rows = []
    for scope in scopes:
        buckets = _fill_buckets(metas, victims, window_sec, scope)
        rows.extend(_buckets_to_rows(buckets, window_sec, scope))

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values(["scope", "window_id", "victim_ip"]).reset_index(drop=True)


def aggregate_windows(packets, window_sec=5, victim_ips=None):
    """
    Convenience wrapper: same as aggregate_packets, but tolerates a dict of
    {window_id: [packets]} as produced by the streaming pcap readers.
    """
    if isinstance(packets, dict):
        flat = []
        for pkts in packets.values():
            flat.extend(pkts)
        packets = flat
    return aggregate_packets(packets, window_sec=window_sec, victim_ips=victim_ips)
