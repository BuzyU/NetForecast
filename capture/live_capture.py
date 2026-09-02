"""
Real Packet Capture → Flow Feature Extraction → Model Prediction Pipeline

This captures REAL network packets (live or from pcap), groups them into
bidirectional flows, computes the 22 CIC-IDS features your model expects,
and feeds them to the backend API for real-time prediction.

This is NOT a simulator. It processes actual network traffic.

Usage:
  # Live capture on your network interface (requires admin/root)
  python live_capture.py --interface "Ethernet" --api http://localhost:8000

  # Process a pcap file (e.g., from CIC-IDS2017 dataset)
  python live_capture.py --pcap path/to/capture.pcap --api http://localhost:8000

  # List available interfaces
  python live_capture.py --list-interfaces

Requirements:
  pip install scapy requests numpy
  On Windows: also install Npcap (https://npcap.com/#download)
  Run as Administrator for live capture.
"""
import argparse
import sys
import time
import logging
import json
from datetime import datetime, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import requests

# Prevent Windows cp1252 console encoding crashes
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

try:
    from scapy.all import (
        sniff, rdpcap, IP, TCP, UDP, Raw,
        get_if_list, conf,
    )
except ImportError:
    print("ERROR: scapy not installed. Run: pip install scapy")
    print("On Windows, also install Npcap: https://npcap.com/#download")
    sys.exit(1)


# ── Flow state tracker ───────────────────────────────────────────────

@dataclass
class FlowState:
    """Tracks packet-level state for a single bidirectional flow."""
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6  # TCP default

    start_time: float = 0.0
    last_time: float = 0.0

    # Forward = src→dst, Backward = dst→src
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    fwd_pkt_lengths: list = field(default_factory=list)
    bwd_pkt_lengths: list = field(default_factory=list)

    # Inter-arrival times
    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    flow_iats: list = field(default_factory=list)

    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0
    last_pkt_time: float = 0.0

    # TCP flags
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # TTL values for variance calculation
    ttl_values: list = field(default_factory=list)

    # TCP window sizes
    tcp_win_sizes: list = field(default_factory=list)

    # Retransmissions (simplified: track seq numbers)
    _seen_seqs: set = field(default_factory=set)
    retransmit_count: int = 0

    packet_count: int = 0

    def add_packet(self, pkt_len: int, is_forward: bool, timestamp: float,
                   tcp_flags: int = 0, ttl: int = 64, tcp_win: int = 0,
                   seq: int = 0):
        """Process a single packet belonging to this flow."""
        if self.packet_count == 0:
            self.start_time = timestamp
            self.last_pkt_time = timestamp
            self.last_fwd_time = timestamp
            self.last_bwd_time = timestamp

        self.last_time = timestamp
        self.packet_count += 1

        # Inter-arrival time (flow-level)
        if self.packet_count > 1:
            iat = (timestamp - self.last_pkt_time) * 1e6  # microseconds
            self.flow_iats.append(iat)
        self.last_pkt_time = timestamp

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lengths.append(pkt_len)
            if self.fwd_packets > 1:
                iat = (timestamp - self.last_fwd_time) * 1e6
                self.fwd_iats.append(iat)
            self.last_fwd_time = timestamp
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lengths.append(pkt_len)
            if self.bwd_packets > 1:
                iat = (timestamp - self.last_bwd_time) * 1e6
                self.bwd_iats.append(iat)
            self.last_bwd_time = timestamp

        # TCP flags
        if tcp_flags:
            if tcp_flags & 0x02:  # SYN
                self.syn_count += 1
            if tcp_flags & 0x10:  # ACK
                self.ack_count += 1
            if tcp_flags & 0x01:  # FIN
                self.fin_count += 1
            if tcp_flags & 0x04:  # RST
                self.rst_count += 1
            if tcp_flags & 0x08:  # PSH
                self.psh_count += 1
            if tcp_flags & 0x20:  # URG
                self.urg_count += 1

        # TTL
        self.ttl_values.append(ttl)

        # TCP window
        if tcp_win > 0:
            self.tcp_win_sizes.append(tcp_win)

        # Retransmission detection (simplified)
        if seq > 0:
            if seq in self._seen_seqs:
                self.retransmit_count += 1
            else:
                self._seen_seqs.add(seq)

    def to_features(self) -> dict:
        """
        Compute the 22 CIC-IDS features from accumulated packet data.
        These are the REAL features, derived from actual packets.
        """
        duration_us = (self.last_time - self.start_time) * 1e6 if self.last_time > self.start_time else 1.0
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_packets + self.bwd_packets

        return {
            "flow_duration": duration_us,
            "tot_fwd_pkts": float(self.fwd_packets),
            "tot_bwd_pkts": float(self.bwd_packets),
            "fwd_pkt_len_mean": float(np.mean(self.fwd_pkt_lengths)) if self.fwd_pkt_lengths else 0.0,
            "bwd_pkt_len_mean": float(np.mean(self.bwd_pkt_lengths)) if self.bwd_pkt_lengths else 0.0,
            "flow_bytes_s": total_bytes / (duration_us / 1e6) if duration_us > 0 else 0.0,
            "flow_pkts_s": total_pkts / (duration_us / 1e6) if duration_us > 0 else 0.0,
            "flow_iat_mean": float(np.mean(self.flow_iats)) if self.flow_iats else 0.0,
            "flow_iat_std": float(np.std(self.flow_iats)) if len(self.flow_iats) > 1 else 0.0,
            "fwd_iat_mean": float(np.mean(self.fwd_iats)) if self.fwd_iats else 0.0,
            "bwd_iat_mean": float(np.mean(self.bwd_iats)) if self.bwd_iats else 0.0,
            "syn_flag_cnt": float(self.syn_count),
            "ack_flag_cnt": float(self.ack_count),
            "fin_flag_cnt": float(self.fin_count),
            "rst_flag_cnt": float(self.rst_count),
            "psh_flag_cnt": float(self.psh_count),
            "urg_flag_cnt": float(self.urg_count),
            "down_up_ratio": self.bwd_bytes / max(self.fwd_bytes, 1),
            "pkt_size_avg": total_bytes / max(total_pkts, 1),
            "ttl_variance": float(np.var(self.ttl_values)) if len(self.ttl_values) > 1 else 0.0,
            "tcp_win_size": float(np.mean(self.tcp_win_sizes)) if self.tcp_win_sizes else 0.0,
            "retransmit_cnt": float(self.retransmit_count),
        }


class FlowExtractor:
    """
    Groups packets into bidirectional flows and extracts CIC-IDS features.
    A flow is defined by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
    Flows are exported when they reach a timeout or packet threshold.
    """

    def __init__(self, api_url: str, flow_timeout: float = 30.0,
                 min_packets: int = 4, export_interval: int = 10):
        self.api_url = api_url
        self.flow_timeout = flow_timeout  # seconds of inactivity before export
        self.min_packets = min_packets    # minimum packets to consider a valid flow
        self.export_interval = export_interval  # export every N new flows

        self.active_flows: dict[str, FlowState] = {}
        self.exported_count = 0
        self.total_packets = 0
        self.alerts_triggered = 0

    def _flow_key(self, src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, proto: int) -> tuple[str, bool]:
        """
        Create a canonical flow key (sorted IPs so both directions match).
        Returns (key, is_forward).
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            return key, True
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
            return key, False

    def process_packet(self, pkt):
        """Process a single packet from live capture or pcap."""
        self.total_packets += 1

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        ttl = ip.ttl
        proto = ip.proto

        src_port = 0
        dst_port = 0
        tcp_flags = 0
        tcp_win = 0
        seq = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = int(tcp.flags)
            tcp_win = tcp.window
            seq = tcp.seq
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        pkt_len = len(pkt)
        timestamp = float(pkt.time)

        flow_key, is_forward = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        # Create or update flow
        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = FlowState(
                src_ip=src_ip if is_forward else dst_ip,
                dst_ip=dst_ip if is_forward else src_ip,
                src_port=src_port if is_forward else dst_port,
                dst_port=dst_port if is_forward else src_port,
                protocol=proto,
            )

        self.active_flows[flow_key].add_packet(
            pkt_len=pkt_len,
            is_forward=is_forward,
            timestamp=timestamp,
            tcp_flags=tcp_flags,
            ttl=ttl,
            tcp_win=tcp_win,
            seq=seq,
        )

        # Periodically check for expired flows
        if self.total_packets % 100 == 0:
            self._export_expired_flows(timestamp)

    def _export_expired_flows(self, current_time: float):
        """Export flows that have been idle beyond the timeout."""
        expired_keys = []
        for key, flow in self.active_flows.items():
            idle_time = current_time - flow.last_time
            if idle_time > self.flow_timeout and flow.packet_count >= self.min_packets:
                expired_keys.append(key)

        for key in expired_keys:
            flow = self.active_flows.pop(key)
            self._send_to_api(flow)

    def _send_to_api(self, flow: FlowState):
        """Send extracted flow features to the backend API."""
        features = flow.to_features()
        features["src_ip"] = flow.src_ip
        features["dst_ip"] = flow.dst_ip
        features["timestamp"] = datetime.now(timezone.utc).isoformat()

        try:
            resp = requests.post(
                f"{self.api_url}/ingest",
                json=features,
                timeout=10,
            )
            self.exported_count += 1

            if resp.status_code == 200:
                result = resp.json()
                pred = result.get("prediction")
                alert = result.get("alert")

                status = (
                    f"Flow #{self.exported_count:>5} | "
                    f"{flow.src_ip:>15}:{flow.src_port:<5} → "
                    f"{flow.dst_ip:>15}:{flow.dst_port:<5} | "
                    f"{flow.packet_count:>4} pkts | "
                )

                if pred:
                    prob = pred["infiltration_probability"]
                    stage = pred["predicted_stage"]
                    status += f"P={prob:.3f} Stage={stage}"
                    if alert:
                        self.alerts_triggered += 1
                        status += f" | 🚨 {alert['severity'].upper()}: {alert['recommended_action'][:60]}"
                else:
                    buf = result.get("buffer_size", "?")
                    status += f"Buffering ({buf}/6)"

                logger.info(status)
            else:
                logger.warning("API returned %d: %s", resp.status_code, resp.text[:100])

        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to API at %s", self.api_url)
        except Exception as e:
            logger.error("Error sending flow: %s", e)

    def export_all_remaining(self):
        """Export all remaining active flows (call at end of capture)."""
        logger.info("Exporting %d remaining active flows...", len(self.active_flows))
        for key in list(self.active_flows.keys()):
            flow = self.active_flows.pop(key)
            if flow.packet_count >= self.min_packets:
                self._send_to_api(flow)

    def print_stats(self):
        print(f"\n{'='*60}")
        print(f"  Capture Statistics")
        print(f"  Total packets processed: {self.total_packets}")
        print(f"  Flows exported:          {self.exported_count}")
        print(f"  Alerts triggered:        {self.alerts_triggered}")
        print(f"  Active flows remaining:  {len(self.active_flows)}")
        print(f"{'='*60}\n")


def list_interfaces():
    """List available network interfaces."""
    print("\nAvailable network interfaces:")
    print("-" * 40)
    for iface in get_if_list():
        print(f"  {iface}")
    print()
    print("Use --interface <name> to capture on a specific interface.")
    print("On Windows, you may need the full name or the NPF device path.")
    print("Run as Administrator for live capture.\n")


def capture_live(interface: str, api_url: str, count: int = 0,
                 timeout_sec: float = 30.0):
    """Live packet capture from a network interface."""
    logger.info("Starting live capture on interface: %s", interface)
    logger.info("Sending flows to: %s", api_url)
    logger.info("Press Ctrl+C to stop.\n")

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec)

    try:
        sniff(
            iface=interface,
            prn=extractor.process_packet,
            count=count if count > 0 else 0,
            store=False,  # Don't store packets in memory
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        logger.error("Permission denied. Run as Administrator/root for live capture.")
        sys.exit(1)
    finally:
        extractor.export_all_remaining()
        extractor.print_stats()


def process_pcap(pcap_path: str, api_url: str, speed: float = 0.0,
                 timeout_sec: float = 30.0):
    """Process a pcap/pcapng file and extract flows."""
    logger.info("Processing pcap: %s", pcap_path)
    logger.info("Sending flows to: %s", api_url)

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec)

    try:
        packets = rdpcap(pcap_path)
        logger.info("Loaded %d packets from pcap", len(packets))

        for i, pkt in enumerate(packets):
            extractor.process_packet(pkt)

            if speed > 0:
                time.sleep(speed)

            if (i + 1) % 1000 == 0:
                logger.info("Processed %d/%d packets...", i + 1, len(packets))

    except FileNotFoundError:
        logger.error("Pcap file not found: %s", pcap_path)
        sys.exit(1)
    except Exception as e:
        logger.error("Error processing pcap: %s", e)
        raise
    finally:
        extractor.export_all_remaining()
        extractor.print_stats()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Real packet capture → flow extraction → model prediction pipeline. "
            "Captures actual network traffic, computes CIC-IDS features, and "
            "sends them to the backend for real-time attack forecasting."
        )
    )
    parser.add_argument("--interface", "-i", help="Network interface for live capture")
    parser.add_argument("--pcap", "-p", help="Path to pcap/pcapng file to process")
    parser.add_argument("--api", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--speed", type=float, default=0.0,
                        help="Delay between packets in pcap replay (0=full speed)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Flow inactivity timeout in seconds")
    parser.add_argument("--count", type=int, default=0,
                        help="Max packets to capture (0=unlimited)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    # Verify backend
    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        health = resp.json()
        if not health.get("model_loaded"):
            logger.error("Backend model not loaded! Health: %s", json.dumps(health))
            sys.exit(1)
        logger.info("Backend healthy: model=%s, device=%s",
                     "loaded" if health["model_loaded"] else "MISSING",
                     health.get("device", "unknown"))
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to backend at %s", args.api)
        logger.error("Start backend first: cd backend && uvicorn app.main:app --reload")
        sys.exit(1)

    if args.pcap:
        process_pcap(args.pcap, args.api, speed=args.speed, timeout_sec=args.timeout)
    elif args.interface:
        capture_live(args.interface, args.api, count=args.count, timeout_sec=args.timeout)
    else:
        print("ERROR: Specify either --interface for live capture or --pcap for file processing")
        print("       Use --list-interfaces to see available interfaces")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
