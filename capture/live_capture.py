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


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6

    start_time: float = 0.0
    last_time: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    fwd_pkt_lengths: list = field(default_factory=list)
    bwd_pkt_lengths: list = field(default_factory=list)

    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    flow_iats: list = field(default_factory=list)

    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0
    last_pkt_time: float = 0.0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    ttl_values: list = field(default_factory=list)

    tcp_win_sizes: list = field(default_factory=list)

    _seen_seqs: set = field(default_factory=set)
    retransmit_count: int = 0

    packet_count: int = 0

    def add_packet(self, pkt_len: int, is_forward: bool, timestamp: float,
                   tcp_flags: int = 0, ttl: int = 64, tcp_win: int = 0,
                   seq: int = 0):
        if self.packet_count == 0:
            self.start_time = timestamp
            self.last_pkt_time = timestamp
            self.last_fwd_time = timestamp
            self.last_bwd_time = timestamp

        self.last_time = timestamp
        self.packet_count += 1

        if self.packet_count > 1:
            iat = (timestamp - self.last_pkt_time) * 1e6
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

        if tcp_flags:
            if tcp_flags & 0x02:
                self.syn_count += 1
            if tcp_flags & 0x10:
                self.ack_count += 1
            if tcp_flags & 0x01:
                self.fin_count += 1
            if tcp_flags & 0x04:
                self.rst_count += 1
            if tcp_flags & 0x08:
                self.psh_count += 1
            if tcp_flags & 0x20:
                self.urg_count += 1

        self.ttl_values.append(ttl)

        if tcp_win > 0:
            self.tcp_win_sizes.append(tcp_win)

        if seq > 0:
            if seq in self._seen_seqs:
                self.retransmit_count += 1
            else:
                self._seen_seqs.add(seq)

    def to_features(self) -> dict:
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
    def __init__(self, api_url: str, flow_timeout: float = 30.0,
                 min_packets: int = 4, export_interval: int = 10):
        self.api_url = api_url
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets
        self.export_interval = export_interval

        self.active_flows: dict[str, FlowState] = {}
        self.exported_count = 0
        self.total_packets = 0
        self.alerts_triggered = 0

    def _flow_key(self, src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, proto: int) -> tuple[str, bool]:
        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            return key, True
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
            return key, False

    def process_packet(self, pkt):
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

        now = time.time()
        last_check = getattr(self, "_last_export_check", 0.0)
        if (self.total_packets % 25 == 0) or (now - last_check >= 3.0):
            self._last_export_check = now
            self._export_expired_flows(now)

    def _export_expired_flows(self, current_time: float):
        expired_keys = []
        stale_keys = []

        for key, flow in self.active_flows.items():
            idle_time = current_time - flow.last_time
            is_terminated = (flow.fin_count > 0 or flow.rst_count > 0) and idle_time >= 1.0

            if (idle_time > self.flow_timeout or is_terminated) and flow.packet_count >= self.min_packets:
                expired_keys.append(key)
            elif idle_time > (self.flow_timeout * 2):
                stale_keys.append(key)

        for key in expired_keys:
            flow = self.active_flows.pop(key)
            self._send_to_api(flow)

        for key in stale_keys:
            self.active_flows.pop(key, None)

    def _send_to_api(self, flow: FlowState):
        features = flow.to_features()
        features["src_ip"] = flow.src_ip
        features["dst_ip"] = flow.dst_ip
        features["timestamp"] = datetime.now(timezone.utc).isoformat()
        features["source"] = "live_capture"  # §7 provenance tag

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


def get_network_interfaces():
    interfaces = []
    active_ip = None

    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    try:
        for k, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(k))
            desc = getattr(iface, "description", "")
            ip = getattr(iface, "ip", "")
            ip_str = str(ip) if ip else ""

            if ip_str.startswith("127.") or "loopback" in name.lower() or "loopback" in desc.lower():
                continue

            is_active = (ip_str == active_ip) if active_ip else (bool(ip_str) and not ip_str.startswith("169.254."))

            interfaces.append({
                "name": name,
                "description": desc,
                "ip": ip_str,
                "is_active": is_active,
                "scapy_key": k,
                "iface": iface,
            })
    except Exception:
        pass

    if not interfaces and active_ip:
        interfaces.append({
            "name": "Default Interface",
            "description": f"Active network adapter ({active_ip})",
            "ip": active_ip,
            "is_active": True,
            "scapy_key": active_ip,
            "iface": active_ip,
        })

    return interfaces, active_ip


def list_interfaces():
    interfaces, active_ip = get_network_interfaces()
    print("\nAvailable Network Interfaces:")
    print("=" * 80)
    print(f"{'Name / Alias':<20} | {'IPv4 Address':<16} | {'Status':<10} | {'Description'}")
    print("-" * 80)

    for iface in interfaces:
        status = "ACTIVE" if iface["is_active"] else ("CONNECTED" if iface["ip"] and not iface["ip"].startswith("169.254.") else "DISCONNECTED")
        print(f"{iface['name']:<20} | {iface['ip']:<16} | {status:<10} | {iface['description']}")

    print("=" * 80)
    print("Run with --interface <name> (or --interface auto for active adapter).")
    print("Run as Administrator for live packet capture on Windows.\n")


def resolve_interface(interface_arg: Optional[str] = None) -> dict:
    interfaces, active_ip = get_network_interfaces()

    active_iface = None
    for iface in interfaces:
        if iface["is_active"]:
            active_iface = iface
            break

    if not active_iface and interfaces:
        for iface in interfaces:
            if iface["ip"] and not iface["ip"].startswith("169.254."):
                active_iface = iface
                break

    if not interface_arg or interface_arg.lower() in ("auto", "default"):
        if active_iface:
            logger.info("Auto-selected active interface: %s (%s - %s)",
                        active_iface["name"], active_iface["ip"], active_iface["description"])
            return active_iface
        elif interfaces:
            return interfaces[0]
        else:
            return {"name": "Default", "description": "Default", "ip": active_ip or "0.0.0.0", "scapy_key": "auto"}

    target = interface_arg.strip().lower()

    matched = None
    for iface in interfaces:
        if (target == iface["name"].lower() or
            target == iface["ip"].lower() or
            target in iface["name"].lower() or
            target in iface["description"].lower() or
            target == str(iface.get("scapy_key", "")).lower()):
            matched = iface
            break

    if matched:
        if not matched["ip"] or matched["ip"].startswith("169.254."):
            if active_iface:
                logger.warning(
                    "Requested interface '%s' has no active connection (IP: %s). "
                    "Automatically switching to active connected interface: '%s' (%s)",
                    interface_arg, matched.get("ip", "none"), active_iface["name"], active_iface["ip"]
                )
                return active_iface
        return matched

    if active_iface:
        logger.warning(
            "Interface '%s' not recognized. Falling back to active adapter: '%s' (%s)",
            interface_arg, active_iface["name"], active_iface["ip"]
        )
        return active_iface

    return {"name": interface_arg, "description": interface_arg, "ip": active_ip or "0.0.0.0", "scapy_key": interface_arg}


def _run_traffic_simulator(api_url: str):
    import subprocess
    from pathlib import Path

    sim_script = Path(__file__).resolve().parent.parent / "demo" / "traffic_simulator.py"
    if sim_script.exists():
        logger.info("Starting Traffic Simulator: %s", sim_script)
        cmd = [sys.executable, str(sim_script), "--api", api_url, "--sessions", "4", "--speed", "1.0"]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
    else:
        logger.error("Traffic simulator script not found at %s", sim_script)


def _handle_permission_denied(api_url: str, fallback_sim: bool = False):
    print("\n" + "=" * 76)
    print("  [!] LIVE PACKET CAPTURE REQUIRES ADMINISTRATOR PRIVILEGES")
    print("=" * 76)
    print("  Capturing live network packets on Windows requires Administrator rights.")
    print()
    print("  How to fix:")
    print("  1. Launch start_all.ps1 (it automatically requests UAC elevation), OR")
    print("  2. Right-click PowerShell -> 'Run as Administrator', then run:")
    print(f"     python capture\\live_capture.py --interface auto --api {api_url}")
    print()
    print("  Note on Npcap:")
    print("  - Installing Npcap (https://npcap.com/#download) with 'WinPcap API-compatible")
    print("    Mode' enabled provides full Layer-2 packet sniffing.")
    print("  - Without Npcap, Windows native Raw Socket capture is used (needs Admin).")
    print()
    print("  Alternatively, you can run the Traffic Simulator to demo attacks without Admin:")
    print(f"     python demo/traffic_simulator.py --api {api_url}")
    print("=" * 76 + "\n")

    if fallback_sim:
        logger.info("Launching Traffic Simulator as fallback...")
        _run_traffic_simulator(api_url)
    else:
        try:
            if sys.stdin.isatty():
                ans = input("Would you like to launch the Traffic Simulator now? [Y/n]: ").strip().lower()
                if ans in ("", "y", "yes"):
                    _run_traffic_simulator(api_url)
                    return
        except Exception:
            pass
        sys.exit(1)


def _capture_with_raw_socket(bind_ip: str, extractor: FlowExtractor, count: int,
                             api_url: str, fallback_sim: bool = False):
    import socket

    if not bind_ip or bind_ip.startswith(("127.", "169.254.")):
        logger.error("Cannot bind raw socket: Invalid or unassigned IP address '%s'.", bind_ip)
        _handle_permission_denied(api_url, fallback_sim)
        return

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((bind_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        logger.error("Permission denied: Raw socket capture on Windows requires Administrator privileges.")
        _handle_permission_denied(api_url, fallback_sim)
        return
    except OSError as e:
        if getattr(e, "winerror", None) == 10013:
            logger.error("Permission denied (WinError 10013): Run PowerShell as Administrator.")
        else:
            logger.error("Failed to bind raw socket on %s: %s", bind_ip, e)
        _handle_permission_denied(api_url, fallback_sim)
        return

    logger.info("=" * 65)
    logger.info("  LIVE RAW SOCKET CAPTURE ACTIVE")
    logger.info("  Listening on IP address: %s", bind_ip)
    logger.info("  Capturing live IPv4 packets (SIO_RCVALL)...")
    logger.info("  Press Ctrl+C to stop.")
    logger.info("=" * 65)

    pkt_count = 0
    last_heartbeat = time.time()

    try:
        while True:
            raw_data, _ = s.recvfrom(65535)
            now = time.time()
            try:
                pkt = IP(raw_data)
                pkt.time = now
                extractor.process_packet(pkt)
                pkt_count += 1
                if count > 0 and pkt_count >= count:
                    break
            except Exception:
                pass

            if now - last_heartbeat >= 10.0:
                last_heartbeat = now
                logger.info(
                    "Live capture active... (Packets: %d | Active flows: %d | Exported: %d)",
                    extractor.total_packets,
                    len(extractor.active_flows),
                    extractor.exported_count,
                )
    except KeyboardInterrupt:
        logger.info("\nCapture stopped by user.")
    finally:
        if s:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        extractor.export_all_remaining()
        extractor.print_stats()


def capture_live(interface_arg: Optional[str], api_url: str, count: int = 0,
                 timeout_sec: float = 10.0, fallback_sim: bool = False):
    resolved = resolve_interface(interface_arg)
    iface_name = resolved["name"]
    iface_ip = resolved.get("ip", "")
    scapy_iface = resolved.get("scapy_key", iface_name)

    logger.info("Target network interface: %s (%s)", iface_name, iface_ip or "No IPv4")
    logger.info("Sending flows to API:      %s", api_url)

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec, min_packets=2)

    has_npcap = False
    try:
        if getattr(conf, "use_pcap", False):
            has_npcap = True
    except Exception:
        pass

    if has_npcap:
        logger.info("Npcap detected. Using Layer-2 capture on %s", scapy_iface)
        logger.info("Press Ctrl+C to stop.\n")
        try:
            sniff(
                iface=scapy_iface,
                prn=extractor.process_packet,
                count=count if count > 0 else 0,
                store=False,
            )
        except PermissionError:
            logger.error("Permission denied. Run as Administrator for live capture.")
            _handle_permission_denied(api_url, fallback_sim)
        except RuntimeError as e:
            logger.warning("Scapy sniff failed (%s). Falling back to Windows native raw socket...", e)
            _capture_with_raw_socket(iface_ip, extractor, count, api_url, fallback_sim)
        except KeyboardInterrupt:
            pass
        finally:
            extractor.export_all_remaining()
            extractor.print_stats()
    else:
        if sys.platform == "win32":
            logger.info("Npcap not detected. Using Windows native Raw Socket capture...")
            _capture_with_raw_socket(iface_ip, extractor, count, api_url, fallback_sim)
        else:
            logger.info("Starting live capture on %s...", scapy_iface)
            try:
                sniff(
                    iface=scapy_iface,
                    prn=extractor.process_packet,
                    count=count if count > 0 else 0,
                    store=False,
                )
            except Exception as e:
                logger.error("Live capture error: %s", e)
                _handle_permission_denied(api_url, fallback_sim)
            finally:
                extractor.export_all_remaining()
                extractor.print_stats()


def process_pcap(pcap_path: str, api_url: str, speed: float = 0.0,
                 timeout_sec: float = 10.0):
    logger.info("Processing pcap: %s", pcap_path)
    logger.info("Sending flows to: %s", api_url)

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec, min_packets=2)

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
            "Network packet capture — flow extraction and model prediction pipeline."
        )
    )
    parser.add_argument("--interface", "-i", default="auto",
                        help="Network interface for live capture (default: 'auto' for active adapter)")
    parser.add_argument("--pcap", "-p", help="Path to pcap/pcapng file to process")
    parser.add_argument("--api", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--speed", type=float, default=0.0,
                        help="Delay between packets in pcap replay (0=full speed)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Flow inactivity timeout in seconds (default: 10.0)")
    parser.add_argument("--count", type=int, default=0,
                        help="Max packets to capture (0=unlimited)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--fallback-simulator", action="store_true",
                        help="Automatically fall back to Traffic Simulator if packet capture cannot start")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

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
    else:
        capture_live(args.interface, args.api, count=args.count, timeout_sec=args.timeout,
                     fallback_sim=args.fallback_simulator)


if __name__ == "__main__":
    main()
