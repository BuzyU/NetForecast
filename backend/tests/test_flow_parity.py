"""
Test flow extraction parity between capture/live_capture.py and backend/app/routes/pcap.py.
Verifies that both modules produce bit-for-bit identical 22-feature dictionaries
when processing identical packet sequences.
"""
import os
import sys

# Ensure project root and backend are on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import FLOW_FEATURES
from app.flow_state import FlowState as BackendFlowState
from capture.flow_state import FlowState as LiveFlowState


def test_flow_state_class_identity():
    """Verify backend and capture import the exact same FlowState class definition."""
    assert LiveFlowState is BackendFlowState


def test_identical_packets_produce_byte_identical_features():
    """
    Simulate a multi-packet bidirectional TCP handshake and data exchange.
    Feed identical parameters to two separate instances and verify identical feature output.
    """
    flow_a = LiveFlowState(src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=54321, dst_port=80, protocol=6)
    flow_b = BackendFlowState(src_ip="192.168.1.10", dst_ip="10.0.0.5", src_port=54321, dst_port=80, protocol=6)

    # Packet sequence:
    # 1. SYN (fwd, 64 bytes)
    # 2. SYN-ACK (bwd, 64 bytes)
    # 3. ACK (fwd, 54 bytes)
    # 4. Data (fwd, 512 bytes, PSH-ACK)
    # 5. ACK (bwd, 54 bytes)
    # 6. Data (bwd, 1024 bytes)
    packets = [
        {"pkt_len": 64, "is_forward": True, "timestamp": 1000.0, "tcp_flags": 0x02, "ttl": 64, "tcp_win": 65535, "seq": 100},
        {"pkt_len": 64, "is_forward": False, "timestamp": 1000.005, "tcp_flags": 0x12, "ttl": 128, "tcp_win": 32768, "seq": 200},
        {"pkt_len": 54, "is_forward": True, "timestamp": 1000.010, "tcp_flags": 0x10, "ttl": 64, "tcp_win": 65535, "seq": 101},
        {"pkt_len": 512, "is_forward": True, "timestamp": 1000.020, "tcp_flags": 0x18, "ttl": 64, "tcp_win": 65535, "seq": 102},
        {"pkt_len": 54, "is_forward": False, "timestamp": 1000.025, "tcp_flags": 0x10, "ttl": 128, "tcp_win": 32768, "seq": 201},
        {"pkt_len": 1024, "is_forward": False, "timestamp": 1000.050, "tcp_flags": 0x18, "ttl": 128, "tcp_win": 32768, "seq": 202},
    ]

    for p in packets:
        flow_a.add_packet(**p)
        flow_b.add_packet(**p)

    feats_a = flow_a.to_features()
    feats_b = flow_b.to_features()

    assert set(feats_a.keys()) == set(FLOW_FEATURES), "Missing features in feats_a"
    assert set(feats_b.keys()) == set(FLOW_FEATURES), "Missing features in feats_b"

    for feat in FLOW_FEATURES:
        val_a = feats_a[feat]
        val_b = feats_b[feat]
        assert isinstance(val_a, float)
        assert isinstance(val_b, float)
        assert val_a == val_b, f"Discrepancy on feature {feat}: {val_a} != {val_b}"


def test_scapy_packet_pipeline_parity():
    """
    Construct real Scapy IP/TCP packets and process them through:
    1. LivePacketCapture.process_packet
    2. pcap.py packet parsing loop
    Verify both produce identical flows with bit-for-bit identical 22-feature dictionaries.
    """
    from scapy.layers.inet import IP, TCP

    from app.routes.pcap import PcapFlowState
    from capture.live_capture import FlowExtractor

    pcap_flows: dict[str, PcapFlowState] = {}
    live_capturer = FlowExtractor(api_url="http://mock", flow_timeout=3600.0, min_packets=1)

    # Sequence of 4 Scapy packets
    p1 = IP(src="192.168.1.50", dst="172.16.0.4", ttl=64) / TCP(sport=50000, dport=443, flags="S", seq=100, window=64240)
    p1.time = 1700000000.0
    p2 = IP(src="172.16.0.4", dst="192.168.1.50", ttl=128) / TCP(sport=443, dport=50000, flags="SA", seq=500, ack=101, window=32768)
    p2.time = 1700000000.015
    p3 = IP(src="192.168.1.50", dst="172.16.0.4", ttl=64) / TCP(sport=50000, dport=443, flags="A", seq=101, ack=501, window=64240)
    p3.time = 1700000000.020
    p4 = IP(src="192.168.1.50", dst="172.16.0.4", ttl=64) / TCP(sport=50000, dport=443, flags="PA", seq=101, ack=501, window=64240) / b"GET / HTTP/1.1\r\n"
    p4.time = 1700000000.035

    scapy_packets = [p1, p2, p3, p4]

    # Process through live capturer
    for pkt in scapy_packets:
        live_capturer.process_packet(pkt)

    # Process through pcap.py logic
    for pkt in scapy_packets:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
        ttl = int(ip.ttl)
        pkt_len = int(ip.len) if hasattr(ip, "len") and ip.len else len(pkt)
        ts = float(pkt.time)
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = int(tcp.flags)
        tcp_win = int(tcp.window)
        seq = int(tcp.seq)

        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            is_fwd = True
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
            is_fwd = False

        if key not in pcap_flows:
            pcap_flows[key] = PcapFlowState(
                src_ip=src_ip if is_fwd else dst_ip,
                dst_ip=dst_ip if is_fwd else src_ip,
                src_port=src_port if is_fwd else dst_port,
                dst_port=dst_port if is_fwd else src_port,
                protocol=proto,
            )

        pcap_flows[key].add_packet(
            pkt_len=pkt_len,
            is_forward=is_fwd,
            timestamp=ts,
            tcp_flags=tcp_flags,
            ttl=ttl,
            tcp_win=tcp_win,
            seq=seq,
        )

    # Assert exactly 1 flow key generated in both
    assert len(live_capturer.active_flows) == 1
    assert len(pcap_flows) == 1
    key = list(pcap_flows.keys())[0]
    assert key in live_capturer.active_flows

    live_flow = live_capturer.active_flows[key]
    pcap_flow = pcap_flows[key]

    live_feats = live_flow.to_features()
    pcap_feats = pcap_flow.to_features()

    for feat in FLOW_FEATURES:
        assert live_feats[feat] == pcap_feats[feat], (
            f"Feature disparity on {feat}: live={live_feats[feat]} vs pcap={pcap_feats[feat]}"
        )

