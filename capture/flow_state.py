"""
Shared FlowState data structure for bidirectional flow reconstruction and 22-feature CIC-IDS extraction.
Used identically by:
  - capture/live_capture.py (Live NIC & raw socket sniffer)
  - backend/app/routes/pcap.py (PCAP/PCAPNG file upload ingestion)
"""
from dataclasses import dataclass, field

import numpy as np

try:
    from .signatures import detect_heartbleed
except ImportError:
    from signatures import detect_heartbleed


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

    heartbleed_detected: bool = False

    def add_packet(
        self,
        pkt_len: int,
        is_forward: bool,
        timestamp: float,
        tcp_flags: int = 0,
        ttl: int = 64,
        tcp_win: int = 0,
        seq: int = 0,
        payload: bytes = b"",
    ):
        if self.packet_count == 0:
            self.start_time = timestamp
            self.last_pkt_time = timestamp
            self.last_fwd_time = timestamp
            self.last_bwd_time = timestamp

        self.last_time = timestamp
        self.packet_count += 1

        if self.packet_count > 1:
            iat = (timestamp - self.last_pkt_time) * 1e6
            self.flow_iats.append(max(0.0, iat))
        self.last_pkt_time = timestamp

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lengths.append(pkt_len)
            if self.fwd_packets > 1:
                iat = (timestamp - self.last_fwd_time) * 1e6
                self.fwd_iats.append(max(0.0, iat))
            self.last_fwd_time = timestamp
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lengths.append(pkt_len)
            if self.bwd_packets > 1:
                iat = (timestamp - self.last_bwd_time) * 1e6
                self.bwd_iats.append(max(0.0, iat))
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

        if payload and not self.heartbleed_detected:
            self.heartbleed_detected = detect_heartbleed(payload)

    def to_features(self) -> dict:
        duration_us = (self.last_time - self.start_time) * 1e6 if self.last_time > self.start_time else 0.0
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_packets + self.bwd_packets

        # Prevent sub-millisecond division artifacts where tiny packet bursts
        # calculate synthetic rates of millions of pkts/sec.
        # Enforce minimum 10ms (0.010s) window for rate calculation.
        effective_duration_sec = max(duration_us / 1e6, 0.01)
        effective_duration_us = max(duration_us, 10000.0)

        return {
            "flow_duration": effective_duration_us,
            "tot_fwd_pkts": float(self.fwd_packets),
            "tot_bwd_pkts": float(self.bwd_packets),
            "fwd_pkt_len_mean": float(np.mean(self.fwd_pkt_lengths)) if self.fwd_pkt_lengths else 0.0,
            "bwd_pkt_len_mean": float(np.mean(self.bwd_pkt_lengths)) if self.bwd_pkt_lengths else 0.0,
            "flow_bytes_s": float(total_bytes / effective_duration_sec),
            "flow_pkts_s": float(total_pkts / effective_duration_sec),
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
            "down_up_ratio": float(self.bwd_packets / max(self.fwd_packets, 1)),
            "pkt_size_avg": float(total_bytes / max(total_pkts, 1)),
            "ttl_variance": float(np.var(self.ttl_values)) if len(self.ttl_values) > 1 else 0.0,
            "tcp_win_size": float(np.mean(self.tcp_win_sizes)) if self.tcp_win_sizes else 0.0,
            "retransmit_cnt": float(self.retransmit_count),
        }
