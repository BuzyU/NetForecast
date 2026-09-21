"""
POST /ingest/pcap — parse PCAP network captures and ingest extracted flows.
Uses Scapy for packet parsing and extracts all 22 CIC-IDS network features.
"""
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..ingestion import ingest_single_flow
from ..schemas import FlowRecord, IngestResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@dataclass
class PcapFlowState:
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

    def add_packet(
        self,
        pkt_len: int,
        is_forward: bool,
        timestamp: float,
        tcp_flags: int = 0,
        ttl: int = 64,
        tcp_win: int = 0,
        seq: int = 0,
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

    def to_features(self) -> dict:
        duration_us = (self.last_time - self.start_time) * 1e6 if self.last_time > self.start_time else 1.0
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_packets + self.bwd_packets

        return {
            "flow_duration": max(1.0, duration_us),
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
            "down_up_ratio": float(self.bwd_bytes / max(self.fwd_bytes, 1)),
            "pkt_size_avg": float(total_bytes / max(total_pkts, 1)),
            "ttl_variance": float(np.var(self.ttl_values)) if len(self.ttl_values) > 1 else 0.0,
            "tcp_win_size": float(np.mean(self.tcp_win_sizes)) if self.tcp_win_sizes else 0.0,
            "retransmit_cnt": float(self.retransmit_count),
        }


@router.post("/ingest/pcap", response_model=IngestResponse)
async def ingest_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest network traffic from an uploaded .pcap or .pcapng file.
    Reconstructs bi-directional flows, computes 22 CIC-IDS features,
    and feeds them through the attack forecasting engine.
    """
    filename = (file.filename or "").lower()
    if not (filename.endswith(".pcap") or filename.endswith(".cap") or filename.endswith(".pcapng")):
        raise HTTPException(
            status_code=422,
            detail="File must be a PCAP capture (.pcap, .cap, .pcapng)",
        )

    try:
        from scapy.all import IP, TCP, UDP, PcapReader
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Scapy is not installed on the backend server",
        )

    # Save to a temporary file for PcapReader streaming
    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    flows: dict[str, PcapFlowState] = {}
    errors = []
    accepted = 0
    rejected = 0
    alerts_generated = 0

    try:
        reader = PcapReader(tmp_path)
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto
            ttl = int(ip.ttl)
            pkt_len = int(ip.len) if hasattr(ip, "len") and ip.len else len(pkt)
            ts = float(pkt.time)

            src_port, dst_port = 0, 0
            tcp_flags, tcp_win, seq = 0, 0, 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = int(tcp.flags)
                tcp_win = int(tcp.window)
                seq = int(tcp.seq)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

            # Canonical bidirectional key: (src, dst) ordered lexicographically
            if (src_ip, src_port) <= (dst_ip, dst_port):
                key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                is_fwd = True
            else:
                key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
                is_fwd = False

            if key not in flows:
                flows[key] = PcapFlowState(
                    src_ip=src_ip if is_fwd else dst_ip,
                    dst_ip=dst_ip if is_fwd else src_ip,
                    src_port=src_port if is_fwd else dst_port,
                    dst_port=dst_port if is_fwd else src_port,
                    protocol=proto,
                )

            flows[key].add_packet(
                pkt_len=pkt_len,
                is_forward=is_fwd,
                timestamp=ts,
                tcp_flags=tcp_flags,
                ttl=ttl,
                tcp_win=tcp_win,
                seq=seq,
            )
        reader.close()
    except Exception as e:
        logger.error("Failed to parse PCAP file: %s", e)
        raise HTTPException(status_code=422, detail=f"Failed to parse PCAP file: {e}")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    # Process extracted flows
    for key, flow_state in flows.items():
        try:
            feat_dict = flow_state.to_features()
            feat_dict["src_ip"] = flow_state.src_ip
            feat_dict["dst_ip"] = flow_state.dst_ip
            feat_dict["source"] = "pcap_upload"
            feat_dict["timestamp"] = (
                datetime.fromtimestamp(flow_state.start_time, tz=timezone.utc)
                if flow_state.start_time > 0
                else datetime.now(timezone.utc)
            )

            flow_record = FlowRecord(**feat_dict)
            result = await ingest_single_flow(flow_record, db)
            accepted += 1
            if result.get("alert"):
                alerts_generated += 1
        except Exception as exc:
            rejected += 1
            if len(errors) < 10:
                errors.append(f"Flow {key}: {exc}")

    return IngestResponse(
        flows_accepted=accepted,
        flows_rejected=rejected,
        errors=errors,
        alerts_generated=alerts_generated,
    )
