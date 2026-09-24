"""
POST /ingest/pcap — parse PCAP network captures and ingest extracted flows.
Uses Scapy for packet parsing and extracts all 22 CIC-IDS network features.
"""
import logging
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..flow_state import FlowState
from ..ingestion import ingest_single_flow
from ..schemas import FlowRecord, IngestResponse

PcapFlowState = FlowState

logger = logging.getLogger(__name__)
router = APIRouter()



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
            payload = b""

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = int(tcp.flags)
                tcp_win = int(tcp.window)
                seq = int(tcp.seq)
                if tcp.payload:
                    payload = bytes(tcp.payload)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

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
                payload=payload,
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

    for key, flow_state in flows.items():
        try:
            feat_dict = flow_state.to_features()
            feat_dict["src_ip"] = flow_state.src_ip
            feat_dict["dst_ip"] = flow_state.dst_ip
            feat_dict["source"] = "pcap_upload"
            feat_dict["heartbleed_signature"] = flow_state.heartbleed_detected
            feat_dict["timestamp"] = (
                datetime.fromtimestamp(flow_state.start_time, tz=timezone.utc)
                if flow_state.start_time > 0
                else datetime.now(timezone.utc)
            )

            flow_record = FlowRecord(**feat_dict)
            result = await ingest_single_flow(flow_record, db)
            accepted += 1
            if result.get("alert") or result.get("heartbleed_alert"):
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
