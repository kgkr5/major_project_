"""
CICFlowMeter-compatible network flow feature extractor.

Processes PCAP files using dpkt, extracts bidirectional flows,
and computes the 77 CICIDS2017 features required by the ML model.

Feature ordering is imported from ml/feature_schema.py (single source of truth).
"""

import io
import logging
import math
import socket
import statistics
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "dpkt not installed. Flow extraction will be unavailable."
    )

import sys, os
# Allow importing ml.feature_schema from the project root
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ml.feature_schema import FEATURE_NAMES, FEATURE_COUNT
from backend.schemas.flows import FlowRecord

logger = logging.getLogger(__name__)

# TCP flag masks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWE = 0x80


@dataclass
class _Packet:
    """Internal representation of a single packet in a flow."""
    timestamp: float          # seconds (epoch)
    length: int               # total IP packet length
    payload_length: int       # TCP/UDP payload length
    header_length: int        # TCP/UDP header length
    tcp_flags: int = 0
    tcp_window: int = 0
    is_forward: bool = True
    is_retransmit: bool = False


@dataclass
class _FlowState:
    """Accumulated state for a bidirectional flow."""
    flow_key: Tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float = 0.0
    last_time: float = 0.0

    fwd_packets: List[_Packet] = field(default_factory=list)
    bwd_packets: List[_Packet] = field(default_factory=list)

    # TCP window sizes (first packet each direction)
    init_win_fwd: int = -1
    init_win_bwd: int = -1

    # Active / idle tracking
    active_start: float = 0.0
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)
    last_active: float = 0.0
    IDLE_THRESHOLD: float = 1.0  # seconds


def _safe_div(a: float, b: float) -> float:
    return a / b if b != 0 else 0.0


def _safe_std(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    try:
        return statistics.stdev(values)
    except statistics.StatisticsError:
        return 0.0


def _safe_mean(values: List[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _iats(timestamps: List[float]) -> List[float]:
    """Inter-arrival times between consecutive packets."""
    if len(timestamps) < 2:
        return []
    return [(timestamps[i] - timestamps[i - 1]) * 1_000_000  # → microseconds
            for i in range(1, len(timestamps))]


def _flag_count(packets: List[_Packet], flag: int) -> int:
    return sum(1 for p in packets if p.tcp_flags & flag)


class FlowExtractor:
    """
    Extract 77 CICIDS2017-compatible features from a PCAP file.
    Returns a list of FlowRecord objects.
    """

    # Flows inactive for this many seconds are considered complete
    FLOW_TIMEOUT_SECONDS: float = 120.0

    def __init__(self) -> None:
        if not DPKT_AVAILABLE:
            raise RuntimeError("dpkt is required for flow extraction. Install it with: pip install dpkt")

    def extract_from_file(self, pcap_path: Path) -> List[FlowRecord]:
        """
        Process a PCAP file and return one FlowRecord per completed flow.
        Malformed packets are skipped with a warning.
        """
        flows: Dict[Tuple, _FlowState] = {}
        completed: List[FlowRecord] = []
        pcap_source = str(pcap_path)

        try:
            with open(pcap_path, "rb") as fh:
                try:
                    reader = dpkt.pcap.Reader(fh)
                except Exception:
                    fh.seek(0)
                    try:
                        reader = dpkt.pcapng.Reader(fh)
                    except Exception as exc:
                        logger.error("Cannot open PCAP %s: %s", pcap_path, exc)
                        return []

                for ts, buf in reader:
                    try:
                        self._process_packet(ts, buf, flows)
                    except Exception as exc:
                        logger.debug("Skipping malformed packet: %s", exc)

        except OSError as exc:
            logger.error("Cannot read PCAP file %s: %s", pcap_path, exc)
            return []

        # Finalise all remaining flows
        for flow_state in flows.values():
            record = self._build_record(flow_state, pcap_source)
            if record is not None:
                completed.append(record)

        logger.info(
            "Extracted %d flows from %s", len(completed), pcap_path.name
        )
        return completed

    def extract_from_bytes(self, pcap_bytes: bytes) -> List[FlowRecord]:
        """Extract flows from an in-memory PCAP byte string."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = Path(tmp.name)
        try:
            return self.extract_from_file(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    # ── Internal ─────────────────────────────────────────────────

    def _process_packet(
        self, ts: float, buf: bytes, flows: Dict[Tuple, "_FlowState"]
    ) -> None:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            return

        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return

        src_ip = _ip_to_str(ip.src)
        dst_ip = _ip_to_str(ip.dst)
        transport = ip.data
        ip_len = len(buf) - len(eth.data) + len(ip)  # approximate

        if isinstance(transport, dpkt.tcp.TCP):
            proto = "TCP"
            src_port = transport.sport
            dst_port = transport.dport
            hdr_len = transport.off * 4
            payload_len = max(0, len(transport.data))
            tcp_flags = int(transport.flags)
            tcp_window = int(transport.win)
        elif isinstance(transport, dpkt.udp.UDP):
            proto = "UDP"
            src_port = transport.sport
            dst_port = transport.dport
            hdr_len = 8
            payload_len = max(0, len(transport.data))
            tcp_flags = 0
            tcp_window = 0
        elif isinstance(transport, dpkt.icmp.ICMP):
            proto = "ICMP"
            src_port = 0
            dst_port = 0
            hdr_len = 4
            payload_len = max(0, len(transport.data))
            tcp_flags = 0
            tcp_window = 0
        else:
            return

        # Flow key: always (min(src,dst), max(src,dst), min_port, max_port, proto)
        # to group bidirectional traffic
        if (src_ip, src_port) <= (dst_ip, dst_port):
            fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
            is_forward = True
        else:
            fwd_key = (dst_ip, src_ip, dst_port, src_port, proto)
            is_forward = False

        if fwd_key not in flows:
            flows[fwd_key] = _FlowState(
                flow_key=fwd_key,
                src_ip=fwd_key[0],
                dst_ip=fwd_key[1],
                src_port=fwd_key[2],
                dst_port=fwd_key[3],
                protocol=proto,
                start_time=ts,
                last_time=ts,
                active_start=ts,
                last_active=ts,
            )

        state = flows[fwd_key]
        pkt = _Packet(
            timestamp=ts,
            length=len(buf),
            payload_length=payload_len,
            header_length=hdr_len,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            is_forward=is_forward,
        )

        if is_forward:
            state.fwd_packets.append(pkt)
            if state.init_win_fwd == -1 and tcp_window:
                state.init_win_fwd = tcp_window
        else:
            state.bwd_packets.append(pkt)
            if state.init_win_bwd == -1 and tcp_window:
                state.init_win_bwd = tcp_window

        # Active / idle tracking
        gap = ts - state.last_active
        if gap > state.IDLE_THRESHOLD:
            state.active_times.append(state.last_active - state.active_start)
            state.idle_times.append(gap)
            state.active_start = ts
        state.last_active = ts
        state.last_time = ts

    def _build_record(self, s: _FlowState, pcap_source: str) -> Optional[FlowRecord]:
        """Convert a _FlowState into a 77-feature FlowRecord."""
        all_pkts = s.fwd_packets + s.bwd_packets
        if not all_pkts:
            return None

        all_pkts_sorted = sorted(all_pkts, key=lambda p: p.timestamp)
        duration_us = max(0, int((s.last_time - s.start_time) * 1_000_000))
        duration_s = max(1e-9, s.last_time - s.start_time)

        fwd = s.fwd_packets
        bwd = s.bwd_packets

        # Lengths
        fwd_lens = [p.length for p in fwd]
        bwd_lens = [p.length for p in bwd]
        all_lens = [p.length for p in all_pkts_sorted]
        fwd_pay = [p.payload_length for p in fwd]
        bwd_pay = [p.payload_length for p in bwd]

        # IATs (microseconds)
        fwd_ts = sorted([p.timestamp for p in fwd])
        bwd_ts = sorted([p.timestamp for p in bwd])
        all_ts = sorted([p.timestamp for p in all_pkts_sorted])

        fwd_iats = _iats(fwd_ts)
        bwd_iats = _iats(bwd_ts)
        all_iats = _iats(all_ts)

        # Header lengths
        fwd_hdr_total = sum(p.header_length for p in fwd)
        bwd_hdr_total = sum(p.header_length for p in bwd)

        # TCP flags
        def fc(pkts: list, flag: int) -> int:
            return _flag_count(pkts, flag)

        fin_cnt = fc(all_pkts_sorted, TCP_FIN)
        syn_cnt = fc(all_pkts_sorted, TCP_SYN)
        rst_cnt = fc(all_pkts_sorted, TCP_RST)
        psh_cnt = fc(all_pkts_sorted, TCP_PSH)
        ack_cnt = fc(all_pkts_sorted, TCP_ACK)
        urg_cnt = fc(all_pkts_sorted, TCP_URG)
        ece_cnt = fc(all_pkts_sorted, TCP_ECE)
        cwe_cnt = fc(all_pkts_sorted, TCP_CWE)

        fwd_psh = fc(fwd, TCP_PSH)
        bwd_psh = fc(bwd, TCP_PSH)
        fwd_urg = fc(fwd, TCP_URG)
        bwd_urg = fc(bwd, TCP_URG)

        # Bulk calculations (simplified)
        fwd_bulk_bytes, fwd_bulk_pkts, fwd_bulk_rate = self._calc_bulk(fwd, duration_s)
        bwd_bulk_bytes, bwd_bulk_pkts, bwd_bulk_rate = self._calc_bulk(bwd, duration_s)

        # Active/Idle
        # Finalize active window
        final_active = s.last_active - s.active_start
        active_times = s.active_times + [final_active] if final_active > 0 else s.active_times
        idle_times = s.idle_times

        # act_data_pkt_fwd: fwd packets with payload > 0
        act_data_fwd = sum(1 for p in fwd if p.payload_length > 0)

        # min_seg_size_forward: minimum TCP segment size (payload)
        min_seg_fwd = min((p.payload_length for p in fwd if p.payload_length > 0), default=0)

        # init window sizes
        init_win_fwd = max(0, s.init_win_fwd) if s.init_win_fwd >= 0 else 0
        init_win_bwd = max(0, s.init_win_bwd) if s.init_win_bwd >= 0 else 0

        # Subflows (simplified: each burst = 1 subflow)
        subflow_fwd_pkts = len(fwd)
        subflow_fwd_bytes = sum(fwd_pay)
        subflow_bwd_pkts = len(bwd)
        subflow_bwd_bytes = sum(bwd_pay)

        # Down/Up ratio
        down_up = _safe_div(len(bwd), len(fwd))

        # Packet length stats (all packets)
        pkt_len_mean = _safe_mean(all_lens)
        pkt_len_std = _safe_std(all_lens)
        pkt_len_var = pkt_len_std ** 2

        # Avg segment sizes
        avg_fwd_seg = _safe_mean(fwd_pay) if fwd_pay else 0.0
        avg_bwd_seg = _safe_mean(bwd_pay) if bwd_pay else 0.0

        # Flow rates
        flow_bytes_s = _safe_div(sum(all_lens), duration_s)
        flow_pkts_s = _safe_div(len(all_pkts_sorted), duration_s)
        fwd_pkts_s = _safe_div(len(fwd), duration_s)
        bwd_pkts_s = _safe_div(len(bwd), duration_s)

        feat = [
            float(s.dst_port),                                      # 0  Destination Port
            float(duration_us),                                     # 1  Flow Duration
            float(len(fwd)),                                        # 2  Total Fwd Packets
            float(len(bwd)),                                        # 3  Total Backward Packets
            float(sum(fwd_pay)),                                    # 4  Total Length of Fwd Packets
            float(sum(bwd_pay)),                                    # 5  Total Length of Bwd Packets
            float(max(fwd_lens, default=0)),                        # 6  Fwd Packet Length Max
            float(min(fwd_lens, default=0)),                        # 7  Fwd Packet Length Min
            float(_safe_mean(fwd_lens)),                            # 8  Fwd Packet Length Mean
            float(_safe_std(fwd_lens)),                             # 9  Fwd Packet Length Std
            float(max(bwd_lens, default=0)),                        # 10 Bwd Packet Length Max
            float(min(bwd_lens, default=0)),                        # 11 Bwd Packet Length Min
            float(_safe_mean(bwd_lens)),                            # 12 Bwd Packet Length Mean
            float(_safe_std(bwd_lens)),                             # 13 Bwd Packet Length Std
            float(flow_bytes_s),                                    # 14 Flow Bytes/s
            float(flow_pkts_s),                                     # 15 Flow Packets/s
            float(_safe_mean(all_iats)),                            # 16 Flow IAT Mean
            float(_safe_std(all_iats)),                             # 17 Flow IAT Std
            float(max(all_iats, default=0)),                        # 18 Flow IAT Max
            float(min(all_iats, default=0)),                        # 19 Flow IAT Min
            float(sum(fwd_iats)),                                   # 20 Fwd IAT Total
            float(_safe_mean(fwd_iats)),                            # 21 Fwd IAT Mean
            float(_safe_std(fwd_iats)),                             # 22 Fwd IAT Std
            float(max(fwd_iats, default=0)),                        # 23 Fwd IAT Max
            float(min(fwd_iats, default=0)),                        # 24 Fwd IAT Min
            float(sum(bwd_iats)),                                   # 25 Bwd IAT Total
            float(_safe_mean(bwd_iats)),                            # 26 Bwd IAT Mean
            float(_safe_std(bwd_iats)),                             # 27 Bwd IAT Std
            float(max(bwd_iats, default=0)),                        # 28 Bwd IAT Max
            float(min(bwd_iats, default=0)),                        # 29 Bwd IAT Min
            float(fwd_psh),                                         # 30 Fwd PSH Flags
            float(bwd_psh),                                         # 31 Bwd PSH Flags
            float(fwd_urg),                                         # 32 Fwd URG Flags
            float(bwd_urg),                                         # 33 Bwd URG Flags
            float(fwd_hdr_total),                                   # 34 Fwd Header Length
            float(bwd_hdr_total),                                   # 35 Bwd Header Length
            float(fwd_pkts_s),                                      # 36 Fwd Packets/s
            float(bwd_pkts_s),                                      # 37 Bwd Packets/s
            float(min(all_lens, default=0)),                        # 38 Min Packet Length
            float(max(all_lens, default=0)),                        # 39 Max Packet Length
            float(pkt_len_mean),                                    # 40 Packet Length Mean
            float(pkt_len_std),                                     # 41 Packet Length Std
            float(pkt_len_var),                                     # 42 Packet Length Variance
            float(fin_cnt),                                         # 43 FIN Flag Count
            float(syn_cnt),                                         # 44 SYN Flag Count
            float(rst_cnt),                                         # 45 RST Flag Count
            float(psh_cnt),                                         # 46 PSH Flag Count
            float(ack_cnt),                                         # 47 ACK Flag Count
            float(urg_cnt),                                         # 48 URG Flag Count
            float(cwe_cnt),                                         # 49 CWE Flag Count
            float(ece_cnt),                                         # 50 ECE Flag Count
            float(down_up),                                         # 51 Down/Up Ratio
            float(_safe_mean(all_lens)),                            # 52 Average Packet Size
            float(avg_fwd_seg),                                     # 53 Avg Fwd Segment Size
            float(avg_bwd_seg),                                     # 54 Avg Bwd Segment Size
            float(fwd_hdr_total),                                   # 55 Fwd Header Length.1 (dup)
            float(fwd_bulk_bytes),                                  # 56 Fwd Avg Bytes/Bulk
            float(fwd_bulk_pkts),                                   # 57 Fwd Avg Packets/Bulk
            float(fwd_bulk_rate),                                   # 58 Fwd Avg Bulk Rate
            float(bwd_bulk_bytes),                                  # 59 Bwd Avg Bytes/Bulk
            float(bwd_bulk_pkts),                                   # 60 Bwd Avg Packets/Bulk
            float(bwd_bulk_rate),                                   # 61 Bwd Avg Bulk Rate
            float(subflow_fwd_pkts),                                # 62 Subflow Fwd Packets
            float(subflow_fwd_bytes),                               # 63 Subflow Fwd Bytes
            float(subflow_bwd_pkts),                                # 64 Subflow Bwd Packets
            float(subflow_bwd_bytes),                               # 65 Subflow Bwd Bytes
            float(init_win_fwd),                                    # 66 Init_Win_bytes_forward
            float(init_win_bwd),                                    # 67 Init_Win_bytes_backward
            float(act_data_fwd),                                    # 68 act_data_pkt_fwd
            float(min_seg_fwd),                                     # 69 min_seg_size_forward
            float(_safe_mean(active_times) * 1e6),                  # 70 Active Mean (µs)
            float(_safe_std(active_times) * 1e6),                   # 71 Active Std
            float(max(active_times, default=0) * 1e6),              # 72 Active Max
            float(min(active_times, default=0) * 1e6),              # 73 Active Min
            float(_safe_mean(idle_times) * 1e6),                    # 74 Idle Mean (µs)
            float(_safe_std(idle_times) * 1e6),                     # 75 Idle Std
            float(max(idle_times, default=0) * 1e6),                # 76 Idle Max
        ]

        assert len(feat) == FEATURE_COUNT, (
            f"Feature count mismatch: got {len(feat)}, expected {FEATURE_COUNT}"
        )

        # Replace any remaining NaN/Inf
        feat = [0.0 if (math.isnan(v) or math.isinf(v)) else v for v in feat]

        return FlowRecord(
            flow_id=str(uuid.uuid4()),
            src_ip=s.src_ip,
            dest_ip=s.dst_ip,
            src_port=s.src_port,
            dest_port=s.dst_port,
            protocol=s.protocol,
            timestamp=datetime.fromtimestamp(s.start_time, tz=timezone.utc),
            features=feat,
            feature_names=FEATURE_NAMES,
            duration_us=duration_us,
            pcap_source=pcap_source,
        )

    @staticmethod
    def _calc_bulk(pkts: List[_Packet], duration_s: float) -> Tuple[float, float, float]:
        """Simplified bulk statistics: treat the entire direction as one bulk."""
        if not pkts:
            return 0.0, 0.0, 0.0
        total_bytes = sum(p.payload_length for p in pkts)
        total_pkts = len(pkts)
        rate = _safe_div(total_bytes, duration_s)
        return float(total_bytes), float(total_pkts), float(rate)


def _ip_to_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        return "0.0.0.0"
