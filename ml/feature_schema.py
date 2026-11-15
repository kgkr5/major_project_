"""
Feature schema for AgentShield ML pipeline.

This is the SINGLE SOURCE OF TRUTH for the 77 network flow features
used by the Random Forest classifier. All feature extraction, normalization,
and model training must use this ordered list.

The feature ordering matches the CICIDS2017 dataset column order
(excluding Label column). Any change here requires model retraining.
"""

from typing import List

# Ordered list of 77 feature names exactly as used in CICIDS2017
# Index 0–76 (77 features total)
FEATURE_NAMES: List[str] = [
    "Destination Port",           # 0
    "Flow Duration",              # 1
    "Total Fwd Packets",          # 2
    "Total Backward Packets",     # 3
    "Total Length of Fwd Packets",# 4
    "Total Length of Bwd Packets",# 5
    "Fwd Packet Length Max",      # 6
    "Fwd Packet Length Min",      # 7
    "Fwd Packet Length Mean",     # 8
    "Fwd Packet Length Std",      # 9
    "Bwd Packet Length Max",      # 10
    "Bwd Packet Length Min",      # 11
    "Bwd Packet Length Mean",     # 12
    "Bwd Packet Length Std",      # 13
    "Flow Bytes/s",               # 14
    "Flow Packets/s",             # 15
    "Flow IAT Mean",              # 16
    "Flow IAT Std",               # 17
    "Flow IAT Max",               # 18
    "Flow IAT Min",               # 19
    "Fwd IAT Total",              # 20
    "Fwd IAT Mean",               # 21
    "Fwd IAT Std",                # 22
    "Fwd IAT Max",                # 23
    "Fwd IAT Min",                # 24
    "Bwd IAT Total",              # 25
    "Bwd IAT Mean",               # 26
    "Bwd IAT Std",                # 27
    "Bwd IAT Max",                # 28
    "Bwd IAT Min",                # 29
    "Fwd PSH Flags",              # 30
    "Bwd PSH Flags",              # 31
    "Fwd URG Flags",              # 32
    "Bwd URG Flags",              # 33
    "Fwd Header Length",          # 34
    "Bwd Header Length",          # 35
    "Fwd Packets/s",              # 36
    "Bwd Packets/s",              # 37
    "Min Packet Length",          # 38
    "Max Packet Length",          # 39
    "Packet Length Mean",         # 40
    "Packet Length Std",          # 41
    "Packet Length Variance",     # 42
    "FIN Flag Count",             # 43
    "SYN Flag Count",             # 44
    "RST Flag Count",             # 45
    "PSH Flag Count",             # 46
    "ACK Flag Count",             # 47
    "URG Flag Count",             # 48
    "CWE Flag Count",             # 49
    "ECE Flag Count",             # 50
    "Down/Up Ratio",              # 51
    "Average Packet Size",        # 52
    "Avg Fwd Segment Size",       # 53
    "Avg Bwd Segment Size",       # 54
    "Fwd Header Length.1",        # 55  (duplicate column in CICIDS2017 CSV)
    "Fwd Avg Bytes/Bulk",         # 56
    "Fwd Avg Packets/Bulk",       # 57
    "Fwd Avg Bulk Rate",          # 58
    "Bwd Avg Bytes/Bulk",         # 59
    "Bwd Avg Packets/Bulk",       # 60
    "Bwd Avg Bulk Rate",          # 61
    "Subflow Fwd Packets",        # 62
    "Subflow Fwd Bytes",          # 63
    "Subflow Bwd Packets",        # 64
    "Subflow Bwd Bytes",          # 65
    "Init_Win_bytes_forward",     # 66
    "Init_Win_bytes_backward",    # 67
    "act_data_pkt_fwd",           # 68
    "min_seg_size_forward",       # 69
    "Active Mean",                # 70
    "Active Std",                 # 71
    "Active Max",                 # 72
    "Active Min",                 # 73
    "Idle Mean",                  # 74
    "Idle Std",                   # 75
    "Idle Max",                   # 76
    # NOTE: "Idle Min" appears in some CICIDS2017 variants as a 78th column.
    # The model is trained on 77 features. Verify against your CSV header.
]

FEATURE_COUNT: int = len(FEATURE_NAMES)

# Index lookup for fast access
FEATURE_INDEX: dict = {name: idx for idx, name in enumerate(FEATURE_NAMES)}

# Alternative column name mappings from raw CICFlowMeter output
# (handles whitespace variations in CSV headers)
COLUMN_ALIASES: dict = {
    " Destination Port": "Destination Port",
    " Flow Duration": "Flow Duration",
    " Total Fwd Packets": "Total Fwd Packets",
    " Total Backward Packets": "Total Backward Packets",
    "Total Length of Fwd Packets": "Total Length of Fwd Packets",
    " Total Length of Bwd Packets": "Total Length of Bwd Packets",
    " Fwd Packet Length Max": "Fwd Packet Length Max",
    " Fwd Packet Length Min": "Fwd Packet Length Min",
    " Fwd Packet Length Mean": "Fwd Packet Length Mean",
    " Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    " Bwd Packet Length Min": "Bwd Packet Length Min",
    " Bwd Packet Length Mean": "Bwd Packet Length Mean",
    " Bwd Packet Length Std": "Bwd Packet Length Std",
    "Flow Bytes/s": "Flow Bytes/s",
    " Flow Packets/s": "Flow Packets/s",
    " Flow IAT Mean": "Flow IAT Mean",
    " Flow IAT Std": "Flow IAT Std",
    " Flow IAT Max": "Flow IAT Max",
    " Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    " Fwd IAT Mean": "Fwd IAT Mean",
    " Fwd IAT Std": "Fwd IAT Std",
    " Fwd IAT Max": "Fwd IAT Max",
    " Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    " Bwd IAT Mean": "Bwd IAT Mean",
    " Bwd IAT Std": "Bwd IAT Std",
    " Bwd IAT Max": "Bwd IAT Max",
    " Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    " Bwd PSH Flags": "Bwd PSH Flags",
    " Fwd URG Flags": "Fwd URG Flags",
    " Bwd URG Flags": "Bwd URG Flags",
    " Fwd Header Length": "Fwd Header Length",
    " Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    " Bwd Packets/s": "Bwd Packets/s",
    " Min Packet Length": "Min Packet Length",
    " Max Packet Length": "Max Packet Length",
    " Packet Length Mean": "Packet Length Mean",
    " Packet Length Std": "Packet Length Std",
    " Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    " SYN Flag Count": "SYN Flag Count",
    " RST Flag Count": "RST Flag Count",
    " PSH Flag Count": "PSH Flag Count",
    " ACK Flag Count": "ACK Flag Count",
    " URG Flag Count": "URG Flag Count",
    " CWE Flag Count": "CWE Flag Count",
    " ECE Flag Count": "ECE Flag Count",
    " Down/Up Ratio": "Down/Up Ratio",
    " Average Packet Size": "Average Packet Size",
    " Avg Fwd Segment Size": "Avg Fwd Segment Size",
    " Avg Bwd Segment Size": "Avg Bwd Segment Size",
    " Fwd Header Length.1": "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
    " Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    " Subflow Fwd Bytes": "Subflow Fwd Bytes",
    " Subflow Bwd Packets": "Subflow Bwd Packets",
    " Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Init_Win_bytes_forward": "Init_Win_bytes_forward",
    " Init_Win_bytes_backward": "Init_Win_bytes_backward",
    " act_data_pkt_fwd": "act_data_pkt_fwd",
    " min_seg_size_forward": "min_seg_size_forward",
    "Active Mean": "Active Mean",
    " Active Std": "Active Std",
    " Active Max": "Active Max",
    " Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    " Idle Std": "Idle Std",
    " Idle Max": "Idle Max",
}


def validate_feature_count() -> bool:
    """Assert the schema has exactly 77 features. Call in tests."""
    assert FEATURE_COUNT == 77, f"Expected 77 features, got {FEATURE_COUNT}"
    names_set = set(FEATURE_NAMES)
    assert len(names_set) == 77, "Duplicate feature names detected"
    return True


def normalize_column_name(raw: str) -> str:
    """Strip leading/trailing whitespace and apply known aliases."""
    stripped = raw.strip()
    return COLUMN_ALIASES.get(raw, stripped)
