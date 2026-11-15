"""
CICIDS2017 dataset loader and cleaner for AgentShield.

Usage:
    from ml.data_loader import load_cicids2017
    X, y = load_cicids2017("path/to/cicids2017/csv_dir")
"""

import logging
import os
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd

from ml.feature_schema import COLUMN_ALIASES, FEATURE_NAMES, normalize_column_name

logger = logging.getLogger(__name__)

# All known attack labels in CICIDS2017 (unified to "ATTACK")
ATTACK_LABELS = {
    "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration",
    "PortScan", "SSH-Patator", "Web Attack – Brute Force",
    "Web Attack – Sql Injection", "Web Attack – XSS",
    # lowercase variants
    "ddos", "dos goldeneye", "dos hulk", "dos slowhttptest",
    "dos slowloris", "ftp-patator", "portScan", "portscan",
    "ssh-patator",
}


def load_cicids2017(
    data_dir: str | Path,
    max_rows_per_file: int | None = None,
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load all CSV files from the CICIDS2017 directory.
    Returns (X, y) where y is a binary Series: 0=BENIGN, 1=ATTACK.
    """
    data_dir = Path(data_dir)
    csv_files = list(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    logger.info("Loading %d CICIDS2017 CSV file(s) from %s", len(csv_files), data_dir)

    dfs = []
    for csv_file in sorted(csv_files):
        logger.info("  Loading: %s", csv_file.name)
        try:
            df = pd.read_csv(
                csv_file,
                nrows=max_rows_per_file,
                low_memory=False,
                on_bad_lines="skip",
            )
            dfs.append(df)
        except Exception as exc:
            logger.warning("Could not read %s: %s", csv_file.name, exc)

    if not dfs:
        raise ValueError("No data loaded from CICIDS2017 directory")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info("Combined shape before cleaning: %s", combined.shape)

    # ── Normalize column names ────────────────────────────────────
    combined.columns = [normalize_column_name(c) for c in combined.columns]

    # Find label column (various spellings in CICIDS2017)
    label_col = None
    for col in combined.columns:
        if col.strip().lower() in ("label", " label"):
            label_col = col
            break
    if label_col is None:
        raise ValueError(
            f"Label column not found. Available columns: {list(combined.columns)[:10]}"
        )

    # ── Extract labels ────────────────────────────────────────────
    raw_labels = combined[label_col].str.strip()
    y = (raw_labels.str.upper() != "BENIGN").astype(int)  # 0=BENIGN, 1=ATTACK
    logger.info(
        "Label distribution: BENIGN=%d, ATTACK=%d",
        (y == 0).sum(), (y == 1).sum(),
    )

    # ── Select features ───────────────────────────────────────────
    missing = [f for f in FEATURE_NAMES if f not in combined.columns]
    if missing:
        logger.warning("Missing %d features in dataset: %s", len(missing), missing[:5])

    available = [f for f in FEATURE_NAMES if f in combined.columns]
    X = combined[available].copy()

    # ── Clean data ────────────────────────────────────────────────
    # Replace infinity with NaN, then handle
    X = X.replace([np.inf, -np.inf], np.nan)

    # Log NaN stats before dropping
    nan_counts = X.isnull().sum()
    if nan_counts.sum() > 0:
        logger.info("NaN counts per feature (top 5): %s", nan_counts[nan_counts > 0].head(5).to_dict())

    # Fill NaN with 0 (safe for tree-based models)
    X = X.fillna(0)

    # Drop duplicate rows
    original_len = len(X)
    X = X.drop_duplicates()
    y = y.loc[X.index]
    logger.info("Dropped %d duplicate rows", original_len - len(X))

    # Ensure correct dtypes
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    logger.info("Final dataset shape: %s | Features: %d", X.shape, len(available))
    return X, y
