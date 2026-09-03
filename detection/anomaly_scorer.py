"""
Fraud-Spike Detector — Advanced Detection Layer

Pipeline:
    Raw transactions
        ↓
    Isolation Forest anomaly detection
        ↓
    Temporal velocity / burst signals
        ↓
    Merchant baseline
        ↓
    Device baseline
        ↓
    Risk score (0-100)
        ↓
    Risk priority + evidence
        ↓
    flagged_events.csv

Usage:
    python anomaly_scorer.py --in ../data/transactions.csv --out flagged_events.csv
"""

import argparse
import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------
# Isolation Forest features
# ---------------------------------------------------------------------

FEATURES = [
    "transaction_amount",
    "retry_count",
    "device_uptime_hrs",
    "last_ping_gap_sec",
    "ip_consistency_flag",
]


# ---------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------

def prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and normalize transaction data."""

    df = df.copy()

    if "timestamp" not in df.columns:
        df["timestamp"] = pd.Timestamp.now(tz="UTC")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )

    df = df.sort_values("timestamp").reset_index(drop=True)

    numeric_defaults = {
        "transaction_amount": 0.0,
        "retry_count": 0,
        "device_uptime_hrs": 0.0,
        "last_ping_gap_sec": 0.0,
        "ip_consistency_flag": 1,
    }

    for column, default in numeric_defaults.items():
        if column not in df.columns:
            df[column] = default

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        ).fillna(default)

    if "device_id" not in df.columns:
        df["device_id"] = "UNKNOWN_DEVICE"

    if "merchant_id" not in df.columns:
        df["merchant_id"] = "UNKNOWN_MERCHANT"

    return df


# ---------------------------------------------------------------------
# Temporal features
# ---------------------------------------------------------------------

def _trailing_window_counts(timestamps, window: pd.Timedelta) -> np.ndarray:
    """
    Vectorized replacement for the previous per-timestamp O(n^2) loops.

    For each row, count how many rows in the (sorted) group fall within
    [ts - window, ts] inclusive — identical semantics to the old
    comparison loop, including duplicate timestamps — computed in
    O(n log n) per group via binary search.

    Rows with NaT timestamps get a count of 0 (they never matched the
    old window comparisons either, and they never counted toward other
    rows' windows).
    """
    if isinstance(timestamps, pd.Series):
        ts_series = timestamps
    else:
        ts_series = pd.Series(timestamps)

    # numpy datetime64 has no timezone support, but prepare_data parses
    # timestamps with utc=True, so dropping the tz to naive UTC keeps
    # the same instants while producing a plain datetime64[ns] array.
    if getattr(ts_series.dtype, "tz", None) is not None:
        ts_series = ts_series.dt.tz_convert(None)

    ts = np.asarray(ts_series, dtype="datetime64[ns]")
    win_ns = window.to_timedelta64().astype("int64")

    out = np.zeros(len(ts), dtype=float)

    valid = ~np.isnat(ts)

    if not valid.all():
        ts = ts[valid].astype("int64")
        starts = np.searchsorted(ts, ts - win_ns, side="left")
        ends = np.searchsorted(ts, ts, side="right")
        out[valid] = ends - starts
        return out

    ts = ts.astype("int64")
    starts = np.searchsorted(ts, ts - win_ns, side="left")
    ends = np.searchsorted(ts, ts, side="right")
    return (ends - starts).astype(float)


def add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate transaction velocity for each device and merchant.

    These features help detect:
      - card testing bursts
      - sudden merchant activity
      - compromised terminals

    Windows are computed per group with binary search (O(n log n))
    instead of per-timestamp comparison loops (O(n^2)), so this scales
    to large datasets.
    """

    df = df.copy()

    df = df.sort_values("timestamp")

    # Device-level windows: 5-min burst, 15-min velocity, plus the
    # wider 1h / 6h / 24h counts.
    #
    # A single 5-min burst window catches fast card-testing attacks
    # but misses slower-moving abuse — a device making an unusual
    # number of transactions spread over several hours never trips a
    # 5-min threshold but can still be well outside its own normal
    # pattern. These wider windows catch that.
    device_windows = [
        ("burst_count_5min", pd.Timedelta(minutes=5)),
        ("velocity_15min", pd.Timedelta(minutes=15)),
        ("device_count_1h", pd.Timedelta(minutes=60)),
        ("device_count_6h", pd.Timedelta(minutes=360)),
        ("device_count_24h", pd.Timedelta(minutes=1440)),
    ]

    # Merchant-level window.
    merchant_windows = [
        ("merchant_velocity_15min", pd.Timedelta(minutes=15)),
    ]

    def _assign_window_counts(group_key_col: str, windows: list):
        for col, _ in windows:
            df[col] = 1.0

        for key, indices in df.groupby(group_key_col).groups.items():
            group = df.loc[indices].sort_values("timestamp")
            ts = group["timestamp"].to_numpy()

            for col, window in windows:
                df.loc[group.index, col] = _trailing_window_counts(
                    ts,
                    window,
                )

    _assign_window_counts("device_id", device_windows)
    _assign_window_counts("merchant_id", merchant_windows)

    return df.reset_index(drop=True)


# ---------------------------------------------------------------------
# Merchant baseline
# ---------------------------------------------------------------------

def add_merchant_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compare current transaction activity against the merchant's
    historical activity.
    """

    df = df.copy()

    merchant_stats = (
        df.groupby("merchant_id")
        .agg(
            merchant_avg_amount=("transaction_amount", "mean"),
            merchant_std_amount=("transaction_amount", "std"),
            merchant_avg_velocity=("merchant_velocity_15min", "mean"),
        )
        .reset_index()
    )

    df = df.merge(
        merchant_stats,
        on="merchant_id",
        how="left",
    )

    df["merchant_std_amount"] = (
        df["merchant_std_amount"]
        .fillna(0)
        .replace(0, 1)
    )

    df["merchant_amount_deviation"] = (
        (
            df["transaction_amount"]
            - df["merchant_avg_amount"]
        ).abs()
        / df["merchant_std_amount"]
    )

    df["merchant_velocity_deviation"] = (
        df["merchant_velocity_15min"]
        / df["merchant_avg_velocity"].replace(0, 1)
    )

    return df


# ---------------------------------------------------------------------
# Device baseline
# ---------------------------------------------------------------------

def add_device_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compare device behavior against its normal behavior.
    """

    df = df.copy()

    device_stats = (
        df.groupby("device_id")
        .agg(
            device_avg_amount=("transaction_amount", "mean"),
            device_std_amount=("transaction_amount", "std"),
            device_avg_burst=("burst_count_5min", "mean"),
        )
        .reset_index()
    )

    df = df.merge(
        device_stats,
        on="device_id",
        how="left",
    )

    df["device_std_amount"] = (
        df["device_std_amount"]
        .fillna(0)
        .replace(0, 1)
    )

    df["device_amount_deviation"] = (
        (
            df["transaction_amount"]
            - df["device_avg_amount"]
        ).abs()
        / df["device_std_amount"]
    )

    df["device_burst_deviation"] = (
        df["burst_count_5min"]
        / df["device_avg_burst"].replace(0, 1)
    )

    return df


# ---------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------

def run_isolation_forest(
    df: pd.DataFrame,
    contamination: float,
) -> pd.DataFrame:

    df = df.copy()

    feature_cols = FEATURES + [
        "burst_count_5min",
        "velocity_15min",
        "merchant_velocity_15min",
        "device_count_1h",
        "device_count_6h",
        "device_count_24h",
    ]

    X = df[feature_cols].replace(
        [np.inf, -np.inf],
        np.nan,
    ).fillna(0)

    model = IsolationForest(
        n_estimators=250,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )

    df["anomaly_score"] = model.fit_predict(X)

    # Lower = more anomalous
    df["anomaly_raw_score"] = model.decision_function(X)

    # Convert anomaly score into approximately 0-100 risk signal.
    raw = df["anomaly_raw_score"]

    low = raw.quantile(0.01)
    high = raw.quantile(0.99)

    if high == low:
        df["anomaly_risk"] = 50.0
    else:
        df["anomaly_risk"] = (
            100
            * (high - raw)
            / (high - low)
        ).clip(0, 100)

    return df


# ---------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------

def calculate_risk_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Combine multiple independent signals into one explainable
    0-100 transaction risk score.

    This is a prioritization score, not a probability of fraud.
    """

    df = df.copy()

    score = (
        0.35 * df["anomaly_risk"]
        + 0.15 * np.clip(
            df["burst_count_5min"] * 10,
            0,
            100,
        )
        + 0.10 * np.clip(
            df["velocity_15min"] * 5,
            0,
            100,
        )
        + 0.10 * np.clip(
            df["merchant_velocity_deviation"] * 25,
            0,
            100,
        )
        + 0.10 * np.clip(
            df["device_burst_deviation"] * 25,
            0,
            100,
        )
        + 0.10 * np.clip(
            df["merchant_amount_deviation"] * 15,
            0,
            100,
        )
        + 0.10 * np.clip(
            df["device_amount_deviation"] * 15,
            0,
            100,
        )
    )

    # Strong signal when IP consistency is broken.
    score += np.where(
        df["ip_consistency_flag"] == 0,
        10,
        0,
    )

    df["risk_score"] = score.clip(0, 100).round(2)

    # -----------------------------------------------------------------
    # Priority
    # -----------------------------------------------------------------

    df["risk_priority"] = pd.cut(
        df["risk_score"],
        bins=[-1, 30, 60, 80, 101],
        labels=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ],
    )

    return df


# ---------------------------------------------------------------------
# Upgrade #2 — Adaptive merchant threshold
# ---------------------------------------------------------------------

def add_adaptive_merchant_threshold(df: pd.DataFrame, k: float = 2.0) -> pd.DataFrame:
    """
    Instead of one fixed global cutoff for every merchant, each merchant
    gets its own flagging bar based on its OWN historical risk-score
    volatility: mean + k * std.

    Why this matters: a merchant whose transactions are naturally quite
    varied (electronics, travel — inherently high, spiky amounts) needs a
    bigger deviation before something looks abnormal FOR THEM. A quiet,
    low-variance merchant (a small kirana store with very consistent
    small transactions) should be flagged on a much smaller deviation,
    because for them even a modest spike is genuinely out of pattern.
    A single global threshold treats both merchants identically and
    either misses the quiet merchant's real anomalies or drowns in false
    positives from the naturally volatile one.
    """

    df = df.copy()

    merchant_risk_stats = (
        df.groupby("merchant_id")["risk_score"]
        .agg(merchant_risk_mean="mean", merchant_risk_std="std")
        .reset_index()
    )
    merchant_risk_stats["merchant_risk_std"] = (
        merchant_risk_stats["merchant_risk_std"].fillna(0).replace(0, 5)
    )

    df = df.merge(merchant_risk_stats, on="merchant_id", how="left")

    df["merchant_adaptive_threshold"] = (
        df["merchant_risk_mean"] + k * df["merchant_risk_std"]
    ).clip(upper=95)

    df["merchant_adaptive_flag"] = (
        df["risk_score"] > df["merchant_adaptive_threshold"]
    )

    return df


# ---------------------------------------------------------------------
# Explainable evidence
# ---------------------------------------------------------------------

def build_risk_reasons(row):
    """Generate human-readable evidence for the AI agent/risk analyst."""

    reasons = []

    if row["anomaly_score"] == -1:
        reasons.append("Isolation Forest anomaly")

    if row["burst_count_5min"] >= 5:
        reasons.append(
            f"high transaction burst ({int(row['burst_count_5min'])} in 5 min)"
        )

    if row["velocity_15min"] >= 10:
        reasons.append(
            f"high device velocity ({int(row['velocity_15min'])} in 15 min)"
        )

    if row["merchant_velocity_deviation"] >= 2:
        reasons.append(
            "merchant activity above its normal baseline"
        )

    if row["device_burst_deviation"] >= 2:
        reasons.append(
            "device burst rate above its normal baseline"
        )

    if row["merchant_amount_deviation"] >= 2:
        reasons.append(
            "transaction amount unusual for merchant"
        )

    if row["device_amount_deviation"] >= 2:
        reasons.append(
            "transaction amount unusual for device"
        )

    if row["retry_count"] >= 5:
        reasons.append(
            f"high retry count ({int(row['retry_count'])})"
        )

    if row["last_ping_gap_sec"] >= 8:
        reasons.append(
            "unusual device ping gap"
        )

    if row["ip_consistency_flag"] == 0:
        reasons.append(
            "IP consistency mismatch"
        )

    if not reasons:
        reasons.append("No strong risk signals detected")

    return "; ".join(reasons)


# ---------------------------------------------------------------------
# Incident clustering
# ---------------------------------------------------------------------

def assign_incidents(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group high-risk events by merchant/device so the risk team can
    investigate incidents rather than isolated transactions.
    """

    df = df.copy()

    df["incident_id"] = "NONE"

    high_risk = df["risk_score"] >= 60

    keys = (
        df.loc[high_risk, "merchant_id"].astype(str)
        + "-"
        + df.loc[high_risk, "device_id"].astype(str)
    )

    mapping = {}

    counter = 1

    for key in keys.unique():
        mapping[key] = f"INC-{counter:04d}"
        counter += 1

    df.loc[high_risk, "incident_id"] = keys.map(mapping)

    df["investigation_priority"] = np.select(
        [
            df["risk_score"] >= 80,
            df["risk_score"] >= 60,
            df["risk_score"] >= 30,
        ],
        [
            "P0 — Immediate",
            "P1 — Investigate",
            "P2 — Monitor",
        ],
        default="P3 — Low",
    )

    return df


# ---------------------------------------------------------------------
# Main scoring pipeline
# ---------------------------------------------------------------------

def score(
    in_path: str,
    out_path: str,
    contamination: float = 0.05,
):

    print("\n" + "=" * 65)
    print("FRAUD-SPIKE DETECTOR — ADVANCED DETECTION")
    print("=" * 65)

    df = pd.read_csv(in_path)

    print(f"Loaded {len(df):,} transactions.")

    # 1. Clean
    df = prepare_data(df)

    # 2. Temporal signals
    print("→ Calculating temporal velocity signals...")
    df = add_temporal_features(df)

    # 3. Merchant baseline
    print("→ Calculating merchant baselines...")
    df = add_merchant_baseline(df)

    # 4. Device baseline
    print("→ Calculating device baselines...")
    df = add_device_baseline(df)

    # 5. Isolation Forest
    print("→ Running Isolation Forest...")
    df = run_isolation_forest(
        df,
        contamination,
    )

    # 6. Combined risk score
    print("→ Calculating explainable risk scores...")
    df = calculate_risk_score(df)

    # 6b. Adaptive per-merchant threshold (Upgrade #2)
    print("→ Applying adaptive merchant thresholds...")
    df = add_adaptive_merchant_threshold(df)

    # 7. Explainability
    print("→ Generating risk evidence...")
    df["risk_reasons"] = df.apply(
        build_risk_reasons,
        axis=1,
    )

    # 8. Incident grouping
    print("→ Grouping related high-risk events...")
    df = assign_incidents(df)

    # -----------------------------------------------------------------
    # Flag candidates
    # -----------------------------------------------------------------

    flagged = df[
        (df["anomaly_score"] == -1)
        | (df["risk_score"] >= 60)
        | (df["merchant_adaptive_flag"])
    ].copy()

    flagged = flagged.sort_values(
        ["risk_score", "anomaly_raw_score"],
        ascending=[False, True],
    )

    # -----------------------------------------------------------------
    # Console metrics
    # -----------------------------------------------------------------

    print("\n" + "-" * 65)
    print("DETECTION SUMMARY")
    print("-" * 65)

    print(f"Total transactions : {len(df):,}")
    print(f"Flagged candidates : {len(flagged):,}")
    print(
        f"Flag rate          : "
        f"{len(flagged) / max(1, len(df)):.2%}"
    )

    print(
        f"Critical           : "
        f"{(df['risk_priority'] == 'CRITICAL').sum():,}"
    )

    print(
        f"High               : "
        f"{(df['risk_priority'] == 'HIGH').sum():,}"
    )

    print(
        f"Incidents          : "
        f"{df.loc[df['incident_id'] != 'NONE', 'incident_id'].nunique():,}"
    )

    # -----------------------------------------------------------------
    # Ground truth evaluation
    # -----------------------------------------------------------------

    if "label" in df.columns:

        labels = df["label"].astype(str).str.lower()

        true_fraud = df[labels == "fraud"]

        flagged_labels = flagged["label"].astype(str).str.lower()

        caught = flagged[flagged_labels == "fraud"]

        false_positives = len(flagged) - len(caught)

        recall = (
            len(caught)
            / max(1, len(true_fraud))
        )

        precision = (
            len(caught)
            / max(1, len(flagged))
        )

        print("\nGROUND TRUTH EVALUATION")
        print("-" * 65)

        print(f"Actual fraud        : {len(true_fraud):,}")
        print(f"Fraud caught        : {len(caught):,}")
        print(f"Recall              : {recall:.2%}")
        print(f"Precision           : {precision:.2%}")
        print(f"False positives     : {false_positives:,}")

    # -----------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------

    flagged.to_csv(
        out_path,
        index=False,
    )

    print("\n" + "=" * 65)
    print(f"Wrote {len(flagged):,} candidates → {out_path}")
    print("=" * 65 + "\n")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

if __name__ == "__main__":

    # The default Windows console (cp1252) cannot encode characters used
    # in the summary output (→, ₹) and would crash mid-print — force
    # UTF-8 output so the CLI runs unchanged on any platform.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--in",
        dest="in_path",
        type=str,
        default="../data/transactions.csv",
    )

    parser.add_argument(
        "--out",
        dest="out_path",
        type=str,
        default="flagged_events.csv",
    )

    def _configured_contamination_default():
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                return float(cfg.get("contamination", 0.05))
            except (json.JSONDecodeError, OSError, ValueError):
                pass
        return 0.05

    parser.add_argument(
        "--contamination",
        type=float,
        default=_configured_contamination_default(),
        help="Default is read from config.json (Settings tab) if present.",
    )

    args = parser.parse_args()

    score(
        args.in_path,
        args.out_path,
        args.contamination,
    )