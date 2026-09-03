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

def add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate transaction velocity for each device and merchant.

    These features help detect:
      - card testing bursts
      - sudden merchant activity
      - compromised terminals
    """

    df = df.copy()

    df = df.sort_values("timestamp")

    # Device-level velocity
    device_groups = df.set_index("timestamp").groupby("device_id")

    df["burst_count_5min"] = (
        device_groups["transaction_amount"]
        .rolling("5min")
        .count()
        .reset_index(level=0, drop=True)
        .reindex(df.set_index("timestamp").index)
        .values
    )

    # The operation above can become difficult to align when timestamps
    # repeat, so calculate using a robust per-device rolling approach.
    df["burst_count_5min"] = 1.0

    for device_id, indices in df.groupby("device_id").groups.items():
        group = df.loc[indices].sort_values("timestamp")

        timestamps = group["timestamp"]
        counts = []

        for current_time in timestamps:
            start_time = current_time - pd.Timedelta(minutes=5)
            count = (
                (timestamps >= start_time)
                & (timestamps <= current_time)
            ).sum()

            counts.append(count)

        df.loc[group.index, "burst_count_5min"] = counts

    # 15-minute device velocity
    df["velocity_15min"] = 1.0

    for device_id, indices in df.groupby("device_id").groups.items():
        group = df.loc[indices].sort_values("timestamp")
        timestamps = group["timestamp"]

        counts = []

        for current_time in timestamps:
            start_time = current_time - pd.Timedelta(minutes=15)

            count = (
                (timestamps >= start_time)
                & (timestamps <= current_time)
            ).sum()

            counts.append(count)

        df.loc[group.index, "velocity_15min"] = counts

    # Merchant 15-minute velocity
    df["merchant_velocity_15min"] = 1.0

    for merchant_id, indices in df.groupby("merchant_id").groups.items():
        group = df.loc[indices].sort_values("timestamp")
        timestamps = group["timestamp"]

        counts = []

        for current_time in timestamps:
            start_time = current_time - pd.Timedelta(minutes=15)

            count = (
                (timestamps >= start_time)
                & (timestamps <= current_time)
            ).sum()

            counts.append(count)

        df.loc[group.index, "merchant_velocity_15min"] = counts

    # -------------------------------------------------------------
    # Multi-window device velocity: 1h / 6h / 24h
    #
    # A single 5-min burst window catches fast card-testing attacks
    # but misses slower-moving abuse — a device making an unusual
    # number of transactions spread over several hours never trips a
    # 5-min threshold but can still be well outside its own normal
    # pattern. These wider windows catch that.
    # -------------------------------------------------------------
    for label, minutes in [("1h", 60), ("6h", 360), ("24h", 1440)]:
        col = f"device_count_{label}"
        df[col] = 1.0

        for device_id, indices in df.groupby("device_id").groups.items():
            group = df.loc[indices].sort_values("timestamp")
            timestamps = group["timestamp"]
            counts = []

            for current_time in timestamps:
                start_time = current_time - pd.Timedelta(minutes=minutes)
                count = (
                    (timestamps >= start_time)
                    & (timestamps <= current_time)
                ).sum()
                counts.append(count)

            df.loc[group.index, col] = counts

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