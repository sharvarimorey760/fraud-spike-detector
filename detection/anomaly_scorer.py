"""
Detection layer: flags statistically anomalous transactions using an
Isolation Forest over device-telemetry features (retry_count, ping gap,
uptime, amount) plus a per-device burst-rate feature computed with pandas.

This layer is intentionally simple and explainable — it is NOT the
"AI" the project is graded on. Its only job is to cheaply surface
candidate events for the agent (in agent/agent_loop.py) to actually
reason about. Keeping detection separate from reasoning keeps costs
down (you don't want an LLM call per transaction) and keeps the
anomaly step auditable on its own.

Usage:
    python anomaly_scorer.py --in ../data/transactions.csv --out flagged_events.csv
"""

import argparse
import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURES = [
    "transaction_amount",
    "retry_count",
    "device_uptime_hrs",
    "last_ping_gap_sec",
    "ip_consistency_flag",
]


def add_burst_feature(df: pd.DataFrame) -> pd.DataFrame:
    """Count transactions per device in a trailing 5-minute window —
    this is what catches card_testing bursts."""
    df = df.sort_values("timestamp").copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.set_index("timestamp")

    burst_counts = []
    for device_id, group in df.groupby("device_id"):
        counts = group["transaction_amount"].rolling("5min").count()
        burst_counts.append(counts)
    df["burst_count_5min"] = pd.concat(burst_counts).sort_index()
    df = df.reset_index()
    return df


def score(in_path: str, out_path: str, contamination: float = 0.05):
    df = pd.read_csv(in_path)
    df = add_burst_feature(df)

    feature_cols = FEATURES + ["burst_count_5min"]
    X = df[feature_cols].fillna(0)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    df["anomaly_score"] = model.fit_predict(X)          # -1 = anomaly, 1 = normal
    df["anomaly_raw_score"] = model.decision_function(X)  # lower = more anomalous

    flagged = df[df["anomaly_score"] == -1].sort_values("anomaly_raw_score")

    print(f"Scored {len(df)} transactions.")
    print(f"Flagged {len(flagged)} as anomalous ({len(flagged)/len(df):.1%}).")
    if "label" in df.columns:
        true_fraud = df[df["label"] == "fraud"]
        caught = flagged[flagged["label"] == "fraud"]
        print(f"Ground truth: {len(true_fraud)} actual fraud rows exist. "
              f"Detector caught {len(caught)} of them "
              f"({len(caught)/max(1,len(true_fraud)):.1%} recall on this run). "
              f"False positives in flagged set: {len(flagged) - len(caught)}.")

    flagged.to_csv(out_path, index=False)
    print(f"Wrote flagged events to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", type=str, default="../data/transactions.csv")
    parser.add_argument("--out", dest="out_path", type=str, default="flagged_events.csv")
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    score(args.in_path, args.out_path, args.contamination)
