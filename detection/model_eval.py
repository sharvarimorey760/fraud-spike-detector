"""
Full model evaluation for the detection layer.

Runs the anomaly-scoring pipeline on labeled data and reports what the
track brief asks for: confusion matrix, precision/recall/F1, ROC-AUC,
and a risk-score threshold sweep so the flag cutoff is a choice backed
by numbers, not a guess.

Usage:
    python detection/model_eval.py
    python detection/model_eval.py --in ../data/transactions.csv --out eval_report.md
"""

import argparse
import json
import os
import sys

# Make the project root importable when run as `python detection/model_eval.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)

from detection.anomaly_scorer import (
    add_adaptive_merchant_threshold,
    add_device_baseline,
    add_merchant_baseline,
    add_temporal_features,
    build_risk_reasons,
    calculate_risk_score,
    prepare_data,
    run_isolation_forest,
)
from detection.ring_detector import add_ring_features


def run_pipeline(df, contamination):
    df = prepare_data(df)
    df = add_temporal_features(df)
    df = add_ring_features(df)
    df = add_merchant_baseline(df)
    df = add_device_baseline(df)
    df = run_isolation_forest(df, contamination)
    df = calculate_risk_score(df)
    df = add_adaptive_merchant_threshold(df)
    df["risk_reasons"] = df.apply(build_risk_reasons, axis=1)
    return df


def evaluate(df, label_col="label"):
    """
    Full evaluation of the pipeline's risk_score against ground truth.

    Returns a dict with the confusion matrix (at the 60 flag cutoff),
    P/R/F1, ROC-AUC, and a threshold sweep table.
    """

    labels = (df[label_col].astype(str).str.lower() == "fraud").astype(int)
    scores = df["risk_score"].to_numpy()

    # --- Confusion matrix at the default flag cutoff (risk >= 60) ---
    preds = (scores >= 60).astype(int)
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )

    # --- ROC-AUC ---
    roc_auc = None
    if len(np.unique(labels)) > 1:
        roc_auc = roc_auc_score(labels, scores)
        fpr, tpr, thresholds = roc_curve(labels, scores)
    else:
        fpr, tpr, thresholds = None, None, None

    # --- Threshold sweep ---
    sweep = []
    for cutoff in range(0, 101, 5):
        p = (scores >= cutoff).astype(int)
        cmc = confusion_matrix(labels, p, labels=[0, 1]).ravel()
        pr, re, f, _ = precision_recall_fscore_support(
            labels, p, average="binary", zero_division=0
        )
        sweep.append(
            {
                "cutoff": cutoff,
                "tp": int(cmc[3]),
                "fp": int(cmc[1]),
                "fn": int(cmc[2]),
                "tn": int(cmc[0]),
                "precision": round(float(pr), 3),
                "recall": round(float(re), 3),
                "f1": round(float(f), 3),
            }
        )

    return {
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": round(float(precision), 3),
        "recall": round(float(recall), 3),
        "f1": round(float(f1), 3),
        "roc_auc": round(float(roc_auc), 3) if roc_auc is not None else None,
        "fpr": fpr,
        "tpr": tpr,
        "sweep": sweep,
    }


def format_report(df, result):
    lines = []
    lines.append("# Detection Model Evaluation")
    lines.append("")
    lines.append(f"- **Transactions evaluated:** {len(df):,}")
    lines.append(f"- **Fraud positives in data:** {int((df['label'].astype(str).str.lower() == 'fraud').sum()):,}")
    lines.append("")

    cm = result["confusion_matrix"]
    lines.append("## Confusion matrix (flag cutoff: risk_score ≥ 60)")
    lines.append("")
    lines.append("| | Predicted flag | Predicted clear |")
    lines.append("|---|---|---|")
    lines.append(f"| **Actually fraud** | {cm['tp']} (TP) | {cm['fn']} (FN) |")
    lines.append(f"| **Actually normal** | {cm['fp']} (FP) | {cm['tn']} (TN) |")
    lines.append("")
    lines.append("## Headline metrics")
    lines.append("")
    lines.append(f"- **Precision:** {result['precision']}")
    lines.append(f"- **Recall:** {result['recall']}")
    lines.append(f"- **F1:** {result['f1']}")
    lines.append(f"- **ROC-AUC:** {result['roc_auc']}")
    lines.append("")

    lines.append("## Risk-score threshold sweep")
    lines.append("")
    lines.append("| Cutoff | TP | FP | FN | Precision | Recall | F1 |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in result["sweep"]:
        lines.append(
            f"| {row['cutoff']} | {row['tp']} | {row['fp']} | {row['fn']} | "
            f"{row['precision']} | {row['recall']} | {row['f1']} |"
        )
    lines.append("")

    return "\n".join(lines)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    def _configured_contamination_default():
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    return float(json.load(f).get("contamination", 0.05))
            except (json.JSONDecodeError, OSError, ValueError):
                pass
        return 0.05

    _DEFAULT_DATA = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "data", "transactions.csv"
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--in", dest="in_path", type=str, default=_DEFAULT_DATA
    )
    parser.add_argument("--out", type=str, default=None, help="Write report to a markdown file")
    parser.add_argument("--contamination", type=float, default=_configured_contamination_default())
    args = parser.parse_args()

    df = pd.read_csv(args.in_path)
    df = run_pipeline(df, args.contamination)
    result = evaluate(df)

    report = format_report(df, result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote evaluation → {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()