"""
Decision-level metrics report + business-impact simulator.

Joins the audit log (agent decisions) with ground-truth labels from the
transactions data and answers two questions the track brief cares about:

  1. Honest metrics — how accurate were the agent's decisions?
       precision / recall / F1 / confusion matrix / false-positive cost
  2. Business impact — where is the cheapest operating point?
       sweep confidence thresholds and compute total cost
       (FP cost + FN cost + human-review cost), report the optimum.

Usage:
    python audit_log/metrics_report.py
    python audit_log/metrics_report.py --out metrics.md
    python audit_log/metrics_report.py --fp-cost 50 --fn-cost 500
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "decisions.jsonl")
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "transactions.csv")

# Actions that count as a "positive" decision (intervention).
POSITIVE_ACTIONS = {"flag_for_review", "soft_hold", "escalate"}

# Costs used by the business-impact simulator (override with flags).
DEFAULT_FP_COST = 50.0      # cost of investigating a false positive
DEFAULT_FN_COST = 500.0     # average loss of a missed fraud transaction
DEFAULT_REVIEW_COST = 20.0  # human review cost per routed decision

THRESHOLD_STEPS = 21  # sweep confidence from 0.0 to 1.0


def load_ground_truth(path=None):
    """Return {transaction_id: is_fraud(bool)} from the labeled data."""
    path = path or DATA_PATH
    if not os.path.exists(path):
        return {}
    df = pd.read_csv(path)
    if "label" not in df.columns or "transaction_id" not in df.columns:
        return {}
    df["label"] = df["label"].astype(str).str.lower()
    return dict(zip(df["transaction_id"], df["label"] == "fraud"))


def load_entries(log_path=None, since=None):
    log_path = log_path or LOG_PATH
    if not os.path.exists(log_path):
        return []
    entries = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if since and entry.get("logged_at", "") < since:
                continue
            entries.append(entry)
    return entries


def confusion_counts(entries, ground_truth, cutoff=0.0):
    """
    Classify decisions against ground truth.

    predicted positive = recommended_action in POSITIVE_ACTIONS AND
                         confidence >= cutoff. Returns
    (tp, fp, tn, fn, reviewed).
    """
    tp = fp = tn = fn = 0
    reviewed = 0
    for entry in entries:
        decision = entry.get("decision", {})
        tid = entry.get("transaction_id")
        if tid not in ground_truth:
            continue
        is_fraud = ground_truth[tid]
        action = decision.get("recommended_action")
        confidence = decision.get("confidence", 0) or 0
        predicted = action in POSITIVE_ACTIONS and confidence >= cutoff

        if decision.get("human_review_required"):
            reviewed += 1

        if predicted and is_fraud:
            tp += 1
        elif predicted and not is_fraud:
            fp += 1
        elif not predicted and not is_fraud:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn, reviewed


def metrics_at_cutoff(entries, ground_truth, cutoff, fp_cost, fn_cost, review_cost):
    tp, fp, tn, fn, reviewed = confusion_counts(entries, ground_truth, cutoff)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    total_cost = fp * fp_cost + fn * fn_cost + reviewed * review_cost
    return {
        "cutoff": cutoff,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "reviewed": reviewed,
        "total_cost": total_cost,
    }


def build_report(entries, ground_truth, fp_cost, fn_cost, review_cost):
    lines = []
    lines.append("# Fraud-Spike Detector — Decision Metrics & Business Impact")
    lines.append("")
    lines.append(
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"from {len(entries)} logged decision(s), "
        f"{len(ground_truth)} labeled transactions_"
    )
    lines.append("")

    # ---- Honest metrics at the natural cutoff (confidence >= 0) ----
    base = metrics_at_cutoff(entries, ground_truth, 0.0, fp_cost, fn_cost, review_cost)
    matched = base["tp"] + base["fp"] + base["tn"] + base["fn"]

    lines.append("## 1. Decision accuracy vs ground truth")
    lines.append("")
    lines.append(
        "> Honesty note: the audit log only contains decisions for events the "
        "detector already flagged, so these metrics measure the agent's decision "
        "quality **conditional on the detector's flags** — not end-to-end recall "
        "over all transactions. Pair this report with `detection/model_eval.py` "
        "for the full-pipeline picture."
    )
    lines.append("")
    lines.append(f"- **Decisions matched to labels:** {matched}/{len(entries)}")
    lines.append(f"- **Precision:** {base['precision']:.3f}")
    lines.append(f"- **Recall:** {base['recall']:.3f}")
    lines.append(f"- **F1:** {base['f1']:.3f}")
    lines.append("")
    lines.append("| | Predicted intervention | Predicted dismiss |")
    lines.append("|---|---|---|")
    lines.append(f"| **Actually fraud** | {base['tp']} (TP) | {base['fn']} (FN) |")
    lines.append(f"| **Actually normal** | {base['fp']} (FP) | {base['tn']} (TN) |")
    lines.append("")
    lines.append(
        f"- **False-positive cost** (at {fp_cost:g} per FP): "
        f"₹{base['fp'] * fp_cost:,.0f}"
    )
    lines.append(
        f"- **Missed-fraud cost** (at {fn_cost:g} per FN): "
        f"₹{base['fn'] * fn_cost:,.0f}"
    )
    lines.append(
        f"- **Review cost** (at {review_cost:g} per review): "
        f"₹{base['reviewed'] * review_cost:,.0f}"
    )
    lines.append(f"- **Total cost:** ₹{base['total_cost']:,.0f}")
    lines.append("")

    # ---- Business-impact simulator ----
    lines.append("## 2. Business-impact simulator")
    lines.append("")
    lines.append(
        f"_Total cost = FP×{fp_cost:g} + FN×{fn_cost:g} + reviews×{review_cost:g}; "
        "sweep confidence cutoff for acting on a decision._"
    )
    lines.append("")

    rows = []
    for i in range(THRESHOLD_STEPS + 1):
        cutoff = round(i / THRESHOLD_STEPS, 2)
        rows.append(
            metrics_at_cutoff(entries, ground_truth, cutoff, fp_cost, fn_cost, review_cost)
        )

    best = min(rows, key=lambda r: r["total_cost"])

    lines.append("| Conf. cutoff | TP | FP | FN | Precision | Recall | Total cost |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in rows:
        marker = " ⭐" if r is best else ""
        lines.append(
            f"| {r['cutoff']:.2f} | {r['tp']} | {r['fp']} | {r['fn']} | "
            f"{r['precision']:.2f} | {r['recall']:.2f} | ₹{r['total_cost']:,.0f}{marker} |"
        )
    lines.append("")
    lines.append(
        f"**Optimal confidence cutoff: {best['cutoff']:.2f}** "
        f"(total cost ₹{best['total_cost']:,.0f})"
    )
    lines.append("")

    return "\n".join(lines)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=str, default=None, help="Write report to a file")
    parser.add_argument("--since", type=str, default=None, help="Only entries after this ISO timestamp")
    parser.add_argument("--data", type=str, default=None, help="Labeled transactions CSV (ground truth)")
    parser.add_argument("--fp-cost", type=float, default=DEFAULT_FP_COST, help="Cost per false positive")
    parser.add_argument("--fn-cost", type=float, default=DEFAULT_FN_COST, help="Cost per missed fraud")
    parser.add_argument("--review-cost", type=float, default=DEFAULT_REVIEW_COST, help="Cost per human review")
    args = parser.parse_args()

    entries = load_entries(since=args.since)
    ground_truth = load_ground_truth(args.data)
    report = build_report(
        entries,
        ground_truth,
        args.fp_cost,
        args.fn_cost,
        args.review_cost,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote metrics report ({len(entries)} decisions) → {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()