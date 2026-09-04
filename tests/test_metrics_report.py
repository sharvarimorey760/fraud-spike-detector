"""
Tests for audit_log.metrics_report — decision metrics + impact simulator.

Run from the project root:
    pytest tests/test_metrics_report.py
"""

import json
import os
import tempfile
import unittest

from audit_log.metrics_report import (
    confusion_counts,
    load_entries,
    load_ground_truth,
    metrics_at_cutoff,
)


def _entry(tid, action, confidence, review=True):
    return {
        "logged_at": "2026-09-01T00:00:00+00:00",
        "transaction_id": tid,
        "decision": {
            "recommended_action": action,
            "confidence": confidence,
            "human_review_required": review,
        },
    }


def _write_jsonl(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


class ConfusionCountsTest(unittest.TestCase):
    def test_counts_tp_fp_tn_fn(self):
        entries = [
            _entry("T1", "flag_for_review", 0.9),  # fraud, flagged -> TP
            _entry("T2", "dismiss", 0.9),           # normal, dismissed -> TN
            _entry("T3", "soft_hold", 0.9),         # normal, flagged -> FP
            _entry("T4", "dismiss", 0.9),           # fraud, dismissed -> FN
        ]
        ground_truth = {"T1": True, "T2": False, "T3": False, "T4": True}

        tp, fp, tn, fn, reviewed = confusion_counts(entries, ground_truth)
        self.assertEqual((tp, fp, tn, fn), (1, 1, 1, 1))
        self.assertEqual(reviewed, 4)

    def test_confidence_cutoff_filters_predictions(self):
        entries = [
            _entry("T1", "flag_for_review", 0.9),
            _entry("T2", "flag_for_review", 0.4),
        ]
        ground_truth = {"T1": True, "T2": True}

        tp_high, _, _, _, _ = confusion_counts(entries, ground_truth, cutoff=0.7)
        tp_low, _, _, _, _ = confusion_counts(entries, ground_truth, cutoff=0.0)
        self.assertEqual(tp_high, 1)
        self.assertEqual(tp_low, 2)

    def test_unmatched_transactions_are_skipped(self):
        entries = [_entry("T1", "flag_for_review", 0.9)]
        tp, fp, tn, fn, _ = confusion_counts(entries, {})
        self.assertEqual((tp, fp, tn, fn), (0, 0, 0, 0))


class MetricsAtCutoffTest(unittest.TestCase):
    def test_perfect_precision_recall(self):
        entries = [
            _entry("T1", "flag_for_review", 0.9),
            _entry("T2", "dismiss", 0.9),
        ]
        ground_truth = {"T1": True, "T2": False}

        m = metrics_at_cutoff(entries, ground_truth, 0.0, 50, 500, 20)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1"], 1.0)
        self.assertEqual(m["total_cost"], 2 * 20)  # two reviews, nothing else

    def test_cost_accounts_for_fp_and_fn(self):
        entries = [
            _entry("T1", "flag_for_review", 0.9),  # normal -> FP
            _entry("T2", "dismiss", 0.9),           # fraud -> FN
        ]
        ground_truth = {"T1": False, "T2": True}

        m = metrics_at_cutoff(entries, ground_truth, 0.0, 50, 500, 20)
        self.assertEqual(m["total_cost"], 50 + 500 + 40)


class LoadersTest(unittest.TestCase):
    def test_load_entries_skips_blank_lines(self):
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write(json.dumps(_entry("T1", "dismiss", 0.5)) + "\n\n")
            path = f.name
        try:
            entries = load_entries(log_path=path)
            self.assertEqual(len(entries), 1)
        finally:
            os.unlink(path)

    def test_load_ground_truth_from_csv(self):
        with tempfile.NamedTemporaryFile(
            suffix=".csv", delete=False, mode="w", encoding="utf-8", newline=""
        ) as f:
            f.write("transaction_id,label\nT1,fraud\nT2,normal\n")
            path = f.name
        try:
            gt = load_ground_truth(path)
            self.assertEqual(gt, {"T1": True, "T2": False})
        finally:
            os.unlink(path)

    def test_load_ground_truth_missing_file(self):
        self.assertEqual(load_ground_truth("/nonexistent/nope.csv"), {})


if __name__ == "__main__":
    unittest.main()