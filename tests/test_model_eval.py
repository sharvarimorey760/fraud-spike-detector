"""
Tests for detection.model_eval — confusion matrix, ROC-AUC, threshold sweep.

Run from the project root:
    pytest tests/test_model_eval.py
"""

import unittest

import numpy as np
import pandas as pd

from detection.model_eval import evaluate, format_report, run_pipeline


def _make_labeled_frame(n=200, seed=42):
    """Synthetic labeled data: high-risk transactions are mostly fraud.

    Devices come in two clusters (2 cities x 2 firmware versions); fraud
    is concentrated in one city/firmware group so both the ring detector
    and the scorer find signal.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        cluster = i % 4  # 0: Delhi/v2.1, 1: Delhi/v2.2, 2: Pune/v2.1, 3: Pune/v2.2
        city = "Delhi" if cluster in (0, 1) else "Pune"
        fw = "v2.1.1" if cluster in (0, 2) else "v2.2.0"
        fraud = cluster == 0  # fraud concentrated in Delhi/v2.1
        rows.append(
            {
                "transaction_id": f"T{i}",
                "device_id": f"POS-{i % 12}",
                "merchant_id": f"MER-{i % 12}",
                "timestamp": pd.Timestamp("2026-08-01") + pd.Timedelta(minutes=i * 7),
                "transaction_amount": float(rng.uniform(3000, 6000) if fraud else rng.uniform(50, 800)),
                "retry_count": int(rng.integers(8, 15) if fraud else rng.integers(0, 2)),
                "device_uptime_hrs": float(rng.uniform(1, 5) if fraud else rng.uniform(100, 400)),
                "firmware_version": fw,
                "last_ping_gap_sec": float(rng.uniform(8, 20) if fraud else rng.uniform(0, 3)),
                "geo_city": city,
                "geo_lat": float(rng.uniform(10, 30)),
                "geo_lon": float(rng.uniform(70, 90)),
                "ip_consistency_flag": int(0 if fraud else 1),
                "label": "fraud" if fraud else "normal",
            }
        )
    return pd.DataFrame(rows)


class ModelEvalTest(unittest.TestCase):
    def test_run_pipeline_adds_ring_and_risk_columns(self):
        df = run_pipeline(_make_labeled_frame(), contamination=0.1)
        for col in ["ring_score", "risk_score", "anomaly_score", "risk_reasons"]:
            self.assertIn(col, df.columns)
        self.assertTrue((df["risk_score"].between(0, 100)).all())

    def test_evaluate_returns_confusion_and_roc(self):
        df = run_pipeline(_make_labeled_frame(), contamination=0.1)
        result = evaluate(df)

        cm = result["confusion_matrix"]
        self.assertEqual(
            set(cm), {"tn", "fp", "fn", "tp"},
        )
        self.assertEqual(cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"], len(df))
        self.assertIsNotNone(result["roc_auc"])
        self.assertGreater(result["roc_auc"], 0.5)
        self.assertTrue(0 <= result["precision"] <= 1)
        self.assertTrue(0 <= result["recall"] <= 1)

    def test_threshold_sweep_is_monotonic_in_recall(self):
        df = run_pipeline(_make_labeled_frame(), contamination=0.1)
        result = evaluate(df)

        recalls = [row["recall"] for row in result["sweep"]]
        self.assertEqual(recalls, sorted(recalls, reverse=True))
        self.assertEqual(result["sweep"][0]["cutoff"], 0)
        self.assertEqual(result["sweep"][-1]["cutoff"], 100)

    def test_format_report_contains_headline_numbers(self):
        df = run_pipeline(_make_labeled_frame(), contamination=0.1)
        report = format_report(df, evaluate(df))
        self.assertIn("Confusion matrix", report)
        self.assertIn("ROC-AUC", report)
        self.assertIn("Risk-score threshold sweep", report)


if __name__ == "__main__":
    unittest.main()