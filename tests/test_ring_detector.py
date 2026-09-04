"""
Tests for detection.ring_detector — abuse-ring / community detection.

Run from the project root:
    pytest tests/test_ring_detector.py
"""

import unittest

import pandas as pd

from detection.ring_detector import (
    add_ring_features,
    build_device_graph,
    detect_communities,
    score_communities,
)


def _make_frame():
    """3 co-located bursty devices (a ring) + 3 isolated quiet devices."""
    rows = []
    for dev, city, fw, burst, t0 in [
        ("POS-R1", "Delhi", "v2.1.1", 12.0, "2026-08-01T00:00:00"),
        ("POS-R2", "Delhi", "v2.1.1", 11.0, "2026-08-01T00:05:00"),
        ("POS-R3", "Delhi", "v2.1.1", 9.0, "2026-08-01T00:10:00"),
        ("POS-N1", "Pune", "v2.0.0", 1.0, "2026-08-01T01:00:00"),
        ("POS-N2", "Mumbai", "v2.0.0", 1.0, "2026-08-01T02:00:00"),
        ("POS-N3", "Kolkata", "v2.0.0", 1.0, "2026-08-01T03:00:00"),
    ]:
        rows.append(
            {
                "device_id": dev,
                "geo_city": city,
                "firmware_version": fw,
                "burst_count_5min": burst,
                "velocity_15min": burst,
                "timestamp": t0,
            }
        )
    return pd.DataFrame(rows)


class RingDetectorTest(unittest.TestCase):
    def test_build_device_graph_connects_co_located_devices(self):
        df = _make_frame()
        graph = build_device_graph(df)

        self.assertTrue(graph.has_edge("POS-R1", "POS-R2"))
        # Different cities / firmware should not connect.
        self.assertFalse(graph.has_edge("POS-R1", "POS-N1"))
        self.assertFalse(graph.has_edge("POS-N1", "POS-N2"))

    def test_detect_communities_finds_the_ring(self):
        df = _make_frame()
        communities = detect_communities(build_device_graph(df))

        found = any(
            set(community) == {"POS-R1", "POS-R2", "POS-R3"}
            for community in communities
        )
        self.assertTrue(found, f"expected ring community, got {communities}")

    def test_score_communities_ranks_ring_above_isolated(self):
        df = _make_frame()
        communities = detect_communities(build_device_graph(df))
        scores = score_communities(df, communities)

        ring_score = scores.loc[
            scores["device_id"] == "POS-R1", "ring_score"
        ].iloc[0]
        self.assertGreater(ring_score, 40)

    def test_add_ring_features_wires_columns_into_frame(self):
        df = add_ring_features(_make_frame())

        ring_rows = df[df["device_id"].str.startswith("POS-R")]
        isolated_rows = df[df["device_id"].str.startswith("POS-N")]

        self.assertTrue((ring_rows["ring_score"] > 40).all())
        self.assertEqual((ring_rows["ring_size"] == 3).all(), True)
        self.assertEqual((isolated_rows["ring_score"] == 0).all(), True)
        self.assertEqual((isolated_rows["ring_size"] == 0).all(), True)

    def test_add_ring_features_handles_empty_input(self):
        out = add_ring_features(pd.DataFrame())
        self.assertIn("ring_score", out.columns)
        self.assertIn("ring_community_id", out.columns)
        self.assertEqual(len(out), 0)

    def test_add_ring_features_missing_columns_does_not_crash(self):
        df = pd.DataFrame(
            {"device_id": ["A", "B", "C"], "some_other_col": [1, 2, 3]}
        )
        out = add_ring_features(df)
        self.assertEqual(len(out), 3)
        self.assertTrue((out["ring_score"] == 0).all())


if __name__ == "__main__":
    unittest.main()