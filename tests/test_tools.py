"""
Tests for agent.tools — investigation tool layer.

Run from the project root:
    pytest
    # or: python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest

import pandas as pd

from agent import tools


def _write_dataset(df):
    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    df.to_csv(tmp.name, index=False)
    tmp.close()
    return tmp.name


BASE_DF = pd.DataFrame({
    "merchant_id": ["M-1"] * 3,
    "device_id": ["D-1", "D-2", "D-3"],
    "timestamp": pd.to_datetime(
        ["2025-01-01 10:00:00", "2025-01-01 10:10:00", "2025-01-01 10:20:00"],
        utc=True,
    ),
    "retry_count": [9, 1, 2],
    "last_ping_gap_sec": [2, 1, 1],
})


class GetMerchantDeviceNetworkTest(unittest.TestCase):
    def tearDown(self):
        for path in getattr(self, "_tmp_paths", []):
            os.unlink(path)

    def _load(self, df):
        path = _write_dataset(df)
        self._tmp_paths = getattr(self, "_tmp_paths", []) + [path]
        tools.load_dataset(path)

    def test_missing_ip_consistency_flag_column_does_not_crash(self):
        # Regression: rows.get("ip_consistency_flag", 1).fillna(1) crashed
        # with AttributeError when the column was absent (schema drift).
        self._load(BASE_DF)
        result = tools.get_merchant_device_network(
            "M-1", "D-1", "2025-01-01 10:20:00"
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["other_devices_checked"], 2)

    def test_ip_inconsistency_detected_when_column_present(self):
        df = BASE_DF.copy()
        df["ip_consistency_flag"] = [1, 0, 1]  # D-2 flagged inconsistent
        self._load(df)
        result = tools.get_merchant_device_network(
            "M-1", "D-1", "2025-01-01 10:20:00"
        )
        self.assertEqual(result["suspicious_device_count"], 1)
        self.assertIn("D-2", result["devices_with_elevated_telemetry"])


class ToolSchemaTest(unittest.TestCase):
    def test_similar_cases_enum_covers_all_prompt_fraud_types(self):
        # The agent prompt reasons about 8 fraud types; the tool schema must
        # accept all of them or Gemini calls for the missing ones fail.
        schema = {t["name"]: t for t in tools.TOOL_SCHEMA}
        enum = schema["get_similar_past_cases"]["parameters"]["properties"][
            "fraud_type_hint"
        ]["enum"]
        self.assertEqual(
            set(enum),
            {
                "card_testing",
                "device_spoof",
                "bust_out",
                "retry_storm",
                "velocity_attack",
                "coordinated_fraud",
                "unusual_behavior",
                "unclear",
            },
        )


if __name__ == "__main__":
    unittest.main()