"""
Tests for guardrails.alert_cooldown — real-time alert & incident cooldown engine.

Run from the project root:
    pytest
    # or: python -m unittest discover -s tests -t . -v
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from guardrails.alert_cooldown import apply_cooldown, cooldown_minutes


def make_event(device_id="D-1001", merchant_id="M-42", amount=5000.0):
    return {
        "device_id": device_id,
        "merchant_id": merchant_id,
        "transaction_amount": amount,
    }


def make_decision(action="escalate"):
    return {"recommended_action": action}


def iso_minutes_ago(minutes):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


class ApplyCooldownTest(unittest.TestCase):
    def setUp(self):
        # Isolate state I/O and config per test: no touching the real
        # audit_log/alert_state.json or config.json.
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = os.path.join(self.tmp.name, "alert_state.json")
        patcher = mock.patch("guardrails.alert_cooldown.STATE_PATH", self.state_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        config_patcher = mock.patch(
            "guardrails.alert_cooldown._load_config", return_value={}
        )
        self.mock_load_config = config_patcher.start()
        self.addCleanup(config_patcher.stop)

    def _write_state(self, state):
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(state, f)

    def _load_state(self):
        with open(self.state_path, encoding="utf-8") as f:
            return json.load(f)

    def test_non_strong_action_is_standard_and_writes_no_state(self):
        decision = apply_cooldown(make_decision("dismiss"), make_event())
        self.assertEqual(decision["alert_status"], "standard")
        self.assertFalse(os.path.exists(self.state_path))

    def test_fresh_escalate_fires_and_records_state(self):
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=5000.0))
        self.assertEqual(decision["alert_status"], "fired")
        self.assertEqual(decision["recommended_action"], "escalate")
        self.assertIn("dispatched", decision["alert_cooldown_note"])
        entry = self._load_state()["D-1001|M-42"]
        self.assertEqual(entry["last_action"], "escalate")
        self.assertEqual(entry["suppressed_count"], 0)
        self.assertEqual(entry["total_amount_inr"], 5000.0)

    def test_duplicate_within_cooldown_suppressed(self):
        apply_cooldown(make_decision("escalate"), make_event(amount=5000.0))
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=7000.0))
        self.assertEqual(decision["alert_status"], "suppressed_duplicate")
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertIn("Suppressed duplicate #1", decision["alert_cooldown_note"])
        entry = self._load_state()["D-1001|M-42"]
        self.assertEqual(entry["suppressed_count"], 1)
        self.assertEqual(entry["total_amount_inr"], 12000.0)

    def test_same_severity_does_not_break_cooldown(self):
        apply_cooldown(make_decision("escalate"), make_event())
        decision = apply_cooldown(make_decision("escalate"), make_event())
        self.assertEqual(decision["alert_status"], "suppressed_duplicate")

    def test_severity_escalation_breaks_cooldown(self):
        # soft_hold fired, then escalate arrives inside the cooldown window.
        # The severity bump (soft_hold -> escalate) must fire, not suppress.
        apply_cooldown(make_decision("soft_hold"), make_event())
        decision = apply_cooldown(make_decision("escalate"), make_event())
        self.assertEqual(decision["alert_status"], "fired")
        self.assertEqual(decision["recommended_action"], "escalate")
        self.assertIn("dispatched", decision["alert_cooldown_note"])

    def test_escalation_carries_suppressed_history_forward(self):
        apply_cooldown(make_decision("soft_hold"), make_event(amount=1000.0))
        apply_cooldown(make_decision("soft_hold"), make_event(amount=2000.0))  # suppressed
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=3000.0))
        self.assertEqual(decision["alert_status"], "fired")
        self.assertIn("1 suppressed alert(s)", decision["alert_cooldown_note"])
        entry = self._load_state()["D-1001|M-42"]
        self.assertEqual(entry["suppressed_count"], 1)
        self.assertEqual(entry["total_amount_inr"], 6000.0)

    def test_expired_cooldown_fires_again_and_preserves_history(self):
        self._write_state({
            "D-1001|M-42": {
                "last_fired": iso_minutes_ago(30),
                "last_action": "escalate",
                "first_fired": iso_minutes_ago(60),
                "suppressed_count": 2,
                "total_amount_inr": 15000.0,
            }
        })
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=5000.0))
        self.assertEqual(decision["alert_status"], "fired")
        entry = self._load_state()["D-1001|M-42"]
        self.assertEqual(entry["suppressed_count"], 2)
        self.assertEqual(entry["total_amount_inr"], 20000.0)

    def test_corrupt_last_fired_entry_is_purged(self):
        # Cleanup runs before the cooldown lookup and evicts entries whose
        # last_fired cannot be parsed, so a corrupt entry is treated as fresh.
        self._write_state({
            "D-1001|M-42": {
                "last_fired": "not-a-timestamp",
                "last_action": "escalate",
                "first_fired": iso_minutes_ago(60),
                "suppressed_count": 3,
                "total_amount_inr": 5000.0,
            }
        })
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=5000.0))
        self.assertEqual(decision["alert_status"], "fired")
        entry = self._load_state()["D-1001|M-42"]
        self.assertEqual(entry["suppressed_count"], 0)
        self.assertEqual(entry["total_amount_inr"], 5000.0)

    def test_entries_older_than_24h_are_purged(self):
        self._write_state({
            "D-1001|M-42": {
                "last_fired": iso_minutes_ago(25 * 60),
                "last_action": "escalate",
                "first_fired": iso_minutes_ago(30 * 60),
                "suppressed_count": 5,
                "total_amount_inr": 9000.0,
            }
        })
        decision = apply_cooldown(make_decision("escalate"), make_event(amount=1000.0))
        self.assertEqual(decision["alert_status"], "fired")
        entry = self._load_state()["D-1001|M-42"]
        # Old incident purged → treated as fresh, history not carried forward
        self.assertEqual(entry["suppressed_count"], 0)
        self.assertEqual(entry["total_amount_inr"], 1000.0)
        self.assertNotIn("suppressed alert(s)", decision["alert_cooldown_note"])

    def test_config_cooldown_minutes_widens_window(self):
        self.mock_load_config.return_value = {"cooldown_minutes": 60}
        self._write_state({
            "D-1001|M-42": {
                "last_fired": iso_minutes_ago(5),
                "last_action": "escalate",
                "first_fired": iso_minutes_ago(10),
                "suppressed_count": 0,
                "total_amount_inr": 1000.0,
            }
        })
        # 5 minutes ago is inside a 60-minute window → suppressed (would have
        # fired under the 15-minute default).
        decision = apply_cooldown(make_decision("escalate"), make_event())
        self.assertEqual(decision["alert_status"], "suppressed_duplicate")
        self.assertIn("cooldown: 60 min", decision["alert_cooldown_note"])

    def test_config_cooldown_minutes_narrows_window(self):
        self.mock_load_config.return_value = {"cooldown_minutes": 3}
        self._write_state({
            "D-1001|M-42": {
                "last_fired": iso_minutes_ago(5),
                "last_action": "escalate",
                "first_fired": iso_minutes_ago(10),
                "suppressed_count": 0,
                "total_amount_inr": 1000.0,
            }
        })
        # 5 minutes ago is outside a 3-minute window → fires
        decision = apply_cooldown(make_decision("escalate"), make_event())
        self.assertEqual(decision["alert_status"], "fired")

    def test_devices_are_tracked_independently(self):
        apply_cooldown(make_decision("escalate"), make_event(device_id="D-1001"))
        decision = apply_cooldown(
            make_decision("escalate"), make_event(device_id="D-2002")
        )
        self.assertEqual(decision["alert_status"], "fired")


class CooldownMinutesTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("guardrails.alert_cooldown._load_config")
        self.mock_load_config = patcher.start()
        self.addCleanup(patcher.stop)

    def test_default_when_config_missing(self):
        self.mock_load_config.return_value = {}
        self.assertEqual(cooldown_minutes(), 15)

    def test_reads_config_value(self):
        self.mock_load_config.return_value = {"cooldown_minutes": 5}
        self.assertEqual(cooldown_minutes(), 5)

    def test_floored_at_one_minute(self):
        self.mock_load_config.return_value = {"cooldown_minutes": 0}
        self.assertEqual(cooldown_minutes(), 1)

    def test_fallback_on_garbage_config(self):
        self.mock_load_config.return_value = {"cooldown_minutes": "nope"}
        self.assertEqual(cooldown_minutes(), 15)


if __name__ == "__main__":
    unittest.main()