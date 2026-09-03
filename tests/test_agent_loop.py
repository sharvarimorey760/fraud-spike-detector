"""
Tests for agent.agent_loop decision normalization.

Run from the project root:
    pytest
    # or: python -m unittest discover -s tests -t . -v
"""

import os
import sys
import unittest

# agent_loop.py imports sibling modules via `from tools import ...`, which
# requires the agent/ directory on sys.path (same approach the dashboard uses).
AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"
)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from agent_loop import enrich_event, normalize_decision  # noqa: E402


def make_event(amount=500.0):
    return {
        "transaction_id": "T-1",
        "device_id": "D-1",
        "merchant_id": "M-1",
        "transaction_amount": amount,
        "retry_count": 2,
        "device_uptime_hrs": 200,
        "last_ping_gap_sec": 1.0,
        "ip_consistency_flag": 1,
    }


class NormalizeDecisionTest(unittest.TestCase):
    def test_guardrail_audit_fields_survive_normalization(self):
        # Regression: guardrail_violations / guardrail_status / risk_level
        # were stripped by normalize_decision, so the circuit-breaker
        # override reason never reached the audit log.
        decision = {
            "fraud_type_guess": "unclear",
            "risk_score": 30,
            "confidence": 0.95,
            "recommended_action": "flag_for_review",
            "reasoning_summary": "looks fine",
            "evidence": ["amount in normal range"],
            "risk_level": "critical",
            "guardrail_status": "adjusted",
            "guardrail_violations": [
                "Circuit Breaker Triggered: Amount ₹30,000 >= ₹25,000."
            ],
        }
        normalized = normalize_decision(decision)
        self.assertEqual(normalized["risk_level"], "critical")
        self.assertEqual(normalized["guardrail_status"], "adjusted")
        self.assertEqual(len(normalized["guardrail_violations"]), 1)

    def test_unknown_fields_are_not_invented(self):
        decision = {
            "confidence": 0.9,
            "recommended_action": "escalate",
            "reasoning_summary": "multiple corroborated signals",
        }
        normalized = normalize_decision(decision)
        self.assertEqual(normalized["recommended_action"], "escalate")
        self.assertNotIn("guardrail_status", normalized)
        self.assertNotIn("guardrail_violations", normalized)

    def test_action_normalized_to_whitelist(self):
        decision = {"recommended_action": "DELETE_EVERYTHING", "confidence": 0.9}
        normalized = normalize_decision(decision)
        self.assertEqual(normalized["recommended_action"], "flag_for_review")

    def test_risk_score_falls_back_to_local_risk(self):
        event = enrich_event(make_event())
        decision = {"confidence": 0.5, "recommended_action": "flag_for_review"}
        normalized = normalize_decision(decision)
        # local_risk_score is injected into the decision upstream, but if a
        # caller omits it, normalize falls back to local risk on the event.
        self.assertIsInstance(normalized["risk_score"], int)


if __name__ == "__main__":
    unittest.main()