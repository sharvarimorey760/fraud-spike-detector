"""
Tests for guardrails.risk_gate — hard safety boundaries & policy enforcement.

Run from the project root:
    pytest
    # or: python -m unittest discover -s tests -t . -v
"""

import unittest
from unittest import mock

from guardrails.risk_gate import (
    CIRCUIT_BREAKER_AMOUNT_INR,
    apply_guardrails,
    calculate_risk_level,
    min_confidence_for_escalate,
    safe_confidence,
)


def make_event(amount=500.0, **overrides):
    event = {
        "device_id": "D-1001",
        "merchant_id": "M-42",
        "transaction_amount": amount,
    }
    event.update(overrides)
    return event


def make_decision(**overrides):
    decision = {
        "confidence": 0.95,
        "fraud_type_guess": "retry_storm",
        "recommended_action": "escalate",
        "risk_score": 60,
        "evidence": ["Retry count 4x baseline"],
        "recommended_remediation": "Suspend terminal and contact merchant manager.",
    }
    decision.update(overrides)
    return decision


class ApplyGuardrailsTest(unittest.TestCase):
    """Core policy enforcement with default config (escalate threshold 0.85)."""

    def setUp(self):
        # Deterministic default config; individual tests override as needed.
        patcher = mock.patch(
            "guardrails.risk_gate._load_config", return_value={}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_high_confidence_escalate_passes_unchanged(self):
        decision = apply_guardrails(make_decision(), make_event())
        self.assertEqual(decision["recommended_action"], "escalate")
        self.assertEqual(decision["risk_level"], "critical")
        self.assertEqual(decision["guardrail_status"], "passed")
        self.assertEqual(decision["guardrail_violations"], [])
        self.assertTrue(decision["human_review_required"])

    # ---- Confidence gating -------------------------------------------------

    def test_escalate_below_threshold_downgraded(self):
        decision = apply_guardrails(
            make_decision(confidence=0.80, recommended_action="escalate"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertEqual(decision["guardrail_status"], "adjusted")
        self.assertTrue(any("escalate" in v for v in decision["guardrail_violations"]))

    def test_soft_hold_above_threshold_kept(self):
        decision = apply_guardrails(
            make_decision(confidence=0.75, recommended_action="soft_hold"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "soft_hold")
        self.assertEqual(decision["risk_level"], "high")

    def test_soft_hold_below_threshold_downgraded(self):
        decision = apply_guardrails(
            make_decision(confidence=0.60, recommended_action="soft_hold"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")

    def test_strong_action_below_floor_downgraded(self):
        # confidence < 0.50 blocks escalate AND soft_hold regardless of config
        decision = apply_guardrails(
            make_decision(confidence=0.40, recommended_action="escalate"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")

    # ---- Financial circuit breaker -----------------------------------------

    def test_circuit_breaker_blocks_dismiss_of_high_value_event(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss"),
            make_event(amount=30000.0),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertTrue(
            any("Circuit Breaker" in v for v in decision["guardrail_violations"])
        )
        self.assertTrue(decision["human_review_required"])

    def test_circuit_breaker_triggers_at_exact_threshold(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss"),
            make_event(amount=CIRCUIT_BREAKER_AMOUNT_INR),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")

    def test_low_value_dismiss_allowed(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss", risk_score=10),
            make_event(amount=500.0),
        )
        self.assertEqual(decision["recommended_action"], "dismiss")
        self.assertFalse(decision["human_review_required"])

    def test_circuit_breaker_reads_amount_from_event_not_decision(self):
        # Regression: the enriched event is passed into the guardrail layer; a
        # stale transaction_amount left in the decision dict must not override
        # the event's (already normalized) amount.
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss", transaction_amount=99999.0),
            make_event(amount=500.0),
        )
        self.assertEqual(decision["recommended_action"], "dismiss")

    def test_circuit_breaker_falls_back_to_decision_amount_without_event(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss", transaction_amount=30000.0),
            None,
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")

    # ---- Telemetry risk cross-validation ------------------------------------

    def test_high_risk_score_overrides_dismiss(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss", risk_score=88),
            make_event(amount=100.0),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertTrue(any("Telemetry" in v for v in decision["guardrail_violations"]))

    def test_elevated_risk_keeps_dismiss_but_locks_human_review(self):
        decision = apply_guardrails(
            make_decision(recommended_action="dismiss", risk_score=60),
            make_event(amount=100.0),
        )
        self.assertEqual(decision["recommended_action"], "dismiss")
        self.assertTrue(decision["human_review_required"])

    # ---- Whitelist enforcement ----------------------------------------------

    def test_invalid_action_downgraded_to_flag_for_review(self):
        decision = apply_guardrails(
            make_decision(recommended_action="delete_all_data"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertTrue(any("Invalid action" in v for v in decision["guardrail_violations"]))

    def test_invalid_fraud_type_set_to_unclear(self):
        decision = apply_guardrails(
            make_decision(fraud_type_guess="money_laundering"),
            make_event(),
        )
        self.assertEqual(decision["fraud_type_guess"], "unclear")

    def test_action_case_insensitive(self):
        decision = apply_guardrails(
            make_decision(recommended_action="ESCALATE"),
            make_event(),
        )
        self.assertEqual(decision["recommended_action"], "escalate")

    # ---- Evidence & remediation ---------------------------------------------

    def test_missing_evidence_downgrades_strong_action(self):
        decision = apply_guardrails(make_decision(evidence=[]), make_event())
        self.assertEqual(decision["recommended_action"], "flag_for_review")
        self.assertTrue(decision["evidence"])  # fallback evidence present
        self.assertTrue(
            any("evidence" in v.lower() for v in decision["guardrail_violations"])
        )

    def test_non_list_evidence_wrapped_into_list(self):
        decision = apply_guardrails(
            make_decision(evidence="retry storm"),
            make_event(),
        )
        self.assertIsInstance(decision["evidence"], list)
        self.assertIn("retry storm", decision["evidence"])

    def test_remediation_auto_generated_when_missing(self):
        decision = apply_guardrails(make_decision(recommended_remediation=""), make_event())
        self.assertGreater(len(decision["recommended_remediation"]), 10)

    def test_valid_remediation_kept(self):
        remediation = "Suspend terminal and call the merchant immediately."
        decision = apply_guardrails(
            make_decision(recommended_remediation=remediation),
            make_event(),
        )
        self.assertEqual(decision["recommended_remediation"], remediation)

    # ---- Config wiring through the gate -------------------------------------

    def test_config_escalate_threshold_wires_into_gate(self):
        with mock.patch(
            "guardrails.risk_gate._load_config",
            return_value={"min_escalate_confidence": 0.90},
        ):
            decision = apply_guardrails(
                make_decision(confidence=0.88, recommended_action="escalate"),
                make_event(),
            )
        self.assertEqual(decision["recommended_action"], "flag_for_review")

        with mock.patch(
            "guardrails.risk_gate._load_config",
            return_value={"min_escalate_confidence": 0.80},
        ):
            decision = apply_guardrails(
                make_decision(confidence=0.88, recommended_action="escalate"),
                make_event(),
            )
        self.assertEqual(decision["recommended_action"], "escalate")


class SafeConfidenceTest(unittest.TestCase):
    def test_valid_confidence_passthrough(self):
        self.assertEqual(safe_confidence(0.73), 0.73)

    def test_bad_input_returns_zero(self):
        self.assertEqual(safe_confidence("abc"), 0.0)
        self.assertEqual(safe_confidence(None), 0.0)

    def test_values_clamped_to_unit_interval(self):
        self.assertEqual(safe_confidence(-1), 0.0)
        self.assertEqual(safe_confidence(2.5), 1.0)


class CalculateRiskLevelTest(unittest.TestCase):
    def test_escalate_always_critical(self):
        self.assertEqual(calculate_risk_level(0.1, "escalate"), "critical")

    def test_soft_hold_is_high(self):
        self.assertEqual(calculate_risk_level(0.6, "soft_hold"), "high")

    def test_confidence_drives_tier(self):
        # Only "dismiss" can reach the low tier; flag_for_review forces medium.
        self.assertEqual(calculate_risk_level(0.9, "dismiss"), "critical")
        self.assertEqual(calculate_risk_level(0.8, "dismiss"), "high")
        self.assertEqual(calculate_risk_level(0.5, "dismiss"), "medium")
        self.assertEqual(calculate_risk_level(0.3, "dismiss"), "low")
        self.assertEqual(calculate_risk_level(0.3, "flag_for_review"), "medium")

    def test_custom_escalate_threshold(self):
        # 0.88 is below a 0.90 threshold → "high", not "critical"
        self.assertEqual(
            calculate_risk_level(0.88, "flag_for_review", min_confidence_for_escalate=0.90),
            "high",
        )


class MinConfidenceForEscalateTest(unittest.TestCase):
    def test_reads_config_value(self):
        with mock.patch(
            "guardrails.risk_gate._load_config",
            return_value={"min_escalate_confidence": 0.90},
        ):
            self.assertEqual(min_confidence_for_escalate(), 0.90)

    def test_default_when_config_missing(self):
        with mock.patch("guardrails.risk_gate._load_config", return_value={}):
            self.assertEqual(min_confidence_for_escalate(), 0.85)

    def test_clamped_to_unit_interval(self):
        with mock.patch(
            "guardrails.risk_gate._load_config",
            return_value={"min_escalate_confidence": 2.0},
        ):
            self.assertEqual(min_confidence_for_escalate(), 1.0)

    def test_fallback_on_garbage_config(self):
        with mock.patch(
            "guardrails.risk_gate._load_config",
            return_value={"min_escalate_confidence": "not-a-number"},
        ):
            self.assertEqual(min_confidence_for_escalate(), 0.85)


if __name__ == "__main__":
    unittest.main()