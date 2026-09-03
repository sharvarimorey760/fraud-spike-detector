"""
Guardrail Layer — Hard Safety Boundaries & Policy Enforcement.

This code-level security gate guarantees that no LLM hallucination or prompt injection
can ever execute an unsafe, unexplainable, or unbounded financial action.

Enforcements:
1. Vocabulary Gating: Actions, risk levels, and fraud types must strictly match whitelist.
2. Confidence Gates: Strict threshold gates for soft_hold and escalate (the escalate
   threshold is configurable via config.json's min_escalate_confidence).
3. Financial Circuit Breaker: High-value transactions (₹25,000+) can NEVER be auto-dismissed.
4. Risk Telemetry Cross-Validation: High deterministic risk scores (75+) override AI dismissals.
5. Remediation Guarantee: Every actionable decision must have a concrete, human-executable next step.
"""

import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")

DEFAULT_MIN_CONFIDENCE_FOR_ESCALATE = 0.85

ALLOWED_ACTIONS = {
    "flag_for_review",
    "soft_hold",
    "escalate",
    "dismiss",
}

ALLOWED_RISK_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_FRAUD_TYPES = {
    "card_testing",
    "device_spoof",
    "bust_out",
    "retry_storm",
    "velocity_attack",
    "coordinated_fraud",
    "unusual_behavior",
    "unclear",
}

STRONG_ACTIONS = {"escalate", "soft_hold"}

# Confidence Thresholds
MIN_CONFIDENCE_FOR_STRONG_ACTION = 0.50
MIN_CONFIDENCE_FOR_SOFT_HOLD = 0.70


def _load_config() -> dict:
    """Read config.json (written by the dashboard's Settings tab)."""
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def min_confidence_for_escalate() -> float:
    """
    Escalate threshold from config.json's min_escalate_confidence,
    clamped to [0, 1], falling back to the default on bad input.

    Read per call (not at import time) so a live dashboard picks up
    Settings changes without a process restart.
    """
    try:
        value = float(
            _load_config().get(
                "min_escalate_confidence",
                DEFAULT_MIN_CONFIDENCE_FOR_ESCALATE,
            )
        )
        return max(0.0, min(1.0, value))
    except (TypeError, ValueError):
        return DEFAULT_MIN_CONFIDENCE_FOR_ESCALATE

# Financial Circuit Breaker Threshold (INR)
CIRCUIT_BREAKER_AMOUNT_INR = 25000.0

# Telemetry Risk Threshold that blocks auto-dismissal
CRITICAL_TELEMETRY_RISK_THRESHOLD = 75.0


def safe_confidence(value) -> float:
    """Convert confidence safely between 0.0 and 1.0."""
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, conf))


def calculate_risk_level(
    confidence: float,
    action: str,
    min_confidence_for_escalate: float = DEFAULT_MIN_CONFIDENCE_FOR_ESCALATE,
) -> str:
    """Derive consistent risk tier from confidence and proposed action."""
    if action == "escalate" or confidence >= min_confidence_for_escalate:
        return "critical"
    if action == "soft_hold" or confidence >= 0.70:
        return "high"
    if action == "flag_for_review" or confidence >= 0.45:
        return "medium"
    return "low"


def apply_guardrails(decision: dict, event: dict = None) -> dict:
    """
    Apply hard deterministic safety policies to the AI decision.
    Ensures that an AI hallucination cannot silently approve or misclassify high-risk events.
    """
    if not isinstance(decision, dict):
        decision = {}

    violations = []

    escalate_threshold = min_confidence_for_escalate()

    # -------------------------------------------------------------
    # 1. Validate & Normalize Confidence
    # -------------------------------------------------------------
    original_conf = decision.get("confidence", 0.0)
    confidence = safe_confidence(original_conf)
    if confidence != original_conf:
        violations.append(f"Normalized malformed confidence '{original_conf}' → {confidence:.2f}")
    decision["confidence"] = confidence

    # -------------------------------------------------------------
    # 2. Whitelist Fraud Type
    # -------------------------------------------------------------
    fraud_type = str(decision.get("fraud_type_guess", "unclear")).strip().lower()
    if fraud_type not in ALLOWED_FRAUD_TYPES:
        violations.append(f"Non-whitelisted fraud type '{fraud_type}' → set to 'unclear'")
        fraud_type = "unclear"
    decision["fraud_type_guess"] = fraud_type

    # -------------------------------------------------------------
    # 3. Whitelist Proposed Action
    # -------------------------------------------------------------
    action = str(decision.get("recommended_action", "flag_for_review")).strip().lower()
    if action not in ALLOWED_ACTIONS:
        violations.append(f"Invalid action '{action}' → downgraded to 'flag_for_review'")
        action = "flag_for_review"

    # -------------------------------------------------------------
    # 4. Confidence-Based Action Gating
    # -------------------------------------------------------------
    if confidence < MIN_CONFIDENCE_FOR_STRONG_ACTION and action in STRONG_ACTIONS:
        violations.append(f"Confidence {confidence:.2f} < {MIN_CONFIDENCE_FOR_STRONG_ACTION:.2f}: '{action}' → 'flag_for_review'")
        action = "flag_for_review"

    if action == "soft_hold" and confidence < MIN_CONFIDENCE_FOR_SOFT_HOLD:
        violations.append(f"Confidence {confidence:.2f} < {MIN_CONFIDENCE_FOR_SOFT_HOLD:.2f} for soft_hold → 'flag_for_review'")
        action = "flag_for_review"

    if action == "escalate" and confidence < escalate_threshold:
        violations.append(f"Confidence {confidence:.2f} < {escalate_threshold:.2f} for escalate → 'flag_for_review'")
        action = "flag_for_review"

    # -------------------------------------------------------------
    # 5. Financial Circuit Breaker (High-Value Safeguard)
    # -------------------------------------------------------------
    txn_amount = 0.0
    if event and isinstance(event, dict):
        txn_amount = float(event.get("transaction_amount", 0) or 0)
    elif "transaction_amount" in decision:
        txn_amount = float(decision.get("transaction_amount", 0) or 0)

    if txn_amount >= CIRCUIT_BREAKER_AMOUNT_INR and action == "dismiss":
        violations.append(
            f"Circuit Breaker Triggered: Amount ₹{txn_amount:,.0f} ≥ ₹{CIRCUIT_BREAKER_AMOUNT_INR:,.0f}. "
            f"Cannot auto-dismiss high-value transaction. Overridden to 'flag_for_review'."
        )
        action = "flag_for_review"

    # -------------------------------------------------------------
    # 6. Telemetry Risk Score Cross-Validation
    # -------------------------------------------------------------
    risk_score = float(decision.get("risk_score", 0) or decision.get("local_risk_score", 0) or 0)
    if risk_score >= CRITICAL_TELEMETRY_RISK_THRESHOLD and action == "dismiss":
        violations.append(
            f"Telemetry Conflict: Deterministic risk score ({risk_score:.0f}/100) indicates elevated danger. "
            f"AI 'dismiss' overridden to 'flag_for_review'."
        )
        action = "flag_for_review"

    # -------------------------------------------------------------
    # 7. Evidence Array Validation
    # -------------------------------------------------------------
    evidence = decision.get("evidence", [])
    if not isinstance(evidence, list):
        violations.append("Evidence was not a list; wrapped into fallback list")
        evidence = [str(evidence)] if evidence else []

    cleaned_evidence = [str(item).strip() for item in evidence if str(item).strip()]
    if not cleaned_evidence:
        cleaned_evidence = ["Telemetry features evaluated by anomaly scorer; no specific tool evidence cited."]
        if action in STRONG_ACTIONS:
            violations.append(f"Missing structured evidence: strong action '{action}' downgraded to 'flag_for_review'")
            action = "flag_for_review"
    decision["evidence"] = cleaned_evidence

    # -------------------------------------------------------------
    # 8. Remediation Next-Step Guarantee
    # -------------------------------------------------------------
    remediation = str(decision.get("recommended_remediation", "")).strip()
    if not remediation or len(remediation) < 10 or "review" == remediation.lower():
        if action == "escalate":
            remediation = "Temporarily suspend POS terminal payouts and contact merchant manager to verify terminal integrity."
        elif action == "soft_hold":
            remediation = "Place a 30-minute hold on transaction batch and issue an SMS/OTP verification challenge to the cardholder."
        else:
            remediation = "Inspect merchant retry history over the last 3 hours to verify whether velocity matches regular peaks."
        decision["recommended_remediation"] = remediation

    # -------------------------------------------------------------
    # 9. Risk Tier Consistency & Human Review Lock
    # -------------------------------------------------------------
    decision["risk_level"] = calculate_risk_level(
        confidence,
        action,
        escalate_threshold,
    )
    decision["recommended_action"] = action

    # Mandatory human review for all actions except justified low-risk dismissals
    decision["human_review_required"] = (
        action in {"escalate", "soft_hold", "flag_for_review"} or
        risk_score >= 50 or
        txn_amount >= CIRCUIT_BREAKER_AMOUNT_INR
    )

    # -------------------------------------------------------------
    # 10. Audit Meta
    # -------------------------------------------------------------
    decision["guardrail_violations"] = violations
    decision["guardrail_status"] = "adjusted" if violations else "passed"

    return decision