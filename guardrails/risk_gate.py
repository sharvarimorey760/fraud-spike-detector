"""
Guardrail layer. This is deliberately NOT the LLM's job — it's a hard,
code-level gate that runs after the agent's decision, so a bad model
output can never directly produce an unbounded action.

This is what makes the pipeline "bounded and gated" rather than trusting
the agent's output outright.
"""

ALLOWED_ACTIONS = {"flag_for_review", "soft_hold", "escalate", "dismiss"}

# Actions strong enough that they require confidence above this bar,
# regardless of what the agent claims.
STRONG_ACTIONS = {"escalate", "soft_hold"}
MIN_CONFIDENCE_FOR_STRONG_ACTION = 0.5


def apply_guardrails(decision: dict) -> dict:
    action = decision.get("recommended_action", "flag_for_review")
    confidence = decision.get("confidence", 0.0)

    violations = []

    # 1. Action must be one of the allowed, bounded set — no "block_account",
    #    no "ban_merchant", nothing outside the defined vocabulary.
    if action not in ALLOWED_ACTIONS:
        violations.append(f"'{action}' is not an allowed action; downgraded to 'flag_for_review'.")
        action = "flag_for_review"

    # 2. Strong actions require sufficient confidence, enforced in code
    #    (not just asked for in the prompt).
    if action in STRONG_ACTIONS and confidence < MIN_CONFIDENCE_FOR_STRONG_ACTION:
        violations.append(
            f"Confidence {confidence} below {MIN_CONFIDENCE_FOR_STRONG_ACTION} "
            f"threshold for '{action}'; downgraded to 'flag_for_review'."
        )
        action = "flag_for_review"

    decision["recommended_action"] = action
    decision["guardrail_violations"] = violations
    decision["human_review_required"] = action in {"escalate", "soft_hold"}
    return decision
