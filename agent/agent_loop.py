"""
Core AI fraud investigation agent.

Pipeline:
    flagged transaction
        -> tool-based investigation
        -> risk enrichment
        -> Gemini reasoning
        -> bounded risk decision
        -> guardrails
        -> audit trail

The AI recommends an action; guardrails remain the final safety layer.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import pandas as pd
from google import genai
from google.genai import types

from tools import TOOL_SCHEMA, TOOL_DISPATCH, load_dataset
from prompts import (
    SYSTEM_PROMPT,
    build_investigation_prompt,
    CRITIC_SYSTEM_PROMPT,
    build_critic_prompt,
)

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from env_loader import load_dotenv  # noqa: E402

# Load GEMINI_API_KEY (and any other secrets) from the project's .env
# file, if present. Real environment variables are never overridden.
load_dotenv()

from guardrails.risk_gate import apply_guardrails  # noqa: E402
from guardrails.alert_cooldown import apply_cooldown  # noqa: E402
from audit_log.logger import log_decision  # noqa: E402


def _load_configured_model():
    """Read a model override from config.json (written by the dashboard's
    Settings tab) if present, otherwise fall back to the default."""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            return cfg.get("model", "gemini-3.5-flash-lite")
        except (json.JSONDecodeError, OSError):
            pass
    return "gemini-3.5-flash-lite"


MODEL = _load_configured_model()
MAX_TOOL_TURNS = 5


GEMINI_TOOLS = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name=t["name"],
            description=t["description"],
            parameters=t["parameters"],
        )
        for t in TOOL_SCHEMA
    ]
)


def clamp(value, minimum=0, maximum=100):
    try:
        return max(minimum, min(maximum, float(value)))
    except (TypeError, ValueError):
        return minimum


def calculate_local_risk(event: dict) -> dict:
    score = 0.0
    reason_codes = []

    amount = float(event.get("transaction_amount", 0) or 0)
    retries = int(event.get("retry_count", 0) or 0)
    uptime = float(event.get("device_uptime_hrs", 0) or 0)
    ping_gap = float(event.get("last_ping_gap_sec", 0) or 0)
    ip_flag = event.get("ip_consistency_flag", 1)
    burst = float(event.get("burst_count_5min", 0) or 0)

    if amount >= 15000:
        score += 20
        reason_codes.append("HIGH_VALUE_TRANSACTION")
    elif amount >= 7500:
        score += 10
        reason_codes.append("ELEVATED_TRANSACTION_AMOUNT")

    if retries >= 10:
        score += 20
        reason_codes.append("EXCESSIVE_RETRIES")
    elif retries >= 5:
        score += 10
        reason_codes.append("ELEVATED_RETRY_COUNT")

    if uptime <= 8:
        score += 15
        reason_codes.append("RECENT_DEVICE_RESTART")

    if ping_gap >= 10:
        score += 15
        reason_codes.append("ABNORMAL_PING_GAP")

    try:
        inconsistent = int(ip_flag) == 0
    except (TypeError, ValueError):
        inconsistent = False

    if inconsistent:
        score += 20
        reason_codes.append("IP_INCONSISTENCY")

    if burst >= 10:
        score += 25
        reason_codes.append("HIGH_TRANSACTION_BURST")
    elif burst >= 5:
        score += 12
        reason_codes.append("ELEVATED_TRANSACTION_BURST")

    return {
        "local_risk_score": int(clamp(score)),
        "reason_codes": reason_codes,
    }


def enrich_event(event: dict) -> dict:
    enriched = dict(event)
    risk = calculate_local_risk(enriched)
    enriched["local_risk_score"] = risk["local_risk_score"]
    enriched["reason_codes"] = risk["reason_codes"]
    enriched["investigation_timestamp"] = datetime.now(
        timezone.utc
    ).isoformat()
    return enriched


ALLOWED_ACTIONS = {
    "dismiss",
    "flag_for_review",
    "soft_hold",
    "escalate",
}


def normalize_decision(decision: dict) -> dict:
    if not isinstance(decision, dict):
        decision = {}

    action = str(
        decision.get("recommended_action", "flag_for_review")
    ).strip().lower()

    if action not in ALLOWED_ACTIONS:
        action = "flag_for_review"

    confidence = clamp(decision.get("confidence", 0), 0, 1)
    risk_score = decision.get("risk_score")

    if risk_score is None:
        risk_score = decision.get("local_risk_score", 0)

    risk_score = int(clamp(risk_score))

    fraud_type = str(
        decision.get("fraud_type_guess", "unclear")
    ).strip()

    reasoning = str(
        decision.get(
            "reasoning_summary",
            "No detailed reasoning was returned.",
        )
    ).strip()

    human_review = decision.get("human_review_required")

    if human_review is None:
        human_review = action != "dismiss"

    normalized = {
        "fraud_type_guess": fraud_type,
        "risk_score": risk_score,
        "confidence": round(confidence, 3),
        "recommended_action": action,
        "reasoning_summary": reasoning,
        "human_review_required": bool(human_review),
        "reason_codes": decision.get("reason_codes", []),
    }

    for field in [
        "evidence",
        "merchant_pattern",
        "device_pattern",
        "spike_context",
        "recommended_next_step",
        "recommended_remediation",
        "critic_verdict",
        "critic_summary",
        "alert_status",
        "alert_cooldown_note",
        # Guardrail enforcement must survive into the audit trail: the
        # circuit-breaker override reason and the final risk tier are
        # exactly what a reviewer needs to see, so never drop them.
        "risk_level",
        "guardrail_status",
        "guardrail_violations",
    ]:
        if field in decision:
            normalized[field] = decision[field]

    return normalized


def run_agent(client: genai.Client, event: dict) -> dict:
    enriched_event = enrich_event(event)

    chat = client.chats.create(
        model=MODEL,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            tools=[GEMINI_TOOLS],
            temperature=0.1,
        ),
    )

    # 503 retry fix only
    for attempt in range(3):
        try:
            response = chat.send_message(
                build_investigation_prompt(enriched_event)
            )
            break
        except Exception as exc:
            if "503" not in str(exc) or attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))

    for _ in range(MAX_TOOL_TURNS):
        if not response.candidates:
            return fallback_decision(
                "Gemini returned no investigation candidates."
            )

        parts = response.candidates[0].content.parts

        function_calls = [
            part.function_call
            for part in parts
            if getattr(part, "function_call", None)
        ]

        if function_calls:
            function_response_parts = []

            for call in function_calls:
                fn = TOOL_DISPATCH.get(call.name)

                if fn:
                    try:
                        result = fn(dict(call.args))
                    except Exception as exc:
                        result = {
                            "error": f"Tool execution failed: {str(exc)}"
                        }
                else:
                    result = {
                        "error": f"Unknown tool: {call.name}"
                    }

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=call.name,
                        response={"result": result},
                    )
                )

            # 503 retry fix only
            for attempt in range(3):
                try:
                    response = chat.send_message(
                        function_response_parts
                    )
                    break
                except Exception as exc:
                    if "503" not in str(exc) or attempt == 2:
                        raise
                    time.sleep(5 * (attempt + 1))

            continue

        final_text = (
            response.text.strip()
            if response.text
            else ""
        )

        decision = parse_decision(final_text)
        decision.setdefault(
            "local_risk_score",
            enriched_event.get("local_risk_score", 0),
        )
        decision.setdefault(
            "reason_codes",
            enriched_event.get("reason_codes", []),
        )
        return normalize_decision(decision)

    return fallback_decision(
        "Agent exceeded the maximum investigation tool-call turns."
    )


def run_critic(
    client: genai.Client,
    event: dict,
    investigator_decision: dict,
) -> dict:

    # Use the chat API (like the investigator) rather than
    # Models.generate_content: the SDK warns against direct AFC-style
    # generate_content calls. No tools are passed, so the critic still
    # cannot call anything — it only reviews the given decision.
    chat = client.chats.create(
        model=MODEL,
        config=types.GenerateContentConfig(
            system_instruction=CRITIC_SYSTEM_PROMPT,
            temperature=0.1,
        ),
    )

    # 503 retry fix only
    for attempt in range(3):
        try:
            response = chat.send_message(
                build_critic_prompt(
                    event,
                    investigator_decision,
                )
            )
            break
        except Exception as exc:
            if "503" not in str(exc) or attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))

    text = response.text.strip() if response.text else ""
    return parse_critic_verdict(text)


def parse_critic_verdict(text: str) -> dict:
    start = text.rfind("{")
    end = text.rfind("}")

    if start == -1 or end == -1:
        return {
            "verdict": "confirm",
            "confidence_adjustment": 0.0,
            "critique_summary": (
                "Critic response could not be parsed; "
                "defaulting to confirm."
            ),
        }

    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {
            "verdict": "confirm",
            "confidence_adjustment": 0.0,
            "critique_summary": (
                "Critic response was not valid JSON; "
                "defaulting to confirm."
            ),
        }


def apply_critic(decision: dict, critique: dict) -> dict:
    adjustment = critique.get(
        "confidence_adjustment",
        0.0,
    ) or 0.0

    original_confidence = decision.get(
        "confidence",
        0.0,
    ) or 0.0

    try:
        decision["confidence"] = max(
            0.0,
            round(
                float(original_confidence)
                + float(adjustment),
                3,
            ),
        )
    except (TypeError, ValueError):
        pass

    decision["critic_verdict"] = critique.get(
        "verdict",
        "confirm",
    )

    decision["critic_summary"] = critique.get(
        "critique_summary",
        "",
    )

    if critique.get("verdict") == "escalate_for_human":
        decision["recommended_action"] = "escalate"

    return decision


def parse_decision(text: str) -> dict:
    if not text:
        return fallback_decision(
            "Gemini returned an empty response."
        )

    cleaned = text.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace(
            "```json",
            "",
            1,
        )
        cleaned = cleaned.replace(
            "```",
            "",
        )
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed

        if isinstance(parsed, list) and parsed:
            return parsed[0]

    except json.JSONDecodeError:
        pass

    start = cleaned.rfind("{")
    end = cleaned.rfind("}")

    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start:end + 1]

        try:
            parsed = json.loads(candidate)

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

    return fallback_decision(
        f"Could not parse structured AI decision. "
        f"Raw output: {cleaned[:300]}"
    )


def fallback_decision(reason: str) -> dict:
    return {
        "fraud_type_guess": "unclear",
        "risk_score": 0,
        "confidence": 0.0,
        "recommended_action": "flag_for_review",
        "reasoning_summary": reason,
        "recommended_remediation": (
            "AI decision unavailable — route to a human "
            "analyst for manual review."
        ),
        "human_review_required": True,
        "reason_codes": ["AI_DECISION_UNAVAILABLE"],
    }


def process_event(client, event: dict) -> dict:
    enriched_event = enrich_event(event)
    decision = run_agent(client, enriched_event)

    critique = run_critic(
        client,
        enriched_event,
        decision,
    )

    decision = apply_critic(
        decision,
        critique,
    )

    decision.setdefault(
        "risk_score",
        enriched_event.get("local_risk_score", 0),
    )

    decision.setdefault(
        "reason_codes",
        enriched_event.get("reason_codes", []),
    )

    # Pass the enriched event so the guardrail layer can enforce the
    # financial circuit breaker: a high-value transaction (>= ₹25k)
    # must never be auto-dismissed even if the AI recommends it.
    decision = apply_guardrails(
        decision,
        enriched_event,
    )
    decision = apply_cooldown(
        decision,
        enriched_event,
    )
    decision = normalize_decision(decision)

    log_decision(
        enriched_event,
        decision,
    )

    return decision


if __name__ == "__main__":

    # The default Windows console (cp1252) cannot encode characters like
    # ₹ that can appear in decision content — force UTF-8 output so the
    # CLI runs unchanged on any platform.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--flagged",
        type=str,
        default="../detection/flagged_events.csv",
    )

    parser.add_argument(
        "--data",
        type=str,
        default="../data/transactions.csv",
    )

    parser.add_argument(
        "--event_index",
        type=int,
        default=0,
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Process every flagged event.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max events to process in --all mode (0 = no limit).",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds to wait between events in --all mode (rate-limit pacing).",
    )

    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        print(
            "ERROR: set GEMINI_API_KEY in your environment "
            "before running the agent."
        )
        sys.exit(1)

    client = genai.Client(
        api_key=api_key
    )

    load_dataset(args.data)

    if not os.path.exists(args.flagged):
        print(
            f"ERROR: flagged events file not found: {args.flagged}"
        )
        sys.exit(1)

    flagged_df = pd.read_csv(args.flagged)

    if flagged_df.empty:
        print("No flagged events found.")
        sys.exit(0)

    if args.all:
        limit = max(0, args.limit)
        delay = max(0.0, args.delay)
        events = flagged_df.iloc[:limit] if limit else flagged_df

        for i, (_, row) in enumerate(events.iterrows()):
            decision = process_event(
                client,
                row.to_dict(),
            )

            print(
                json.dumps(
                    decision,
                    indent=2,
                    default=str,
                )
            )

            if i < len(events) - 1 and delay > 0:
                print(f"... waiting {delay}s before next event (rate-limit pacing)")
                time.sleep(delay)

    else:
        if args.event_index >= len(flagged_df):
            print(
                f"ERROR: event_index {args.event_index} is out of range. "
                f"Available events: 0-{len(flagged_df) - 1}"
            )
            sys.exit(1)

        event = flagged_df.iloc[
            args.event_index
        ].to_dict()

        decision = process_event(
            client,
            event,
        )

        print(
            json.dumps(
                decision,
                indent=2,
                default=str,
            )
        )