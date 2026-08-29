"""
The core agent: takes one flagged transaction, investigates it using
tool-calling (multi-turn), and returns a bounded decision + reasoning.

Requires ANTHROPIC_API_KEY to be set in the environment.

Usage:
    python agent_loop.py --event_index 0 --flagged ../detection/flagged_events.csv --data ../data/transactions.csv
"""

import argparse
import json
import os
import sys

import anthropic
import pandas as pd

from tools import TOOL_SCHEMA, TOOL_DISPATCH, load_dataset
from prompts import SYSTEM_PROMPT, build_investigation_prompt

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from guardrails.risk_gate import apply_guardrails  # noqa: E402
from audit_log.logger import log_decision  # noqa: E402

MODEL = "claude-sonnet-4-6"
MAX_TOOL_TURNS = 5


def run_agent(client: anthropic.Anthropic, event: dict) -> dict:
    messages = [
        {"role": "user", "content": build_investigation_prompt(event)}
    ]

    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMA,
            messages=messages,
        )

        # If the model wants to call tools, execute them and loop again
        tool_calls = [b for b in response.content if b.type == "tool_use"]
        if tool_calls:
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for call in tool_calls:
                fn = TOOL_DISPATCH.get(call.name)
                result = fn(call.input) if fn else {"error": f"unknown tool {call.name}"}
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": call.id,
                    "content": json.dumps(result),
                })
            messages.append({"role": "user", "content": tool_results})
            continue

        # No more tool calls — extract the final text/JSON decision
        text_blocks = [b.text for b in response.content if b.type == "text"]
        final_text = "\n".join(text_blocks).strip()
        return parse_decision(final_text)

    return {
        "fraud_type_guess": "unclear",
        "confidence": 0.0,
        "recommended_action": "flag_for_review",
        "reasoning_summary": "Agent exceeded max tool-call turns without reaching a decision.",
    }


def parse_decision(text: str) -> dict:
    """Extract the trailing JSON object from the model's final response."""
    start = text.rfind("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return {
            "fraud_type_guess": "unclear",
            "confidence": 0.0,
            "recommended_action": "flag_for_review",
            "reasoning_summary": f"Could not parse structured decision. Raw output: {text[:300]}",
        }
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {
            "fraud_type_guess": "unclear",
            "confidence": 0.0,
            "recommended_action": "flag_for_review",
            "reasoning_summary": f"JSON parse error. Raw output: {text[:300]}",
        }


def process_event(client, event: dict) -> dict:
    decision = run_agent(client, event)
    decision = apply_guardrails(decision)
    log_decision(event, decision)
    return decision


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--flagged", type=str, default="../detection/flagged_events.csv")
    parser.add_argument("--data", type=str, default="../data/transactions.csv")
    parser.add_argument("--event_index", type=int, default=0)
    parser.add_argument("--all", action="store_true", help="process every flagged event")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: set ANTHROPIC_API_KEY in your environment before running the agent.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    load_dataset(args.data)  # for tools.py to query merchant/device history

    flagged_df = pd.read_csv(args.flagged)

    if args.all:
        for _, row in flagged_df.iterrows():
            decision = process_event(client, row.to_dict())
            print(json.dumps(decision, indent=2))
    else:
        event = flagged_df.iloc[args.event_index].to_dict()
        decision = process_event(client, event)
        print(json.dumps(decision, indent=2))
