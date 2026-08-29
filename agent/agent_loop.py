"""
The core agent: takes one flagged transaction, investigates it using
tool-calling (multi-turn), and returns a bounded decision + reasoning.

Uses Google's Gemini API with function calling.
Requires GEMINI_API_KEY to be set in the environment.

Usage:
    python agent_loop.py --event_index 0 --flagged ../detection/flagged_events.csv --data ../data/transactions.csv
"""

import argparse
import json
import os
import sys

import pandas as pd
from google import genai
from google.genai import types

from tools import TOOL_SCHEMA, TOOL_DISPATCH, load_dataset
from prompts import SYSTEM_PROMPT, build_investigation_prompt

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from guardrails.risk_gate import apply_guardrails  # noqa: E402
from audit_log.logger import log_decision  # noqa: E402

MODEL = "gemini-2.5-flash"
MAX_TOOL_TURNS = 5

# Wrap our plain-dict tool schema into Gemini's Tool/FunctionDeclaration objects
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


def run_agent(client: genai.Client, event: dict) -> dict:
    chat = client.chats.create(
        model=MODEL,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            tools=[GEMINI_TOOLS],
        ),
    )

    response = chat.send_message(build_investigation_prompt(event))

    for _ in range(MAX_TOOL_TURNS):
        function_calls = [
            part.function_call
            for part in response.candidates[0].content.parts
            if getattr(part, "function_call", None)
        ]

        if function_calls:
            function_response_parts = []
            for call in function_calls:
                fn = TOOL_DISPATCH.get(call.name)
                result = fn(dict(call.args)) if fn else {"error": f"unknown tool {call.name}"}
                function_response_parts.append(
                    types.Part.from_function_response(
                        name=call.name,
                        response={"result": result},
                    )
                )
            response = chat.send_message(function_response_parts)
            continue

        # No more function calls — extract the final text/JSON decision
        final_text = response.text.strip() if response.text else ""
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

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: set GEMINI_API_KEY in your environment before running the agent.")
        sys.exit(1)

    client = genai.Client(api_key=api_key)
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
