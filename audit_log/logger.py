"""
Audit trail. Every decision the agent makes — pre and post guardrail —
is logged here with a timestamp, so any action can be traced back to
the exact reasoning that produced it. This satisfies the "must
demonstrate an audit trail" requirement from the track brief.
"""

import json
import os
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "decisions.jsonl")


def log_decision(event: dict, decision: dict):
    entry = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "transaction_id": event.get("transaction_id"),
        "device_id": event.get("device_id"),
        "merchant_id": event.get("merchant_id"),
        "decision": decision,
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def read_recent_logs(limit: int = 50):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH) as f:
        lines = f.readlines()
    entries = [json.loads(line) for line in lines[-limit:]]
    return entries
