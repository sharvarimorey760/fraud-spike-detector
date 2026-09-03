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
REVIEWED_PATH = os.path.join(os.path.dirname(__file__), "reviewed.json")


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


# ---------------------------------------------------------------------
# Human-review queue
# ---------------------------------------------------------------------
#
# decisions.jsonl is append-only (each line is one immutable logged
# decision), so "reviewed" status can't be written back onto a line in
# place. Instead we track reviewed transaction IDs in a small separate
# file and cross-reference it when building the pending-review list.

def _load_reviewed() -> dict:
    if not os.path.exists(REVIEWED_PATH):
        return {}
    try:
        with open(REVIEWED_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_reviewed(reviewed: dict):
    with open(REVIEWED_PATH, "w") as f:
        json.dump(reviewed, f, indent=2)


def mark_reviewed(transaction_id: str, note: str = ""):
    """Record that a human reviewer has signed off on a logged decision."""
    reviewed = _load_reviewed()
    reviewed[str(transaction_id)] = {
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "note": note or "",
    }
    _save_reviewed(reviewed)


def get_pending_review(limit: int = 100):
    """
    Return logged decisions that required human review (escalate /
    soft_hold / flag_for_review) and have not yet been marked reviewed.

    Looks further back into the log than `limit` so an old unreviewed
    decision doesn't silently fall off the pending list just because
    newer decisions were logged after it.
    """
    logs = read_recent_logs(limit=max(limit * 5, 500))
    reviewed = _load_reviewed()

    pending = [
        entry
        for entry in logs
        if entry.get("decision", {}).get("human_review_required")
        and str(entry.get("transaction_id")) not in reviewed
    ]

    return pending[-limit:]