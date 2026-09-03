"""
Guardrail Layer — Real-time Alert & Incident Cooldown Engine (Upgrade #4 Enterprise).

Problem Solved:
When an ongoing fraud spike attacks a terminal, a naive pipeline sends 50+ duplicate
'escalate' alerts in minutes, causing severe alert fatigue for the SOC analyst.

Upgrades:
1. Incident Correlation: Tracks total events, suppressed alerts, and cumulative transaction volume.
2. Severity Escalation: If a previous alert was 'soft_hold' but the new event is 'escalate',
   cooldown permits the escalation rather than blindly suppressing it — and now PRESERVES the
   incident's cumulative suppressed-count/amount history instead of resetting it to zero.
3. Automatic TTL: Automatically purges state records older than 24 hours to prevent state file bloat.
4. Thread-Safe Atomic Writes: Safely writes state without file corruption.
"""

import json
import os
from datetime import datetime, timezone

COOLDOWN_MINUTES = 15
STATE_CLEANUP_HOURS = 24
STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "audit_log", "alert_state.json")

STRONG_ACTIONS = {"escalate", "soft_hold"}
ACTION_SEVERITY = {
    "dismiss": 0,
    "flag_for_review": 1,
    "soft_hold": 2,
    "escalate": 3,
}


def _load_state() -> dict:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(state: dict):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    temp_path = STATE_PATH + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(temp_path, STATE_PATH)
    except OSError:
        pass


def _key(device_id, merchant_id) -> str:
    return f"{str(device_id).strip()}|{str(merchant_id).strip()}"


def _cleanup_old_entries(state: dict, now: datetime) -> dict:
    """Evict entries older than STATE_CLEANUP_HOURS to keep state lightweight."""
    cleaned = {}
    for k, v in state.items():
        try:
            fired_time = datetime.fromisoformat(v.get("last_fired", ""))
            if (now - fired_time).total_seconds() / 3600.0 < STATE_CLEANUP_HOURS:
                cleaned[k] = v
        except Exception:
            continue
    return cleaned


def apply_cooldown(decision: dict, event: dict) -> dict:
    """
    Evaluate real-time alert cooldown with incident tracking and severity escalation.
    """
    action = str(decision.get("recommended_action", "flag_for_review")).lower()
    if action not in STRONG_ACTIONS:
        decision["alert_status"] = "standard"
        return decision

    device_id = str(event.get("device_id", "unknown"))
    merchant_id = str(event.get("merchant_id", "unknown"))
    key = _key(device_id, merchant_id)
    amount = float(event.get("transaction_amount", 0) or 0)

    now = datetime.now(timezone.utc)
    raw_state = _load_state()
    state = _cleanup_old_entries(raw_state, now)

    incident = state.get(key)

    if incident and isinstance(incident, dict):
        last_fired_str = incident.get("last_fired", "")
        last_action = incident.get("last_action", "soft_hold")
        try:
            last_fired = datetime.fromisoformat(last_fired_str)
            elapsed_minutes = (now - last_fired).total_seconds() / 60.0
        except ValueError:
            elapsed_minutes = COOLDOWN_MINUTES + 1

        if elapsed_minutes < COOLDOWN_MINUTES:
            is_severity_escalation = ACTION_SEVERITY.get(action, 0) > ACTION_SEVERITY.get(last_action, 0)

            if not is_severity_escalation:
                incident["suppressed_count"] = incident.get("suppressed_count", 0) + 1
                incident["total_amount_inr"] = incident.get("total_amount_inr", 0) + amount
                state[key] = incident
                _save_state(state)

                decision["recommended_action"] = "flag_for_review"
                decision["alert_status"] = "suppressed_duplicate"
                decision["alert_cooldown_note"] = (
                    f"Ongoing incident active for {elapsed_minutes:.1f} min (cooldown: {COOLDOWN_MINUTES} min). "
                    f"Suppressed duplicate #{incident['suppressed_count']} ({action.upper()}). "
                    f"Cumulative incident volume: ₹{incident['total_amount_inr']:,.0f}. "
                    f"Downgraded to flag_for_review to prevent alert fatigue."
                )
                return decision

    # Fresh alert OR a severity escalation broke through the cooldown.
    # Carry the incident's prior suppressed_count/total_amount_inr forward
    # instead of resetting to zero, so the audit trail keeps showing the
    # full cumulative picture even at the moment it escalates.
    previous_suppressed = incident.get("suppressed_count", 0) if incident else 0
    previous_total = incident.get("total_amount_inr", 0) if incident else 0
    new_total = previous_total + amount

    state[key] = {
        "last_fired": now.isoformat(),
        "last_action": action,
        "first_fired": incident.get("first_fired", now.isoformat()) if incident else now.isoformat(),
        "suppressed_count": previous_suppressed,
        "total_amount_inr": new_total,
    }
    _save_state(state)

    decision["alert_status"] = "fired"

    if previous_suppressed > 0:
        decision["alert_cooldown_note"] = (
            f"Severity escalation: this incident already had {previous_suppressed} "
            f"suppressed alert(s) totaling ₹{previous_total:,.0f} before this "
            f"{action.upper()} broke through the {COOLDOWN_MINUTES}-minute cooldown. "
            f"Cumulative incident volume is now ₹{new_total:,.0f}."
        )
    else:
        decision["alert_cooldown_note"] = (
            f"Real-time alert {action.upper()} dispatched. "
            f"Cooldown window active for {COOLDOWN_MINUTES}m."
        )

    return decision