"""
Tools the fraud-investigation agent can call to gather context before
making a decision. Each tool queries the transaction dataset (a stand-in
for what would be live DB/API calls against payments platform's systems ).
"""

import pandas as pd

_DF = None  # lazily loaded full transaction history


def load_dataset(path: str):
    global _DF
    _DF = pd.read_csv(path)
    _DF["timestamp"] = pd.to_datetime(_DF["timestamp"])
    return _DF


def get_merchant_history(merchant_id: str) -> dict:
    """Return summary stats for a merchant's recent transaction history."""
    rows = _DF[_DF["merchant_id"] == merchant_id]
    if rows.empty:
        return {"merchant_id": merchant_id, "found": False}
    return {
        "merchant_id": merchant_id,
        "found": True,
        "total_transactions": len(rows),
        "avg_amount": round(rows["transaction_amount"].mean(), 2),
        "max_amount": round(rows["transaction_amount"].max(), 2),
        "unique_devices_used": rows["device_id"].nunique(),
        "prior_fraud_flags": int((rows["label"] == "fraud").sum()) if "label" in rows.columns else None,
    }


def get_device_pattern(device_id: str) -> dict:
    """Return summary stats for a device's telemetry history."""
    rows = _DF[_DF["device_id"] == device_id]
    if rows.empty:
        return {"device_id": device_id, "found": False}
    return {
        "device_id": device_id,
        "found": True,
        "total_transactions": len(rows),
        "avg_retry_count": round(rows["retry_count"].mean(), 2),
        "max_retry_count": int(rows["retry_count"].max()),
        "avg_ping_gap_sec": round(rows["last_ping_gap_sec"].mean(), 2),
        "firmware_versions_seen": sorted(rows["firmware_version"].unique().tolist()),
        "cities_seen": sorted(rows["geo_city"].unique().tolist()),
        "home_city_guess": rows["geo_city"].mode().iloc[0] if not rows.empty else None,
    }


def get_similar_past_cases(fraud_type_hint: str, limit: int = 5) -> dict:
    """Return a handful of past confirmed-fraud rows matching a suspected pattern,
    for the agent to compare against (few-shot grounding instead of guessing)."""
    if "fraud_type" not in _DF.columns:
        return {"cases": []}
    rows = _DF[(_DF["label"] == "fraud") & (_DF["fraud_type"] == fraud_type_hint)]
    sample = rows.head(limit)
    return {
        "fraud_type_hint": fraud_type_hint,
        "matches_found": len(rows),
        "cases": sample[[
            "transaction_id", "transaction_amount", "retry_count",
            "last_ping_gap_sec", "ip_consistency_flag"
        ]].to_dict(orient="records"),
    }


# Tool schema exposed to the LLM via the Anthropic API tool-calling interface
TOOL_SCHEMA = [
    {
        "name": "get_merchant_history",
        "description": "Get summary transaction stats for a merchant, to check whether this event fits their normal pattern.",
        "input_schema": {
            "type": "object",
            "properties": {"merchant_id": {"type": "string"}},
            "required": ["merchant_id"],
        },
    },
    {
        "name": "get_device_pattern",
        "description": "Get telemetry history for a device (retry counts, ping gaps, firmware, cities seen) to check for spoofing or tampering signals.",
        "input_schema": {
            "type": "object",
            "properties": {"device_id": {"type": "string"}},
            "required": ["device_id"],
        },
    },
    {
        "name": "get_similar_past_cases",
        "description": "Retrieve past confirmed fraud cases matching a suspected pattern type (card_testing, device_spoof, bust_out, retry_storm) to compare the current event against known examples.",
        "input_schema": {
            "type": "object",
            "properties": {
                "fraud_type_hint": {
                    "type": "string",
                    "enum": ["card_testing", "device_spoof", "bust_out", "retry_storm"],
                }
            },
            "required": ["fraud_type_hint"],
        },
    },
]

TOOL_DISPATCH = {
    "get_merchant_history": lambda inp: get_merchant_history(inp["merchant_id"]),
    "get_device_pattern": lambda inp: get_device_pattern(inp["device_id"]),
    "get_similar_past_cases": lambda inp: get_similar_past_cases(inp["fraud_type_hint"]),
}
