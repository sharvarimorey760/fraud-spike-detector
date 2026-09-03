"""
Fraud Investigation Tools — Advanced Risk Intelligence Layer

These tools provide grounded context to the AI investigation agent.

The agent can inspect:
1. Merchant history
2. Device behavior
3. Similar confirmed fraud cases
4. Transaction velocity / burst patterns
5. Geo / IP consistency
6. Cross-merchant device activity
7. Merchant device network (other devices, same merchant, same time window)
8. Risk signals and evidence summary

The tools are read-only and defense-only.
They never execute payment, blocking, account closure, or other irreversible actions.
"""

import pandas as pd


_DF = None


# ---------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------

def load_dataset(path: str):
    """
    Load the transaction dataset used by the investigation tools.
    """
    global _DF

    _DF = pd.read_csv(path)

    if "timestamp" in _DF.columns:
        _DF["timestamp"] = pd.to_datetime(
            _DF["timestamp"],
            errors="coerce",
            utc=True,
        )

    return _DF


def _ensure_dataset():
    if _DF is None:
        raise RuntimeError(
            "Dataset is not loaded. Call load_dataset(path) before using tools."
        )


# ---------------------------------------------------------------------
# 1. Merchant history
# ---------------------------------------------------------------------

def get_merchant_history(merchant_id: str) -> dict:
    """
    Return merchant-level transaction statistics and historical fraud signals.
    """
    _ensure_dataset()

    rows = _DF[_DF["merchant_id"].astype(str) == str(merchant_id)]

    if rows.empty:
        return {
            "merchant_id": merchant_id,
            "found": False,
        }

    fraud_count = 0

    if "label" in rows.columns:
        fraud_count = int(
            (rows["label"].astype(str).str.lower() == "fraud").sum()
        )

    return {
        "merchant_id": merchant_id,
        "found": True,
        "total_transactions": int(len(rows)),
        "avg_amount": round(float(rows["transaction_amount"].mean()), 2),
        "max_amount": round(float(rows["transaction_amount"].max()), 2),
        "unique_devices_used": int(rows["device_id"].nunique()),
        "prior_fraud_flags": fraud_count,
        "fraud_rate": round(
            fraud_count / max(1, len(rows)),
            4,
        ),
    }


# ---------------------------------------------------------------------
# 2. Device behavior
# ---------------------------------------------------------------------

def get_device_pattern(device_id: str) -> dict:
    """
    Return historical behavior of a POS/device.
    """
    _ensure_dataset()

    rows = _DF[_DF["device_id"].astype(str) == str(device_id)]

    if rows.empty:
        return {
            "device_id": device_id,
            "found": False,
        }

    firmware_versions = []

    if "firmware_version" in rows.columns:
        firmware_versions = sorted(
            rows["firmware_version"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

    cities = []

    if "geo_city" in rows.columns:
        cities = sorted(
            rows["geo_city"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

    return {
        "device_id": device_id,
        "found": True,
        "total_transactions": int(len(rows)),
        "avg_retry_count": round(
            float(rows["retry_count"].mean()),
            2,
        ),
        "max_retry_count": int(
            rows["retry_count"].max()
        ),
        "avg_ping_gap_sec": round(
            float(rows["last_ping_gap_sec"].mean()),
            2,
        ),
        "firmware_versions_seen": firmware_versions,
        "cities_seen": cities,
        "home_city_guess": (
            rows["geo_city"].mode().iloc[0]
            if "geo_city" in rows.columns and not rows.empty
            else None
        ),
    }


# ---------------------------------------------------------------------
# 3. Similar confirmed fraud cases
# ---------------------------------------------------------------------

def get_similar_past_cases(
    fraud_type_hint: str,
    limit: int = 5,
) -> dict:
    """
    Retrieve previously confirmed fraud cases matching a suspected pattern.
    """

    _ensure_dataset()

    if "fraud_type" not in _DF.columns:
        return {
            "fraud_type_hint": fraud_type_hint,
            "matches_found": 0,
            "cases": [],
        }

    if "label" not in _DF.columns:
        return {
            "fraud_type_hint": fraud_type_hint,
            "matches_found": 0,
            "cases": [],
        }

    rows = _DF[
        (_DF["label"].astype(str).str.lower() == "fraud")
        & (
            _DF["fraud_type"].astype(str).str.lower()
            == str(fraud_type_hint).lower()
        )
    ]

    sample = rows.head(limit)

    available_columns = [
        "transaction_id",
        "transaction_amount",
        "retry_count",
        "last_ping_gap_sec",
        "ip_consistency_flag",
    ]

    available_columns = [
        c for c in available_columns if c in sample.columns
    ]

    return {
        "fraud_type_hint": fraud_type_hint,
        "matches_found": int(len(rows)),
        "cases": sample[available_columns].to_dict(
            orient="records"
        ),
    }


# ---------------------------------------------------------------------
# 4. Transaction velocity / burst analysis
# ---------------------------------------------------------------------

def get_transaction_velocity(
    device_id: str,
    merchant_id: str,
    timestamp: str,
) -> dict:
    """
    Check how many transactions occurred around the current event.

    This helps identify card-testing and retry-storm style bursts.
    """

    _ensure_dataset()

    if "timestamp" not in _DF.columns:
        return {
            "error": "timestamp column is unavailable"
        }

    event_time = pd.to_datetime(
        timestamp,
        errors="coerce",
        utc=True,
    )

    if pd.isna(event_time):
        return {
            "error": "invalid event timestamp"
        }

    rows = _DF[
        (_DF["device_id"].astype(str) == str(device_id))
        | (_DF["merchant_id"].astype(str) == str(merchant_id))
    ].copy()

    if rows.empty:
        return {
            "transactions_last_1_min": 0,
            "transactions_last_5_min": 0,
            "transactions_last_15_min": 0,
        }

    time_diff = event_time - rows["timestamp"]

    past = rows[
        (time_diff >= pd.Timedelta(0))
        & (time_diff <= pd.Timedelta(minutes=15))
    ]

    count_1m = int(
        (event_time - past["timestamp"]
         <= pd.Timedelta(minutes=1)).sum()
    )

    count_5m = int(
        (event_time - past["timestamp"]
         <= pd.Timedelta(minutes=5)).sum()
    )

    count_15m = int(len(past))

    return {
        "device_id": device_id,
        "merchant_id": merchant_id,
        "transactions_last_1_min": count_1m,
        "transactions_last_5_min": count_5m,
        "transactions_last_15_min": count_15m,
        "velocity_risk": (
            "high"
            if count_5m >= 10
            else "medium"
            if count_5m >= 5
            else "low"
        ),
    }


# ---------------------------------------------------------------------
# 5. Geo / IP consistency
# ---------------------------------------------------------------------

def check_geo_ip_consistency(
    device_id: str,
    geo_city: str,
    ip_consistency_flag: int,
) -> dict:
    """
    Compare the current location/IP signal against historical device behavior.
    """

    _ensure_dataset()

    rows = _DF[
        _DF["device_id"].astype(str) == str(device_id)
    ]

    historical_cities = []

    if not rows.empty and "geo_city" in rows.columns:
        historical_cities = (
            rows["geo_city"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

    city_match = str(geo_city) in historical_cities

    ip_flag = int(ip_consistency_flag)

    if ip_flag == 0 and not city_match:
        risk = "high"
    elif ip_flag == 0 or not city_match:
        risk = "medium"
    else:
        risk = "low"

    return {
        "current_city": geo_city,
        "historical_cities": historical_cities,
        "city_seen_before": city_match,
        "ip_consistency_flag": ip_flag,
        "geo_ip_risk": risk,
    }


# ---------------------------------------------------------------------
# 6. Cross-merchant device activity
# ---------------------------------------------------------------------

def get_cross_merchant_activity(device_id: str) -> dict:
    """
    Detect whether one device is operating across many merchants.

    Useful for identifying suspicious device reuse without automatically
    declaring the device fraudulent.
    """

    _ensure_dataset()

    rows = _DF[
        _DF["device_id"].astype(str) == str(device_id)
    ]

    if rows.empty:
        return {
            "device_id": device_id,
            "found": False,
            "merchant_count": 0,
            "merchants": [],
        }

    merchants = (
        rows["merchant_id"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    return {
        "device_id": device_id,
        "found": True,
        "merchant_count": len(merchants),
        "merchants": merchants[:20],
        "cross_merchant_risk": (
            "high"
            if len(merchants) >= 5
            else "medium"
            if len(merchants) >= 3
            else "low"
        ),
    }


# ---------------------------------------------------------------------
# 7. Upgrade #6 — Network evidence (multi-device correlation, SAME merchant,
#    SAME time window)
# ---------------------------------------------------------------------

def get_merchant_device_network(
    merchant_id: str,
    exclude_device_id: str,
    timestamp: str,
    window_minutes: int = 60,
) -> dict:
    """
    Check whether OTHER devices at the same merchant are ALSO showing
    elevated retry/ping-gap telemetry AROUND THE SAME TIME as the
    current event — the signature of a coordinated attack hitting
    multiple terminals at one merchant, rather than one device just
    having a bad day.

    Time-windowed on purpose: without a time restriction, a merchant
    that ever had a single flaky device months ago would look
    permanently "suspicious" even when nothing is happening right now.
    `exclude_device_id` is required (not optional) so the current
    device's own signal can never be used as "network evidence" for
    itself — that would be circular reasoning.

    A single suspicious device is comparatively weak evidence. Multiple
    devices at the same merchant independently showing the same kind of
    anomaly in the same window is much stronger evidence of a real
    attack, and is exactly the kind of cross-entity signal a
    single-transaction view can never see.
    """

    _ensure_dataset()

    if "timestamp" not in _DF.columns:
        return {"error": "timestamp column is unavailable"}

    event_time = pd.to_datetime(timestamp, errors="coerce", utc=True)

    if pd.isna(event_time):
        return {"error": "invalid event timestamp"}

    window_start = event_time - pd.Timedelta(minutes=window_minutes)

    rows = _DF[
        (_DF["merchant_id"].astype(str) == str(merchant_id))
        & (_DF["device_id"].astype(str) != str(exclude_device_id))
        & (_DF["timestamp"] >= window_start)
        & (_DF["timestamp"] <= event_time)
    ].copy()

    if rows.empty:
        return {
            "merchant_id": merchant_id,
            "found": False,
            "window_minutes": window_minutes,
            "other_devices_checked": 0,
            "devices_with_elevated_telemetry": [],
            "network_risk": "low",
        }

    retry_mask = rows["retry_count"].fillna(0) >= 6
    ping_mask = rows["last_ping_gap_sec"].fillna(0) >= 8

    if "ip_consistency_flag" in rows.columns:
        suspicious_mask = (
            retry_mask
            | ping_mask
            | (rows["ip_consistency_flag"].fillna(1) == 0)
        )
    else:
        # Column may be absent on schema drift — never call .fillna on a
        # bare int default (that crashes); just skip the IP signal.
        suspicious_mask = retry_mask | ping_mask

    suspicious_devices = (
        rows.loc[suspicious_mask, "device_id"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    total_devices = rows["device_id"].nunique()

    return {
        "merchant_id": merchant_id,
        "found": True,
        "window_minutes": window_minutes,
        "other_devices_checked": int(total_devices),
        "devices_with_elevated_telemetry": suspicious_devices[:15],
        "suspicious_device_count": len(suspicious_devices),
        "network_risk": (
            "high" if len(suspicious_devices) >= 3
            else "medium" if len(suspicious_devices) >= 1
            else "low"
        ),
    }


# ---------------------------------------------------------------------
# 8. Evidence / risk signal summary
# ---------------------------------------------------------------------

def build_risk_signal_summary(event: dict) -> dict:
    """
    Produce a deterministic summary of observable risk signals.

    This is NOT an ML prediction.
    It simply converts telemetry into explainable evidence that the AI can use.
    """

    amount = float(event.get("transaction_amount", 0) or 0)
    retries = int(event.get("retry_count", 0) or 0)
    ping_gap = float(event.get("last_ping_gap_sec", 0) or 0)
    ip_flag = int(event.get("ip_consistency_flag", 1) or 1)
    burst = int(event.get("burst_count_5min", 0) or 0)

    signals = []

    if retries >= 8:
        signals.append("high_retry_count")

    if ping_gap >= 8:
        signals.append("large_device_ping_gap")

    if ip_flag == 0:
        signals.append("ip_inconsistency")

    if burst >= 5:
        signals.append("high_5min_transaction_burst")

    if amount >= 15000:
        signals.append("high_transaction_amount")

    return {
        "signal_count": len(signals),
        "signals": signals,
        "risk_signal_level": (
            "high"
            if len(signals) >= 3
            else "medium"
            if len(signals) >= 1
            else "low"
        ),
    }


# ---------------------------------------------------------------------
# Gemini tool schema
# ---------------------------------------------------------------------

TOOL_SCHEMA = [

    {
        "name": "get_merchant_history",
        "description": (
            "Get merchant transaction history, average amount, device count, "
            "previous fraud flags and fraud rate."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "merchant_id": {
                    "type": "string"
                }
            },
            "required": ["merchant_id"],
        },
    },

    {
        "name": "get_device_pattern",
        "description": (
            "Get historical device telemetry including retries, ping gaps, "
            "firmware versions and geographic locations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string"
                }
            },
            "required": ["device_id"],
        },
    },

    {
        "name": "get_similar_past_cases",
        "description": (
            "Retrieve confirmed historical fraud cases matching a suspected "
            "fraud pattern."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "fraud_type_hint": {
                    "type": "string",
                    "enum": [
                        "card_testing",
                        "device_spoof",
                        "bust_out",
                        "retry_storm",
                        "velocity_attack",
                        "coordinated_fraud",
                        "unusual_behavior",
                        "unclear",
                    ],
                }
            },
            "required": ["fraud_type_hint"],
        },
    },

    {
        "name": "get_transaction_velocity",
        "description": (
            "Analyze transaction velocity around the event for the device "
            "and merchant over 1, 5 and 15 minute windows."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string"
                },
                "merchant_id": {
                    "type": "string"
                },
                "timestamp": {
                    "type": "string"
                },
            },
            "required": [
                "device_id",
                "merchant_id",
                "timestamp",
            ],
        },
    },

    {
        "name": "check_geo_ip_consistency",
        "description": (
            "Compare the current transaction city and IP consistency signal "
            "against historical device locations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string"
                },
                "geo_city": {
                    "type": "string"
                },
                "ip_consistency_flag": {
                    "type": "integer"
                },
            },
            "required": [
                "device_id",
                "geo_city",
                "ip_consistency_flag",
            ],
        },
    },

    {
        "name": "get_cross_merchant_activity",
        "description": (
            "Check whether the same device has been used across multiple "
            "merchants and return a risk signal."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string"
                }
            },
            "required": ["device_id"],
        },
    },

    {
        "name": "get_merchant_device_network",
        "description": (
            "Check whether OTHER devices at the same merchant were ALSO "
            "showing elevated retry/ping-gap telemetry within the same "
            "recent time window as this event — evidence of a coordinated "
            "multi-device attack rather than one bad device. Always pass "
            "the current device_id as exclude_device_id so the device's "
            "own signal is never counted as evidence against itself."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "merchant_id": {"type": "string"},
                "exclude_device_id": {"type": "string"},
                "timestamp": {"type": "string"},
            },
            "required": ["merchant_id", "exclude_device_id", "timestamp"],
        },
    },

    {
        "name": "build_risk_signal_summary",
        "description": (
            "Create an explainable deterministic summary of observable "
            "transaction risk signals. This is evidence, not a prediction."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "transaction_amount": {
                    "type": "number"
                },
                "retry_count": {
                    "type": "integer"
                },
                "last_ping_gap_sec": {
                    "type": "number"
                },
                "ip_consistency_flag": {
                    "type": "integer"
                },
                "burst_count_5min": {
                    "type": "integer"
                },
            },
            "required": [
                "transaction_amount",
                "retry_count",
                "last_ping_gap_sec",
                "ip_consistency_flag",
                "burst_count_5min",
            ],
        },
    },
]


# ---------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------

TOOL_DISPATCH = {

    "get_merchant_history":
        lambda inp:
        get_merchant_history(inp["merchant_id"]),

    "get_device_pattern":
        lambda inp:
        get_device_pattern(inp["device_id"]),

    "get_similar_past_cases":
        lambda inp:
        get_similar_past_cases(
            inp["fraud_type_hint"]
        ),

    "get_transaction_velocity":
        lambda inp:
        get_transaction_velocity(
            inp["device_id"],
            inp["merchant_id"],
            inp["timestamp"],
        ),

    "check_geo_ip_consistency":
        lambda inp:
        check_geo_ip_consistency(
            inp["device_id"],
            inp["geo_city"],
            inp["ip_consistency_flag"],
        ),

    "get_cross_merchant_activity":
        lambda inp:
        get_cross_merchant_activity(
            inp["device_id"]
        ),

    "get_merchant_device_network":
        lambda inp:
        get_merchant_device_network(
            inp["merchant_id"],
            inp["exclude_device_id"],
            inp["timestamp"],
        ),

    "build_risk_signal_summary":
        lambda inp:
        build_risk_signal_summary(inp),
}