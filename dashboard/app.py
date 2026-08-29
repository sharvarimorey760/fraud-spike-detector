"""
Streamlit dashboard: transaction feed -> flagged spikes -> agent reasoning
-> decision -> audit log. This is the screen you'll record for the demo video.

Run with:
    streamlit run app.py
"""

import json
import os
import sys

import pandas as pd
import streamlit as st

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "agent"))
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from audit_log.logger import read_recent_logs  # noqa: E402

st.set_page_config(page_title="Fraud-Spike Detector — Agent Dashboard", layout="wide")

st.title("🛡️ Fraud-Spike Detector — Agent Dashboard")
st.caption(
    "Payment-terminal telemetry → anomaly detection → AI investigation agent → "
    "bounded decision → audit trail. Defense-only."
)

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "transactions.csv")
FLAGGED_PATH = os.path.join(os.path.dirname(__file__), "..", "detection", "flagged_events.csv")

tab1, tab2, tab3 = st.tabs(["📊 Overview", "🚩 Flagged Events", "📜 Audit Log"])

with tab1:
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        col1, col2, col3 = st.columns(3)
        col1.metric("Total transactions", len(df))
        col2.metric("Unique devices", df["device_id"].nunique())
        col3.metric("Unique merchants", df["merchant_id"].nunique())
        st.subheader("Recent transactions")
        st.dataframe(df.tail(20), use_container_width=True)
    else:
        st.warning("No transaction data found. Run data/generate_synthetic_data.py first.")

with tab2:
    if os.path.exists(FLAGGED_PATH):
        flagged = pd.read_csv(FLAGGED_PATH)
        st.subheader(f"Flagged events ({len(flagged)})")
        st.dataframe(flagged, use_container_width=True)
        st.info(
            "These were surfaced by the Isolation Forest anomaly scorer. "
            "Run agent/agent_loop.py on any of these to see the agent investigate."
        )
    else:
        st.warning("No flagged events found. Run detection/anomaly_scorer.py first.")

with tab3:
    st.subheader("Agent decision audit trail")
    logs = read_recent_logs(limit=100)
    if not logs:
        st.info("No agent decisions logged yet. Run agent/agent_loop.py to generate some.")
    else:
        for entry in reversed(logs):
            decision = entry["decision"]
            action = decision.get("recommended_action", "unknown")
            color = {
                "dismiss": "🟢",
                "flag_for_review": "🟡",
                "soft_hold": "🟠",
                "escalate": "🔴",
            }.get(action, "⚪")
            with st.expander(
                f"{color} {entry['transaction_id']} — {action} "
                f"(confidence: {decision.get('confidence', '?')})"
            ):
                st.write(f"**Merchant:** {entry['merchant_id']}  |  **Device:** {entry['device_id']}")
                st.write(f"**Logged at:** {entry['logged_at']}")
                st.write(f"**Fraud type guess:** {decision.get('fraud_type_guess')}")
                st.write(f"**Reasoning:** {decision.get('reasoning_summary')}")
                if decision.get("guardrail_violations"):
                    st.warning(f"Guardrail adjustments: {decision['guardrail_violations']}")
                st.json(decision)
