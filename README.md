# Fraud-Spike Detector — Device-Telemetry-Aware Fraud Investigation Agent

## Problem

Most fraud-detection systems only look at transaction data (amount, merchant,
timing). They ignore that a huge share of real-world card-present fraud
happens *through* payment terminals — physical or virtual POS devices — and
those devices leave their own telemetry trail: retry counts, protocol ping
gaps, firmware versions, uptime. That signal is usually thrown away.

This project treats the payment terminal as a first-class source of fraud
signal, not just a pipe the transaction passes through, and uses an AI agent
— not static rules — to investigate flagged events, gather context, and
recommend a bounded, explainable action.

## Architecture

```
[Synthetic POS telemetry data]
          |
          v
[Anomaly Scorer]  <-- Isolation Forest over amount, retry_count,
   (detection/)        ping_gap, uptime, ip_consistency, 5-min burst rate
          |
          v
   [flagged events]
          |
          v
[Investigation Agent]  <-- Gemini, tool-calling loop
   (agent/)               tools: get_merchant_history,
                                  get_device_pattern,
                                  get_similar_past_cases
          |
          v
   [proposed decision: fraud_type, confidence, action, reasoning]
          |
          v
[Guardrail Gate]  <-- code-level, not LLM-level
 (guardrails/)         - only 4 allowed actions, ever
                        - low confidence can never trigger strong action
                        - never a direct "block account" action
          |
          v
[Audit Log]  <-- every decision, pre/post guardrail, timestamped
(audit_log/)
          |
          v
[Dashboard]  <-- Streamlit: feed -> flags -> reasoning -> decision -> log
(dashboard/)
```

**Why detection and reasoning are separate steps:** the Isolation Forest is
cheap and runs on every transaction; the LLM agent only investigates events
that are already statistically suspicious. This keeps the AI cost proportional
to actual risk instead of calling an LLM per transaction.

**Why the guardrail is code, not prompt:** the system prompt asks the model to
stay bounded, but `guardrails/risk_gate.py` enforces it regardless of what the
model outputs — a hallucinated or overconfident model response can never
directly produce an unbounded action like closing an account.

## Setup

```bash
git clone <this-repo>
cd fraud-spike-detector
pip install -r requirements.txt

# Create a .env file with your Gemini API key (auto-loaded by the
# agent CLI and the dashboard — no manual export needed):
echo "GEMINI_API_KEY=your_key_here" > .env
```

The key is also picked up if you export it in your shell (`export
GEMINI_API_KEY=...`) — a real environment variable always takes
precedence over the `.env` file, and `.env` is git-ignored so your key
never gets committed.

## Running the tests

```bash
pytest
# or, without pytest:
python -m unittest discover -s tests -t . -v
```

## Running the pipeline

```bash
# 1. Generate synthetic transaction + telemetry data
cd data
python generate_synthetic_data.py --rows 3000 --fraud_rate 0.03 --out transactions.csv

# 2. Score for anomalies
cd ../detection
python anomaly_scorer.py --in ../data/transactions.csv --out flagged_events.csv --contamination 0.10

# 3. Run the agent on a flagged event
cd ../agent
python agent_loop.py --event_index 0

# Or process every flagged event:
python agent_loop.py --all

# Limit the batch and pace calls to stay within API rate limits:
python agent_loop.py --all --limit 5 --delay 2

# 4. View everything in the dashboard
cd ../dashboard
streamlit run app.py
```

## Example: detector performance (honest metrics)

Run on 3,365 synthetic transactions (365 true fraud rows across 4 patterns:
card_testing, device_spoof, bust_out, retry_storm):

| Contamination setting | Flagged | Recall | False positives |
|---|---|---|---|
| 0.04 | 135 | 37.0% | 0 |
| 0.10 | 337 | 90.7% | 6 |

This is a real precision/recall tradeoff, not a cherry-picked number — lower
contamination misses more fraud but has zero noise; higher contamination
catches nearly all fraud at the cost of a small false-positive rate that a
human reviewer (via the `flag_for_review` / `escalate` split) would need to
triage.

## Example: agent decision

```json
{
  "fraud_type_guess": "card_testing",
  "confidence": 0.88,
  "recommended_action": "soft_hold",
  "reasoning_summary": "Device POS-5E135EE5 issued 11 transactions under ₹20 within a 40-second window, all from a merchant whose historical average transaction is ₹2,400. Pattern matches 4 of 5 retrieved card_testing reference cases on burst size and amount range.",
  "guardrail_violations": [],
  "human_review_required": true
}
```

## Known limitations / what I'd improve with more time

- Data is synthetic. Real fraud patterns are noisier and more adversarial —
  the anomaly thresholds here would need retuning against real distribution.
- The agent currently investigates one flagged event at a time; a production
  version should batch and correlate across devices/merchants (e.g. detect a
  coordinated abuse ring, not just one bad device).
- No feedback loop yet — confirmed false positives/negatives from human
  review aren't fed back to retrain the anomaly scorer.
- Guardrail thresholds (0.5 confidence cutoff) are a reasonable starting
  point, not tuned against real cost-of-error data.

## Why this project, why this framing

I come from an IIoT background, so I naturally think about systems not just
in terms of the data they produce, but also in terms of how the underlying
device behaves. That led me to treat the payment terminal as more than just
a transaction source and instead use its own health signals—such as retry
counts, ping gaps, uptime, and firmware changes—as additional fraud signals.
These device-level patterns can reveal issues that transaction data alone
may miss, such as retry storms or device spoofing. That IIoT perspective is
what shaped the way I approached this project.
