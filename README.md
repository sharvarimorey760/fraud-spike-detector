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
[Abuse-Ring Detector]  <-- device similarity graph + Louvain community
   (detection/)            detection; co-located/bursty device clusters
                           add a ring_score signal to the risk score
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

The suite is fully hermetic (no API calls or keys) and runs on GitHub
Actions via `.github/workflows/ci.yml` on every push and pull request.

## Running the pipeline

The repo ships demo data (`data/transactions.csv` and
`detection/flagged_events.csv`) so the dashboard works out of the box;
regenerate it any time with:

```bash
# 1. Generate synthetic transaction + telemetry data
cd data
python generate_synthetic_data.py --rows 3000 --fraud_rate 0.03 --out transactions.csv

# 2. Score for anomalies
cd ../detection
python anomaly_scorer.py --in ../data/transactions.csv --out flagged_events.csv --contamination 0.10

#    Model evaluation — confusion matrix, ROC-AUC, threshold sweep:
python model_eval.py --in ../data/transactions.csv --out eval_report.md

# 3. Run the agent on a flagged event
cd ../agent
python agent_loop.py --event_index 0

# Or process every flagged event:
python agent_loop.py --all

# Limit the batch and pace calls to stay within API rate limits:
python agent_loop.py --all --limit 5 --delay 2

# Resume an interrupted batch exactly where it stopped (no duplicates):
python agent_loop.py --all --start 95 --delay 10

# 4. View everything in the dashboard
cd ../dashboard
streamlit run app.py
```

**Gemini free-tier rate limits:** the free tier allows roughly 15
requests/minute and 500 requests/day for `gemini-3.5-flash-lite`. The
agent retries 429s automatically (waiting the server-suggested delay),
and each event costs 2+ calls (investigator + critic), so use
`--delay 10` or higher for long batches and `--start N` to resume after
the daily quota resets.

## Audit report

Every decision is logged to `audit_log/decisions.jsonl` (append-only;
currently ignored entries are `alert_state.json` and `reviewed.json` — a
snapshot of `decisions.jsonl` is committed as demo data so the deployed
dashboard's Decision Audit Trail is populated out of the box). Summarize the log as markdown at any time:

```bash
python audit_log/summary_report.py                # print to console
python audit_log/summary_report.py --out report.md
python audit_log/summary_report.py --since 2026-09-03T16:00  # subset
```

## Decision metrics & business impact

Joins the audit log with ground-truth labels to answer two questions the
track brief cares about — how accurate were the agent's decisions, and
where is the cheapest operating point:

```bash
python audit_log/metrics_report.py                        # console
python audit_log/metrics_report.py --out metrics.md       # save
python audit_log/metrics_report.py --fp-cost 50 --fn-cost 500   # your costs
```

The report includes a confusion matrix, precision/recall/F1 of the agent's
decisions vs ground truth, and a **business-impact simulator** that sweeps
the confidence cutoff and reports total cost (FP × fp_cost + FN × fn_cost +
reviews × review_cost) with the optimal operating point.

> Honesty note: the audit log only covers events the detector already
> flagged, so decision metrics are conditional on the detector — pair them
> with `detection/model_eval.py` for the full-pipeline picture.

## Example: detector performance (honest metrics)

Run on 3,343 synthetic transactions (343 true fraud rows across 4 patterns:
card_testing, device_spoof, bust_out, retry_storm):

| Metric | Value |
|---|---|
| Flagged candidates | 404 (12.1%) |
| Recall (fraud caught) | 92.1% |
| Precision | 78.2% |
| False positives | 88 |
| ROC-AUC (risk score) | 0.97 |

Full evaluation — confusion matrix, ROC-AUC, and the risk-score threshold
sweep — is one command: `python detection/model_eval.py --out eval_report.md`.
The sweep shows the honest precision/recall tradeoff across cutoffs (e.g. at
cutoff 30: precision 0.86 / recall 0.93; at cutoff 60: precision 1.0 /
recall 0.44), so the flag bar is a choice backed by numbers, not a guess.

A lower flag bar catches more fraud at the cost of false positives a human
reviewer (via the `flag_for_review` / `escalate` split) would need to
triage — the `metrics_report.py` simulator turns that tradeoff into a rupee
number.

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

## Deploy to Streamlit Cloud

1. Open [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
2. **New app** → select the repo, branch `main`, main file path `dashboard/app.py` → **Deploy**.
3. After the first build, open **Advanced settings → Secrets** and add:

```
GEMINI_API_KEY = "your_key_here"
```

The dashboard already falls back to `st.secrets` when no environment
variable is set. Note that on the free tier the container filesystem is
ephemeral — `audit_log/` and `config.json` changes reset on restart; the
committed demo data keeps the dashboard fully populated regardless.

## Known limitations / what I'd improve with more time

- Data is synthetic. Real fraud patterns are noisier and more adversarial —
  the anomaly thresholds here would need retuning against real distribution.
- Ring detection uses geo-city + firmware + co-activity as device edges; a
  production version should add shared IP/CVV/device-fingerprint edges and
  re-tune community scoring against real fraud rings.
- No feedback loop yet — confirmed false positives/negatives from human
  review aren't fed back to retrain the anomaly scorer.
- Guardrail thresholds (0.5 confidence cutoff) are a reasonable starting
  point, not tuned against real cost-of-error data.
- The Gemini free tier caps usage at ~500 requests/day, so a full
  400-event batch takes a couple of days of resuming (`--start N`) or a
  paid API tier. The batch pipeline handles per-minute throttling
  automatically, but the daily cap requires waiting for the reset.

## Why this project, why this framing

I come from an IIoT background, so I naturally think about systems not just
in terms of the data they produce, but also in terms of how the underlying
device behaves. That led me to treat the payment terminal as more than just
a transaction source and instead use its own health signals—such as retry
counts, ping gaps, uptime, and firmware changes—as additional fraud signals.
These device-level patterns can reveal issues that transaction data alone
may miss, such as retry storms or device spoofing. That IIoT perspective is
what shaped the way I approached this project.
