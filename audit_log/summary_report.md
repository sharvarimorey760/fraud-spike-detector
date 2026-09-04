# Fraud-Spike Detector — Audit Log Report

_Generated 2026-09-04 11:54 UTC from 258 logged decision(s)_

## Headline

- **Decisions logged:** 258
- **Strong actions taken (soft_hold/escalate):** 66 (25.6%)
- **Routed to human review:** 233 (90.3%)
- **Guardrail-adjusted decisions:** 39 (15.1%) — 183 passed clean
- **Average confidence:** 0.488

## Recommended actions

| Action | Count | Share |
|---|---|---|
| `flag_for_review` | 167 | 64.7% |
| `soft_hold` | 63 | 24.4% |
| `dismiss` | 25 | 9.7% |
| `escalate` | 3 | 1.2% |

## Risk levels

| Level | Count | Share |
|---|---|---|
| medium | 139 | 53.9% |
| high | 65 | 25.2% |
| None | 36 | 14.0% |
| low | 17 | 6.6% |
| critical | 1 | 0.4% |

## Fraud patterns identified

| Pattern | Count | Share |
|---|---|---|
| `unclear` | 81 | 31.4% |
| `card_testing` | 75 | 29.1% |
| `velocity_attack` | 63 | 24.4% |
| `unusual_behavior` | 19 | 7.4% |
| `retry_storm` | 18 | 7.0% |
| `device_spoof` | 1 | 0.4% |
| `bust_out` | 1 | 0.4% |

## Safety layer

| Signal | Count |
|---|---|
| Guardrails passed | 183 |
| Guardrails adjusted | 39 |
| Critic confirmed | 198 |
| Critic escalated to human | 20 |

## Top local risk signals

| Reason code | Occurrences |
|---|---|
| `HIGH_TRANSACTION_BURST` | 68 |
| `AI_DECISION_UNAVAILABLE` | 63 |
| `ELEVATED_TRANSACTION_BURST` | 49 |
| `RECENT_DEVICE_RESTART` | 13 |
| `IP_INCONSISTENCY` | 13 |
| `HIGH_VALUE_TRANSACTION` | 5 |
| `ABNORMAL_PING_GAP` | 3 |
| `EXCESSIVE_RETRIES` | 2 |

## Recent decisions

| Logged at (UTC) | Transaction | Action | Confidence | Risk | Pattern |
|---|---|---|---|---|---|
| 11:18:05 | `4ba57c63-4e0` | `dismiss` | 0.35 | low | `unclear` |
| 11:19:07 | `2ab188ce-042` | `flag_for_review` | 0 | medium | `unclear` |
| 11:19:12 | `11168d89-dba` | `flag_for_review` | 0 | medium | `unclear` |
| 11:19:20 | `5fb60015-6a5` | `flag_for_review` | 0.55 | medium | `unusual_behavior` |
| 11:19:28 | `73a0b1c3-862` | `flag_for_review` | 0.72 | high | `card_testing` |
| 11:19:35 | `2c9f64d1-234` | `flag_for_review` | 0.78 | high | `card_testing` |
| 11:19:42 | `41418917-f17` | `flag_for_review` | 0.78 | high | `card_testing` |
| 11:19:52 | `b001377d-3c7` | `dismiss` | 0.35 | low | `unclear` |
| 11:20:02 | `0842fe5e-d18` | `flag_for_review` | 0.65 | medium | `card_testing` |
| 11:21:05 | `679d4b05-d40` | `dismiss` | 0.35 | low | `unclear` |
| 11:21:11 | `6ac22c02-149` | `dismiss` | 0.4 | low | `unclear` |
| 11:21:18 | `1d6ea3b0-9bc` | `dismiss` | 0.25 | low | `unclear` |
| 11:21:25 | `bfa2d7ad-569` | `dismiss` | 0.35 | low | `unclear` |
| 11:21:31 | `366229ca-06e` | `flag_for_review` | 0.58 | medium | `unusual_behavior` |
| 11:21:39 | `7c27f656-6b8` | `dismiss` | 0.42 | low | `unusual_behavior` |
