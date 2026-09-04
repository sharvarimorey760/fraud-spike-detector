# Fraud-Spike Detector — Audit Log Report

_Generated 2026-09-04 02:38 UTC from 142 logged decision(s)_

## Headline

- **Decisions logged:** 142
- **Strong actions taken (soft_hold/escalate):** 50 (35.2%)
- **Routed to human review:** 133 (93.7%)
- **Guardrail-adjusted decisions:** 25 (17.6%) — 81 passed clean
- **Average confidence:** 0.550

## Recommended actions

| Action | Count | Share |
|---|---|---|
| `flag_for_review` | 83 | 58.5% |
| `soft_hold` | 47 | 33.1% |
| `dismiss` | 9 | 6.3% |
| `escalate` | 3 | 2.1% |

## Risk levels

| Level | Count | Share |
|---|---|---|
| medium | 66 | 46.5% |
| None | 36 | 25.4% |
| high | 36 | 25.4% |
| low | 3 | 2.1% |
| critical | 1 | 0.7% |

## Fraud patterns identified

| Pattern | Count | Share |
|---|---|---|
| `velocity_attack` | 49 | 34.5% |
| `card_testing` | 39 | 27.5% |
| `unclear` | 36 | 25.4% |
| `retry_storm` | 16 | 11.3% |
| `device_spoof` | 1 | 0.7% |
| `unusual_behavior` | 1 | 0.7% |

## Safety layer

| Signal | Count |
|---|---|
| Guardrails passed | 81 |
| Guardrails adjusted | 25 |
| Critic confirmed | 95 |
| Critic escalated to human | 12 |

## Top local risk signals

| Reason code | Occurrences |
|---|---|
| `HIGH_TRANSACTION_BURST` | 68 |
| `AI_DECISION_UNAVAILABLE` | 27 |
| `ELEVATED_TRANSACTION_BURST` | 20 |
| `RECENT_DEVICE_RESTART` | 2 |
| `IP_INCONSISTENCY` | 2 |

## Recent decisions

| Logged at (UTC) | Transaction | Action | Confidence | Risk | Pattern |
|---|---|---|---|---|---|
| 18:22:23 | `c4ce81fc-5e4` | `soft_hold` | 0.78 | high | `card_testing` |
| 18:22:42 | `2799b1c8-3a4` | `flag_for_review` | 0.62 | medium | `velocity_attack` |
| 18:23:07 | `d6995672-754` | `flag_for_review` | 0.65 | medium | `velocity_attack` |
| 18:23:25 | `4913f42b-d82` | `soft_hold` | 0.78 | high | `card_testing` |
| 18:23:43 | `8e568549-c1b` | `flag_for_review` | 0 | medium | `unclear` |
| 18:24:14 | `016b1bf4-54b` | `flag_for_review` | 0.62 | medium | `velocity_attack` |
| 18:24:43 | `62668192-329` | `soft_hold` | 0.75 | high | `card_testing` |
| 18:24:58 | `6ba5a794-8d0` | `flag_for_review` | 0.65 | medium | `velocity_attack` |
| 18:25:13 | `88a6adc1-876` | `soft_hold` | 0.82 | high | `card_testing` |
| 18:25:29 | `73f2eca7-a68` | `flag_for_review` | 0.65 | medium | `velocity_attack` |
| 18:25:48 | `a6f29310-c27` | `flag_for_review` | 0.6 | medium | `velocity_attack` |
| 18:26:05 | `fd4aa0dc-cb1` | `flag_for_review` | 0 | medium | `unclear` |
| 18:27:09 | `65cfcfd5-e8b` | `soft_hold` | 0.78 | high | `card_testing` |
| 18:27:39 | `750c6be3-60a` | `soft_hold` | 0.78 | high | `card_testing` |
| 18:28:05 | `1ccbfe98-515` | `flag_for_review` | 0.65 | medium | `velocity_attack` |
