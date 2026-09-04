# Fraud-Spike Detector — Decision Metrics & Business Impact

_Generated 2026-09-04 02:37 UTC from 142 logged decision(s), 3343 labeled transactions_

## 1. Decision accuracy vs ground truth

> Honesty note: the audit log only contains decisions for events the detector already flagged, so these metrics measure the agent's decision quality **conditional on the detector's flags** — not end-to-end recall over all transactions. Pair this report with `detection/model_eval.py` for the full-pipeline picture.

- **Decisions matched to labels:** 126/142
- **Precision:** 1.000
- **Recall:** 1.000
- **F1:** 1.000

| | Predicted intervention | Predicted dismiss |
|---|---|---|
| **Actually fraud** | 126 (TP) | 0 (FN) |
| **Actually normal** | 0 (FP) | 0 (TN) |

- **False-positive cost** (at 50 per FP): ₹0
- **Missed-fraud cost** (at 500 per FN): ₹0
- **Review cost** (at 20 per review): ₹2,520
- **Total cost:** ₹2,520

## 2. Business-impact simulator

_Total cost = FP×50 + FN×500 + reviews×20; sweep confidence cutoff for acting on a decision._

| Conf. cutoff | TP | FP | FN | Precision | Recall | Total cost |
|---|---|---|---|---|---|---|
| 0.00 | 126 | 0 | 0 | 1.00 | 1.00 | ₹2,520 ⭐ |
| 0.05 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.10 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.14 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.19 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.24 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.29 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.33 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.38 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.43 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.48 | 103 | 0 | 23 | 1.00 | 0.82 | ₹14,020 |
| 0.52 | 88 | 0 | 38 | 1.00 | 0.70 | ₹21,520 |
| 0.57 | 88 | 0 | 38 | 1.00 | 0.70 | ₹21,520 |
| 0.62 | 83 | 0 | 43 | 1.00 | 0.66 | ₹24,020 |
| 0.67 | 59 | 0 | 67 | 1.00 | 0.47 | ₹36,020 |
| 0.71 | 59 | 0 | 67 | 1.00 | 0.47 | ₹36,020 |
| 0.76 | 43 | 0 | 83 | 1.00 | 0.34 | ₹44,020 |
| 0.81 | 29 | 0 | 97 | 1.00 | 0.23 | ₹51,020 |
| 0.86 | 11 | 0 | 115 | 1.00 | 0.09 | ₹60,020 |
| 0.90 | 5 | 0 | 121 | 1.00 | 0.04 | ₹63,020 |
| 0.95 | 2 | 0 | 124 | 1.00 | 0.02 | ₹64,520 |
| 1.00 | 0 | 0 | 126 | 0.00 | 0.00 | ₹65,520 |

**Optimal confidence cutoff: 0.00** (total cost ₹2,520)
