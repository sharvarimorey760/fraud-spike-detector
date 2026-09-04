# Fraud-Spike Detector — Decision Metrics & Business Impact

_Generated 2026-09-04 11:54 UTC from 258 logged decision(s), 3343 labeled transactions_

## 1. Decision accuracy vs ground truth

> Honesty note: the audit log only contains decisions for events the detector already flagged, so these metrics measure the agent's decision quality **conditional on the detector's flags** — not end-to-end recall over all transactions. Pair this report with `detection/model_eval.py` for the full-pipeline picture.

- **Decisions matched to labels:** 242/258
- **Precision:** 1.000
- **Recall:** 0.946
- **F1:** 0.972

| | Predicted intervention | Predicted dismiss |
|---|---|---|
| **Actually fraud** | 226 (TP) | 13 (FN) |
| **Actually normal** | 0 (FP) | 3 (TN) |

- **False-positive cost** (at 50 per FP): ₹0
- **Missed-fraud cost** (at 500 per FN): ₹6,500
- **Review cost** (at 20 per review): ₹4,520
- **Total cost:** ₹11,020

## 2. Business-impact simulator

_Total cost = FP×50 + FN×500 + reviews×20; sweep confidence cutoff for acting on a decision._

| Conf. cutoff | TP | FP | FN | Precision | Recall | Total cost |
|---|---|---|---|---|---|---|
| 0.00 | 226 | 0 | 13 | 1.00 | 0.95 | ₹11,020 ⭐ |
| 0.05 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.10 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.14 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.19 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.24 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.29 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.33 | 167 | 0 | 72 | 1.00 | 0.70 | ₹40,520 |
| 0.38 | 166 | 0 | 73 | 1.00 | 0.69 | ₹41,020 |
| 0.43 | 163 | 0 | 76 | 1.00 | 0.68 | ₹42,520 |
| 0.48 | 161 | 0 | 78 | 1.00 | 0.67 | ₹43,520 |
| 0.52 | 144 | 0 | 95 | 1.00 | 0.60 | ₹52,020 |
| 0.57 | 138 | 0 | 101 | 1.00 | 0.58 | ₹55,020 |
| 0.62 | 130 | 0 | 109 | 1.00 | 0.54 | ₹59,020 |
| 0.67 | 88 | 0 | 151 | 1.00 | 0.37 | ₹80,020 |
| 0.71 | 88 | 0 | 151 | 1.00 | 0.37 | ₹80,020 |
| 0.76 | 56 | 0 | 183 | 1.00 | 0.23 | ₹96,020 |
| 0.81 | 29 | 0 | 210 | 1.00 | 0.12 | ₹109,520 |
| 0.86 | 11 | 0 | 228 | 1.00 | 0.05 | ₹118,520 |
| 0.90 | 5 | 0 | 234 | 1.00 | 0.02 | ₹121,520 |
| 0.95 | 2 | 0 | 237 | 1.00 | 0.01 | ₹123,020 |
| 1.00 | 0 | 0 | 239 | 0.00 | 0.00 | ₹124,020 |

**Optimal confidence cutoff: 0.00** (total cost ₹11,020)
