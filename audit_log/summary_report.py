"""
Audit log report generator.

Reads audit_log/decisions.jsonl and prints a markdown report of the
pipeline's decisions: action/risk/pattern breakdowns, guardrail
enforcement, confidence, and human-review load.

Usage:
    python audit_log/summary_report.py                # print to stdout
    python audit_log/summary_report.py --out report.md
    python audit_log/summary_report.py --since 2026-09-03T16:00  # only entries after a timestamp
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decisions.jsonl")


def load_entries(since=None):
    if not os.path.exists(LOG_PATH):
        return []
    entries = []
    with open(LOG_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if since and entry.get("logged_at", "") < since:
                continue
            entries.append(entry)
    return entries


def pct(part, total):
    return f"{part / total * 100:.1f}%" if total else "—"


def build_report(entries):
    total = len(entries)
    decisions = [e.get("decision", {}) for e in entries]

    actions = Counter(d.get("recommended_action") for d in decisions)
    risks = Counter(d.get("risk_level") for d in decisions)
    patterns = Counter(d.get("fraud_type_guess") for d in decisions)
    reason_codes = Counter(
        code for d in decisions for code in d.get("reason_codes", [])
    )

    guardrail_passed = sum(
        1 for d in decisions if d.get("guardrail_status") == "passed"
    )
    guardrail_adjusted = sum(
        1 for d in decisions if d.get("guardrail_status") == "adjusted"
    )
    human_review = sum(1 for d in decisions if d.get("human_review_required"))
    critic_confirm = sum(
        1 for d in decisions if d.get("critic_verdict") == "confirm"
    )
    critic_escalate = sum(
        1 for d in decisions if d.get("critic_verdict") == "escalate_for_human"
    )

    confidences = [d.get("confidence", 0) for d in decisions]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    strong_actions = sum(
        1 for d in decisions if d.get("recommended_action") in ("soft_hold", "escalate")
    )

    lines = []
    lines.append("# Fraud-Spike Detector — Audit Log Report")
    lines.append("")
    lines.append(
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"from {total} logged decision(s)_"
    )
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append(f"- **Decisions logged:** {total}")
    lines.append(
        f"- **Strong actions taken (soft_hold/escalate):** {strong_actions} ({pct(strong_actions, total)})"
    )
    lines.append(
        f"- **Routed to human review:** {human_review} ({pct(human_review, total)})"
    )
    lines.append(
        f"- **Guardrail-adjusted decisions:** {guardrail_adjusted} ({pct(guardrail_adjusted, total)}) — "
        f"{guardrail_passed} passed clean"
    )
    lines.append(f"- **Average confidence:** {avg_conf:.3f}")
    lines.append("")

    lines.append("## Recommended actions")
    lines.append("")
    lines.append("| Action | Count | Share |")
    lines.append("|---|---|---|")
    for action, count in actions.most_common():
        lines.append(f"| `{action}` | {count} | {pct(count, total)} |")
    lines.append("")

    lines.append("## Risk levels")
    lines.append("")
    lines.append("| Level | Count | Share |")
    lines.append("|---|---|---|")
    for level, count in risks.most_common():
        lines.append(f"| {level} | {count} | {pct(count, total)} |")
    lines.append("")

    lines.append("## Fraud patterns identified")
    lines.append("")
    lines.append("| Pattern | Count | Share |")
    lines.append("|---|---|---|")
    for pattern, count in patterns.most_common():
        lines.append(f"| `{pattern}` | {count} | {pct(count, total)} |")
    lines.append("")

    lines.append("## Safety layer")
    lines.append("")
    lines.append("| Signal | Count |")
    lines.append("|---|---|")
    lines.append(f"| Guardrails passed | {guardrail_passed} |")
    lines.append(f"| Guardrails adjusted | {guardrail_adjusted} |")
    lines.append(f"| Critic confirmed | {critic_confirm} |")
    lines.append(f"| Critic escalated to human | {critic_escalate} |")
    lines.append("")

    lines.append("## Top local risk signals")
    lines.append("")
    lines.append("| Reason code | Occurrences |")
    lines.append("|---|---|")
    for code, count in reason_codes.most_common(10):
        lines.append(f"| `{code}` | {count} |")
    lines.append("")

    lines.append("## Recent decisions")
    lines.append("")
    lines.append("| Logged at (UTC) | Transaction | Action | Confidence | Risk | Pattern |")
    lines.append("|---|---|---|---|---|---|")
    for entry in entries[-15:]:
        d = entry.get("decision", {})
        tid = str(entry.get("transaction_id", ""))[:12]
        lines.append(
            f"| {str(entry.get('logged_at', ''))[11:19]} | `{tid}` | "
            f"`{d.get('recommended_action')}` | {d.get('confidence', 0)} | "
            f"{d.get('risk_level')} | `{d.get('fraud_type_guess')}` |"
        )
    lines.append("")

    return "\n".join(lines)


def main():
    # Windows consoles default to cp1252 and garble characters like — and ₹;
    # force UTF-8 output so the report renders correctly on any platform.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=str, default=None, help="Write report to a file")
    parser.add_argument("--since", type=str, default=None, help="Only entries logged after this ISO timestamp")
    args = parser.parse_args()

    entries = load_entries(since=args.since)
    report = build_report(entries)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Wrote report ({len(entries)} decisions) → {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()