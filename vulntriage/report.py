"""Outputs: normalized findings (JSON), a triage report (Markdown) and audit evidence (CSV)."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PRIORITIES = ["P1", "P2", "P3", "P4"]


def write_findings(findings, out_dir: Path) -> Path:
    path = out_dir / "findings.json"
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    return path


def write_evidence(findings, out_dir: Path) -> Path:
    """One row per compliance control per check: PASS and FAIL, for auditors."""
    path = out_dir / "compliance_evidence.csv"
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["collected_at", "control", "check", "resource", "region", "status"])
        for f in findings:
            if f.source != "prowler":
                continue
            for control in f.compliance or ["(no mapping)"]:
                writer.writerow([stamp, control, f.rule_id, f.resource, f.region, f.status])
    return path


def write_report(findings, out_dir: Path, tickets: list[str]) -> Path:
    open_items = [f for f in findings if f.is_open]
    by_priority = Counter(f.priority for f in open_items)
    passed = sum(1 for f in findings if f.status == "PASS")
    suppressed = [f for f in findings if f.suppressed]
    expired = [f for f in findings if f.suppression_note.startswith("Suppression expired")]
    kev = [f for f in open_items if f.kev]

    lines = [
        "# Vulnerability and posture triage report",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        "| Priority | Open findings | SLA |",
        "| --- | --- | --- |",
    ]
    sla = {f.priority: f.sla_days for f in open_items}
    for p in PRIORITIES:
        lines.append(f"| {p} | {by_priority.get(p, 0)} | {sla.get(p, '-')} days |")
    lines += [
        "",
        f"- Open findings: **{len(open_items)}** "
        f"({sum(1 for f in open_items if f.source == 'trivy')} vulnerabilities, "
        f"{sum(1 for f in open_items if f.source == 'prowler')} misconfigurations)",
        f"- Actively exploited (CISA KEV): **{len(kev)}**",
        f"- Suppressed (accepted risk or verified false positive): {len(suppressed)}",
        f"- Suppressions expired and back for review: {len(expired)}",
        f"- Posture checks passed: {passed}",
        "",
        "## Fix first (P1 and P2)",
        "",
        "| Priority | Due | Finding | Resource | Owner | Why |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    top = sorted(
        (f for f in open_items if f.priority in ("P1", "P2")),
        key=lambda f: (f.priority, -(f.cvss or 0), -(f.epss or 0)),
    )
    shown = top[:25]
    for f in shown:
        what = f"{f.rule_id} {f.package}".strip() if f.package else f.rule_id
        why = "; ".join(r.split(":")[0] for r in f.reasons)
        lines.append(f"| {f.priority} | {f.due_date} | {what} | `{f.resource}` | {f.owner} | {why} |")

    if len(top) > len(shown):
        lines.append(f"\n*{len(top) - len(shown)} more P1/P2 findings in findings.json.*")

    images = sorted({f.resource for f in open_items if f.kind == "vulnerability"})
    if images:
        lines += ["", "## By image (one rebuild fixes most of these)", "",
                  "| Image | Open | P1 | P2 | KEV | End-of-life OS |", "| --- | --- | --- | --- | --- | --- |"]
        for img in images:
            items = [f for f in open_items if f.resource == img]
            lines.append(
                f"| `{img}` | {len(items)} | {sum(f.priority == 'P1' for f in items)} | "
                f"{sum(f.priority == 'P2' for f in items)} | {sum(f.kev for f in items)} | "
                f"{'yes' if any(f.eol_os for f in items) else 'no'} |")

    if any(f.ai_summary for f in top):
        lines += ["", "## AI summaries (verify before acting)", ""]
        for f in top:
            if f.ai_summary:
                lines += [f"**{f.rule_id}** ({f.resource}): {f.ai_summary}", ""]

    if suppressed or expired:
        lines += ["", "## Suppressions", ""]
        for f in suppressed + expired:
            lines.append(f"- {f.rule_id} on `{f.resource}`: {f.suppression_note}")

    lines += ["", "## Tickets", ""] + ([f"- {t}" for t in tickets] or ["- None created"])
    path = out_dir / "report.md"
    path.write_text("\n".join(lines) + "\n")
    return path
