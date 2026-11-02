"""Open remediation tickets as GitHub Issues (a stand-in for Jira).

Each ticket carries the finding's fingerprint, so re-running the pipeline
never creates duplicates. Needs a GITHUB_TOKEN with Issues read/write on the repo.
"""

from __future__ import annotations

import os
import re

import requests

API = "https://api.github.com"
LABEL = "vulntriage"
FINGERPRINT_RE = re.compile(r"fingerprint: ([0-9a-f]{16})")
PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def existing_fingerprints(repo: str, token: str) -> set[str]:
    found: set[str] = set()
    url = f"{API}/repos/{repo}/issues"
    params = {"labels": LABEL, "state": "all", "per_page": 100}
    while url:
        resp = requests.get(url, headers=_headers(token), params=params, timeout=30)
        resp.raise_for_status()
        for issue in resp.json():
            found.update(FINGERPRINT_RE.findall(issue.get("body") or ""))
        url = resp.links.get("next", {}).get("url")
        params = None  # the "next" link already carries the query
    return found


def ticket_title(f) -> str:
    what = f"{f.rule_id} in {f.package}" if f.package else f.title
    return f"[{f.priority}] {what} ({f.resource})"[:250]


def ticket_body(f) -> str:
    lines = [
        f"**Priority:** {f.priority} | **Due:** {f.due_date} ({f.sla_days}-day SLA) | **Owner:** {f.owner}",
        f"**Source:** {f.source} | **Resource:** `{f.resource}` | **Environment:** {f.environment} | **Exposure:** {f.exposure}",
        "",
        f"**Finding:** {f.title}",
    ]
    if f.kind == "vulnerability":
        lines.append(
            f"**Package:** {f.package} {f.installed_version} -> fixed in {f.fixed_version or 'not yet available'}"
        )
        epss = f"{f.epss:.3f}" if f.epss is not None else "n/a"
        lines.append(f"**CVSS:** {f.cvss} | **EPSS:** {epss} | **CISA KEV:** {'yes' if f.kev else 'no'}")
    if f.mitre:
        lines.append(f"**MITRE ATT&CK:** {', '.join(f.mitre)}")
    if f.compliance:
        lines.append(f"**Compliance:** {', '.join(f.compliance[:5])}")
    lines += ["", "**Why this priority:**"] + [f"- {r}" for r in f.reasons]
    lines += ["", f"**Remediation:** {f.remediation or 'See reference'}"]
    if f.url:
        lines.append(f"**Reference:** {f.url}")
    if f.ai_summary:
        lines += ["", "**AI summary (verify before acting):**", f.ai_summary]
    lines += ["", f"<!-- fingerprint: {f.fingerprint} -->"]
    return "\n".join(lines)


def group_by_image(findings, min_priority: str = "P2"):
    """One remediation ticket per container image instead of one per CVE.

    Most container findings share a single fix: rebuild the image on a patched
    (or supported) base image. Grouping turns hundreds of tickets into a few.
    Misconfigurations: the same check failing on several resources or regions
    (for example no CloudTrail trail in 17 regions) has one fix, so it becomes one ticket.
    """
    from collections import defaultdict
    from .models import Finding

    allowed = PRIORITY_ORDER[: PRIORITY_ORDER.index(min_priority) + 1]
    by_image = defaultdict(list)
    by_check = defaultdict(list)
    for f in findings:
        if not (f.is_open and f.priority in allowed):
            continue
        (by_image[f.resource] if f.kind == "vulnerability" else by_check[f.rule_id]).append(f)

    singles = []
    for rule_id, items in sorted(by_check.items()):
        if len(items) == 1:
            singles.append(items[0])
            continue
        items.sort(key=lambda f: f.priority)
        top = items[0]
        regions = sorted({f.region for f in items if f.region})
        singles.append(Finding(
            source=top.source, kind="remediation-group", rule_id=f"fix:{rule_id}",
            title=f"{top.title} ({len(items)} resources, {len(regions)} regions)",
            resource=top.account or top.resource, severity=top.severity, owner=top.owner,
            environment=top.environment, exposure=top.exposure, mitre=top.mitre,
            compliance=top.compliance, priority=top.priority, sla_days=top.sla_days,
            due_date=min(f.due_date for f in items), region=", ".join(regions),
            reasons=top.reasons + [f"Same check failing on {len(items)} resources: one fix"],
            remediation=top.remediation,
        ))

    groups = []
    for image, items in sorted(by_image.items()):
        items.sort(key=lambda f: (f.priority, -(f.cvss or 0)))
        top = items[0]
        counts = {p: sum(f.priority == p for f in items) for p in PRIORITY_ORDER}
        kev = [f.rule_id for f in items if f.kev]
        eol = any(f.eol_os for f in items)
        fix = ("Rebuild on a supported base image (current OS is end-of-life)" if eol
               else "Rebuild on the latest patched base image and redeploy")
        groups.append(Finding(
            source="trivy", kind="remediation-group", rule_id=f"rebuild:{image}",
            title=f"{fix.split(' (')[0]} ({len(items)} findings)",
            resource=image, severity=top.severity, owner=top.owner,
            environment=top.environment, exposure=top.exposure,
            priority=top.priority, sla_days=top.sla_days, due_date=min(f.due_date for f in items),
            reasons=[f"{counts[p]} {p}" for p in PRIORITY_ORDER if counts[p]]
                    + ([f"On CISA KEV: {', '.join(kev)}"] if kev else [])
                    + [f"Highest: {f.rule_id} ({f.package}), CVSS {f.cvss}" for f in items[:5]],
            remediation=fix + ". Re-scan after the rebuild; remaining findings get their own tickets.",
        ))
    return groups + singles


def create_tickets(findings, repo: str | None, min_priority: str = "P2", dry_run: bool = True) -> list[str]:
    """Create one issue per open finding at or above min_priority. Returns created titles."""
    allowed = PRIORITY_ORDER[: PRIORITY_ORDER.index(min_priority) + 1]
    candidates = [f for f in findings if f.is_open and f.priority in allowed]
    token = os.environ.get("GITHUB_TOKEN")
    if dry_run or not repo or not token:
        return [f"(dry run) {ticket_title(f)}" for f in candidates]

    seen = existing_fingerprints(repo, token)
    created: list[str] = []
    for f in candidates:
        if f.fingerprint in seen:
            continue
        resp = requests.post(
            f"{API}/repos/{repo}/issues",
            headers=_headers(token),
            json={
                "title": ticket_title(f),
                "body": ticket_body(f),
                "labels": [LABEL, f.priority, f.source],
            },
            timeout=30,
        )
        resp.raise_for_status()
        created.append(resp.json()["html_url"])
    return created
