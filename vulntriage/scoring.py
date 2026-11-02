"""Deterministic, explainable prioritization.

Every point added or removed is recorded in `finding.reasons`, so anyone can
see exactly why a finding got its priority. The LLM never changes priority.

  Base points from severity (CVSS for vulnerabilities, scanner severity for
  misconfigurations): critical 4, high 3, medium 2, low 1.
  +1 if the asset is internet-facing
  +1 if a misconfiguration exposes identities or credentials (ATT&CK T1078 / T1552)
  +1 if a misconfiguration removes logging or detection (ATT&CK T1562): without it,
     every other incident goes unseen
  +1 if EPSS >= 0.10 (likely to be exploited soon)
  -1 if EPSS < 0.01 and the asset is internal (unlikely to be exploited)
  On CISA KEV (actively exploited): always P1
  P1 for a vulnerability also needs a sign of real-world exploitation
  (KEV, or EPSS >= 0.10); otherwise it is capped at P2. (Policy, can be turned off.)

  Points -> priority: 5+ = P1, 4 = P2, 3 = P3, 2 or less = P4
"""

from __future__ import annotations

from datetime import date, timedelta

DEFAULT_SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
SEVERITY_POINTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 2}


def _base_points(f) -> tuple[int, str]:
    if f.kind == "vulnerability" and f.cvss is not None:
        if f.cvss >= 9.0:
            return 4, f"CVSS {f.cvss} (critical)"
        if f.cvss >= 7.0:
            return 3, f"CVSS {f.cvss} (high)"
        if f.cvss >= 4.0:
            return 2, f"CVSS {f.cvss} (medium)"
        return 1, f"CVSS {f.cvss} (low)"
    points = SEVERITY_POINTS.get(f.severity, 2)
    return points, f"Scanner severity {f.severity}"


def _points_to_priority(points: int) -> str:
    if points >= 5:
        return "P1"
    if points == 4:
        return "P2"
    if points == 3:
        return "P3"
    return "P4"


def score(f, sla_days: dict[str, int] | None = None, today: date | None = None,
          require_exploit_signal: bool = True) -> None:
    sla_days = sla_days or DEFAULT_SLA_DAYS
    today = today or date.today()
    points, reason = _base_points(f)
    f.reasons = [f"{reason}: +{points}"]

    if f.exposure == "internet":
        points += 1
        f.reasons.append("Internet-facing asset: +1")
    if any(t.startswith(("T1078", "T1552")) for t in f.mitre):
        points += 1
        f.reasons.append("Identity or credential exposure: +1")
    if any(t.startswith("T1562") for t in f.mitre):
        points += 1
        f.reasons.append("Logging or detection gap: +1")
    if f.epss is not None:
        if f.epss >= 0.10:
            points += 1
            f.reasons.append(f"EPSS {f.epss:.2f} (likely exploitation): +1")
        elif f.epss < 0.01 and f.exposure != "internet":
            points -= 1
            f.reasons.append(f"EPSS {f.epss:.3f} on an internal asset (unlikely exploitation): -1")

    f.priority = _points_to_priority(points)
    exploit_signal = f.kev or (f.epss is not None and f.epss >= 0.10)
    if require_exploit_signal and f.kind == "vulnerability" and f.priority == "P1" and not exploit_signal:
        f.priority = "P2"
        f.reasons.append("No sign of exploitation (not on KEV, EPSS < 0.10): capped at P2")
    if f.kev:
        f.priority = "P1"
        f.reasons.append("On CISA KEV (actively exploited): forced to P1")
    if f.kind == "vulnerability" and not f.fixed_version:
        f.reasons.append("No fixed version yet: SLA applies to a mitigation")
    if f.eol_os:
        f.reasons.append("End-of-life OS: rebuild on a supported base image")

    f.sla_days = sla_days[f.priority]
    f.due_date = (today + timedelta(days=f.sla_days)).isoformat()


def score_all(findings, sla_days=None, today=None, require_exploit_signal=True) -> None:
    for f in findings:
        if f.status == "FAIL":
            score(f, sla_days, today, require_exploit_signal)
