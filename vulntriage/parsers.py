"""Turn raw scanner output into Finding objects.

Trivy:   `trivy image --format json -o out.json IMAGE`
Prowler: `prowler aws --output-formats json-ocsf`

Scanner output formats change between versions. If a field comes back empty,
inspect your file (for example `jq '.[0]' prowler.ocsf.json`) and adjust the
`.get(...)` paths below.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _norm_severity(value: str | None) -> str:
    value = (value or "").upper()
    if value == "INFORMATIONAL":
        return "LOW"
    return value if value in SEVERITIES else "UNKNOWN"


def _best_cvss(vuln: dict) -> float | None:
    """Prefer NVD's CVSS v3 score, then any vendor's v3 score."""
    cvss = vuln.get("CVSS") or {}
    nvd = cvss.get("nvd") or {}
    if nvd.get("V3Score") is not None:
        return float(nvd["V3Score"])
    for source in cvss.values():
        if isinstance(source, dict) and source.get("V3Score") is not None:
            return float(source["V3Score"])
    return None


def parse_trivy(path: str | Path) -> list[Finding]:
    """One finding per CVE per image. Packages built from the same source
    (for example curl and libcurl4) share one finding, since one fix covers them."""
    report = json.loads(Path(path).read_text())
    artifact = report.get("ArtifactName", str(path))
    eol = bool(((report.get("Metadata") or {}).get("OS") or {}).get("EOSL"))
    merged: dict[str, Finding] = {}
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "")
            if cve in merged:
                existing = merged[cve]
                pkg = vuln.get("PkgName", "")
                if pkg and pkg not in existing.package.split(", "):
                    existing.package += f", {pkg}"
                score = _best_cvss(vuln)
                if score is not None and (existing.cvss is None or score > existing.cvss):
                    existing.cvss = score
                continue
            findings.append(
                Finding(
                    source="trivy",
                    kind="vulnerability",
                    rule_id=vuln.get("VulnerabilityID", ""),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                    resource=artifact,
                    severity=_norm_severity(vuln.get("Severity")),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    cvss=_best_cvss(vuln),
                    url=vuln.get("PrimaryURL", ""),
                    remediation=(
                        f"Upgrade {vuln.get('PkgName')} to {vuln['FixedVersion']}"
                        if vuln.get("FixedVersion")
                        else "No fixed version yet: mitigate (isolate, config change) and monitor"
                    ),
                    eol_os=eol,
                )
            )
            merged[cve] = findings[-1]
    return findings


def _flatten_compliance(compliance: dict | None) -> list[str]:
    items: list[str] = []
    for framework, controls in (compliance or {}).items():
        if isinstance(controls, list):
            items.extend(f"{framework}: {c}" for c in controls)
        elif controls:
            items.append(f"{framework}: {controls}")
    return items


def parse_prowler(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):  # some versions wrap findings in an object
        data = data.get("findings", [data])
    findings: list[Finding] = []
    for item in data:
        status = (item.get("status_code") or item.get("status") or "").upper()
        if status not in {"FAIL", "PASS"}:
            continue  # skip MANUAL / MUTED / unknown
        info = item.get("finding_info") or {}
        resources = item.get("resources") or [{}]
        resource = resources[0] if resources else {}
        cloud = item.get("cloud") or {}
        findings.append(
            Finding(
                source="prowler",
                kind="misconfiguration",
                rule_id=(item.get("metadata") or {}).get("event_code") or info.get("uid", ""),
                title=info.get("title") or item.get("message", ""),
                resource=resource.get("uid") or resource.get("name") or "",
                severity=_norm_severity(item.get("severity")),
                status=status,
                region=resource.get("region") or cloud.get("region", ""),
                account=((cloud.get("account") or {}).get("uid")) or "",
                remediation=(item.get("remediation") or {}).get("desc", ""),
                compliance=_flatten_compliance((item.get("unmapped") or {}).get("compliance")),
            )
        )
    return findings
