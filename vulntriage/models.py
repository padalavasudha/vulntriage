"""The one normalized shape every scanner finding is converted into."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    source: str                 # "trivy" or "prowler"
    kind: str                   # "vulnerability" or "misconfiguration"
    rule_id: str                # CVE ID for vulnerabilities, check ID for misconfigurations
    title: str
    resource: str               # container image or cloud resource ARN
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    status: str = "FAIL"        # FAIL = open issue, PASS = control passed (kept for audit evidence)
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss: float | None = None
    region: str = ""
    account: str = ""
    remediation: str = ""
    url: str = ""
    compliance: list[str] = field(default_factory=list)
    eol_os: bool = False        # image's OS no longer gets security fixes

    # Filled in by enrichment and scoring
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    owner: str = "unassigned"
    environment: str = "unknown"
    exposure: str = "internal"
    mitre: list[str] = field(default_factory=list)
    priority: str = ""
    sla_days: int | None = None
    due_date: str = ""
    reasons: list[str] = field(default_factory=list)
    suppressed: bool = False
    suppression_note: str = ""
    ai_summary: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable ID so the same finding is never ticketed twice."""
        # Vulnerabilities are one finding per CVE per image, so the package list is not part of the key.
        package = "" if self.kind == "vulnerability" else self.package
        key = "|".join([self.source, self.rule_id, self.resource, package])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def is_open(self) -> bool:
        return self.status == "FAIL" and not self.suppressed

    def to_dict(self) -> dict:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data
