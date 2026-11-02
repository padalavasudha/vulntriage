"""Business context: who owns an asset, how exposed it is, and suppressions.

A scanner only knows a package is vulnerable. Prioritization needs context:
is the asset internet-facing, is it production, who fixes it?
"""

from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path

import yaml

# ATT&CK techniques for common cloud misconfigurations, matched on check-ID keywords.
MITRE_BY_KEYWORD = [
    ("public", "T1530 Data from Cloud Storage"),
    ("cloudtrail", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs"),
    ("mfa", "T1078.004 Valid Accounts: Cloud Accounts"),
    ("access_key", "T1078.004 Valid Accounts: Cloud Accounts"),
    ("administrative_privileges", "T1078.004 Valid Accounts: Cloud Accounts"),
    ("temporary_credentials", "T1078.004 Valid Accounts: Cloud Accounts"),
    ("password_policy", "T1110 Brute Force"),
    ("accesskey", "T1078.004 Valid Accounts: Cloud Accounts"),
    ("imdsv2", "T1552.005 Unsecured Credentials: Cloud Instance Metadata API"),
    ("ingress_from_internet", "T1190 Exploit Public-Facing Application"),
    ("guardduty", "T1562 Impair Defenses"),
]

EXPOSURE_KEYWORDS = ("public", "internet")


def load_yaml(path: str | Path | None) -> dict:
    if not path or not Path(path).exists():
        return {}
    return yaml.safe_load(Path(path).read_text()) or {}


def apply_asset_context(findings, assets: dict) -> None:
    """Match each finding's resource against asset patterns (first match wins)."""
    patterns = assets.get("assets", [])
    default = assets.get("default", {})
    for f in findings:
        ctx = next((a for a in patterns if fnmatch.fnmatch(f.resource, a["match"])), default)
        f.owner = ctx.get("owner", f.owner)
        f.environment = ctx.get("environment", f.environment)
        f.exposure = ctx.get("exposure", f.exposure)
        # A misconfiguration that is itself about public exposure makes the asset exposed.
        if f.kind == "misconfiguration" and any(k in f.rule_id.lower() for k in EXPOSURE_KEYWORDS):
            f.exposure = "internet"


def apply_mitre(findings) -> None:
    for f in findings:
        if f.kind != "misconfiguration":
            continue
        rule = f.rule_id.lower()
        f.mitre = sorted({tech for key, tech in MITRE_BY_KEYWORD if key in rule})


def apply_suppressions(findings, suppressions: dict, today: date | None = None) -> None:
    """Accepted risks and verified false positives, each with a reason, an owner and an expiry date.

    Expired suppressions stop applying, so the finding comes back for review.
    """
    today = today or date.today()
    for rule in suppressions.get("suppressions", []):
        expires = rule.get("expires")
        expired = expires is not None and date.fromisoformat(str(expires)) < today
        for f in findings:
            if f.rule_id != rule.get("rule_id"):
                continue
            if not fnmatch.fnmatch(f.resource, rule.get("resource", "*")):
                continue
            if expired:
                f.suppression_note = f"Suppression expired {expires}: re-review ({rule.get('reason')})"
            else:
                f.suppressed = True
                f.suppression_note = (
                    f"{rule.get('type', 'accepted-risk')}: {rule.get('reason')} "
                    f"(owner {rule.get('owner')}, expires {expires})"
                )
