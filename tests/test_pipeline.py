from datetime import date
from pathlib import Path

from vulntriage import cli, context, parsers, scoring
from vulntriage.models import Finding

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def vuln(**kw):
    base = dict(source="trivy", kind="vulnerability", rule_id="CVE-2000-0001", title="t",
                resource="img:1", severity="HIGH", package="pkg", fixed_version="1.1")
    base.update(kw)
    return Finding(**base)


def test_kev_forces_p1_even_when_cvss_is_moderate():
    f = vuln(cvss=6.5, kev=True, epss=0.02)
    scoring.score(f, today=date(2026, 11, 1))
    assert f.priority == "P1"
    assert f.due_date == "2026-11-08"


def test_critical_cvss_on_internal_asset_with_low_epss_is_deprioritized():
    f = vuln(cvss=9.8, epss=0.004, exposure="internal")
    scoring.score(f)
    assert f.priority == "P3"
    assert any("unlikely exploitation" in r for r in f.reasons)


def test_internet_exposure_and_high_epss_raise_priority():
    f = vuln(cvss=7.5, epss=0.5, exposure="internet")
    scoring.score(f)
    assert f.priority == "P1"


def test_identity_misconfiguration_gets_extra_point():
    f = Finding(source="prowler", kind="misconfiguration", rule_id="iam_root_mfa_enabled",
                title="t", resource="arn:aws:iam::1:root", severity="CRITICAL")
    context.apply_mitre([f])
    scoring.score(f)
    assert f.priority == "P1"


def test_expired_suppression_does_not_hide_finding():
    f = vuln(rule_id="CVE-2023-5678", resource="shop-api:1.4")
    rules = {"suppressions": [{"rule_id": "CVE-2023-5678", "resource": "shop-api:*",
                               "reason": "x", "owner": "y", "expires": "2026-09-30"}]}
    context.apply_suppressions([f], rules, today=date(2026, 11, 1))
    assert not f.suppressed and "expired" in f.suppression_note


def test_active_suppression_hides_finding():
    f = vuln(rule_id="CVE-2022-0778", resource="batch-worker:2.0")
    rules = {"suppressions": [{"rule_id": "CVE-2022-0778", "resource": "batch-worker:*",
                               "reason": "x", "owner": "y", "expires": "2027-03-31"}]}
    context.apply_suppressions([f], rules, today=date(2026, 11, 1))
    assert f.suppressed and not f.is_open


def test_parsers_read_samples():
    trivy = parsers.parse_trivy(SAMPLES / "trivy-shop-api.json")
    assert any(f.rule_id == "CVE-2021-44228" and f.cvss == 10.0 for f in trivy)
    prowler = parsers.parse_prowler(SAMPLES / "prowler-aws.ocsf.json")
    assert {f.status for f in prowler} == {"FAIL", "PASS"}
    assert all(f.compliance for f in prowler)


def test_fingerprint_is_stable():
    assert vuln().fingerprint == vuln().fingerprint
    assert vuln().fingerprint != vuln(resource="img:2").fingerprint


def test_offline_end_to_end(tmp_path):
    assert cli.main(["--offline", "--out", str(tmp_path)]) == 0
    report = (tmp_path / "report.md").read_text()
    assert "CVE-2021-44228" in report
    assert (tmp_path / "compliance_evidence.csv").read_text().count("\n") > 1


class FakeResp:
    def __init__(self, data=None, status=200, text=""):
        self._data, self.status_code, self.text = data or {}, status, text

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def test_jira_creates_only_new_tickets(monkeypatch):
    from vulntriage import jira
    monkeypatch.setenv("JIRA_EMAIL", "a@b.c")
    monkeypatch.setenv("JIRA_API_TOKEN", "t")
    a = vuln(rule_id="CVE-1", cvss=9.8, kev=True)
    b = vuln(rule_id="CVE-2", cvss=9.8, kev=True)
    for f in (a, b):
        scoring.score(f)
    monkeypatch.setattr(jira.requests, "get", lambda *a_, **k: FakeResp(
        {"issues": [{"fields": {"labels": ["vulntriage", f"fp-{a.fingerprint}"]}}], "isLast": True}))
    posted = []
    def fake_post(url, json=None, **k):
        posted.append(json["fields"])
        return FakeResp({"key": "SEC-1"}, status=201)
    monkeypatch.setattr(jira.requests, "post", fake_post)
    created = jira.create_tickets([a, b], "https://x.atlassian.net", "SEC")
    assert created == ["https://x.atlassian.net/browse/SEC-1"]
    assert posted[0]["summary"].startswith("[P1] CVE-2")
    assert f"fp-{b.fingerprint}" in posted[0]["labels"] and posted[0]["duedate"] == b.due_date


def test_splunk_hec_batches_events(monkeypatch):
    import json as _json
    from vulntriage import splunk
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "tok")
    bodies = []
    def fake_post(url, data=None, headers=None, **k):
        assert url.endswith("/services/collector/event") and headers["Authorization"] == "Splunk tok"
        bodies.append(data)
        return FakeResp()
    monkeypatch.setattr(splunk.requests, "post", fake_post)
    findings = [vuln(rule_id=f"CVE-{i}") for i in range(150)]
    assert splunk.send(findings, "https://localhost:8088", batch_size=100) == 150
    assert len(bodies) == 2
    first = _json.loads(bodies[0].splitlines()[0])
    assert first["sourcetype"] == "vulntriage:finding" and first["event"]["rule_id"] == "CVE-0"


def test_p1_needs_exploitation_signal():
    f = vuln(cvss=9.8, epss=0.02, exposure="internet")      # 4 + 1 = 5 points, but no KEV, low EPSS
    scoring.score(f)
    assert f.priority == "P2" and any("capped at P2" in r for r in f.reasons)
    g = vuln(cvss=9.8, epss=0.02, exposure="internet")
    scoring.score(g, require_exploit_signal=False)
    assert g.priority == "P1"


def test_same_cve_in_two_packages_is_one_finding(tmp_path):
    import json
    report = {"ArtifactName": "img:1", "Metadata": {"OS": {"EOSL": True}}, "Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "curl", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 7.5}}},
        {"VulnerabilityID": "CVE-1", "PkgName": "libcurl4", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 9.8}}}]}]}
    path = tmp_path / "t.json"
    path.write_text(json.dumps(report))
    findings = parsers.parse_trivy(path)
    assert len(findings) == 1
    assert findings[0].package == "curl, libcurl4" and findings[0].cvss == 9.8 and findings[0].eol_os


def test_group_by_image_makes_one_ticket_per_image():
    from vulntriage import tickets
    items = [vuln(rule_id=f"CVE-{i}", cvss=9.8, kev=True, resource="nginx:1.21") for i in range(5)]
    for f in items:
        scoring.score(f)
    groups = tickets.group_by_image(items)
    assert len(groups) == 1 and groups[0].priority == "P1" and "5 findings" in groups[0].title


def misconfig(rule_id, severity="HIGH", region="us-east-1", resource="arn:aws:iam::1:x"):
    return Finding(source="prowler", kind="misconfiguration", rule_id=rule_id, title=rule_id,
                   resource=resource, severity=severity, region=region, account="1")


def test_admin_policy_and_logging_gaps_score_higher():
    admin = misconfig("iam_aws_attached_policy_no_administrative_privileges", "CRITICAL")
    trail = misconfig("cloudtrail_multi_region_enabled", "HIGH")
    pw = misconfig("iam_password_policy_symbol", "MEDIUM")
    context.apply_mitre([admin, trail, pw])
    for f in (admin, trail, pw):
        scoring.score(f)
    assert admin.priority == "P1"
    assert trail.priority == "P2" and any("Logging" in r for r in trail.reasons)
    assert pw.priority == "P4" and pw.mitre == ["T1110 Brute Force"]


def test_same_check_in_many_regions_is_one_ticket():
    from vulntriage import tickets
    items = [misconfig("cloudtrail_multi_region_enabled", region=f"r{i}") for i in range(17)]
    context.apply_mitre(items)
    for f in items:
        scoring.score(f)
    groups = tickets.group_by_image(items)
    assert len(groups) == 1 and "17 regions" in groups[0].title