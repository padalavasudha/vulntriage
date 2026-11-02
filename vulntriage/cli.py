"""Run the pipeline: parse -> enrich -> add context -> score -> AI summary -> tickets -> reports.

Examples:
  python -m vulntriage.cli --offline                       # sample data, no network
  python -m vulntriage.cli --trivy scans/*.json --prowler scans/prowler.ocsf.json
  python -m vulntriage.cli ... --repo you/vuln-tickets --create-tickets --llm
  python -m vulntriage.cli ... --jira-url https://you.atlassian.net --jira-project SEC --create-tickets
  python -m vulntriage.cli ... --splunk-hec-url https://localhost:8088 --splunk-insecure
"""

from __future__ import annotations

import argparse
import glob
from pathlib import Path

from . import context, intel, jira, llm, parsers, report, scoring, splunk, tickets

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
CONFIG = Path(__file__).resolve().parent.parent / "config"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Vulnerability and posture triage pipeline")
    ap.add_argument("--trivy", nargs="*", default=[], help="Trivy JSON reports (globs allowed)")
    ap.add_argument("--prowler", nargs="*", default=[], help="Prowler JSON-OCSF reports")
    ap.add_argument("--assets", default=str(CONFIG / "assets.yaml"))
    ap.add_argument("--suppressions", default=str(CONFIG / "suppressions.yaml"))
    ap.add_argument("--policy", default=str(CONFIG / "policy.yaml"))
    ap.add_argument("--offline", action="store_true", help="Use sample scans and intel files")
    ap.add_argument("--out", default="out")
    ap.add_argument("--repo", help="GitHub repo for tickets, e.g. you/vuln-tickets")
    ap.add_argument("--create-tickets", action="store_true", help="Actually create issues (default: dry run)")
    ap.add_argument("--min-priority", default="P2", choices=["P1", "P2", "P3", "P4"])
    ap.add_argument("--jira-url", help="Jira Cloud site, e.g. https://you.atlassian.net (uses JIRA_EMAIL, JIRA_API_TOKEN)")
    ap.add_argument("--jira-project", help="Jira project key, e.g. SEC")
    ap.add_argument("--splunk-hec-url", help="Splunk HEC base URL, e.g. https://localhost:8088 (uses SPLUNK_HEC_TOKEN)")
    ap.add_argument("--splunk-index", help="Splunk index (default: the token's default index)")
    ap.add_argument("--splunk-insecure", action="store_true", help="Skip TLS verification (local lab only)")
    ap.add_argument("--group-by-image", action="store_true",
                    help="One ticket per container image (rebuild) instead of one per CVE")
    ap.add_argument("--llm", action="store_true", help="Add AI summaries (needs ANTHROPIC_API_KEY)")
    args = ap.parse_args(argv)

    trivy_files = [p for pattern in args.trivy for p in glob.glob(pattern)]
    prowler_files = [p for pattern in args.prowler for p in glob.glob(pattern)]
    if args.offline and not (trivy_files or prowler_files):
        trivy_files = sorted(glob.glob(str(SAMPLES / "trivy-*.json")))
        prowler_files = sorted(glob.glob(str(SAMPLES / "prowler-*.json")))

    findings = []
    for path in trivy_files:
        findings += parsers.parse_trivy(path)
    for path in prowler_files:
        findings += parsers.parse_prowler(path)
    print(f"1. Parsed {len(findings)} findings from {len(trivy_files)} Trivy and {len(prowler_files)} Prowler files")

    intel.enrich(findings, offline_dir=str(SAMPLES) if args.offline else None)
    print(f"2. Enriched with EPSS and CISA KEV ({sum(f.kev for f in findings)} on KEV)")

    context.apply_asset_context(findings, context.load_yaml(args.assets))
    context.apply_mitre(findings)
    context.apply_suppressions(findings, context.load_yaml(args.suppressions))
    print(f"3. Added asset context, ATT&CK mapping, {sum(f.suppressed for f in findings)} suppressions")

    policy = context.load_yaml(args.policy)
    scoring.score_all(findings, policy.get("sla_days"),
                      require_exploit_signal=policy.get("p1_requires_exploit_signal", True))
    open_items = [f for f in findings if f.is_open]
    counts = {p: sum(f.priority == p for f in open_items) for p in ["P1", "P2", "P3", "P4"]}
    print(f"4. Scored {len(open_items)} open findings: {counts}")

    if args.llm:
        print(f"5. AI summaries added: {llm.summarize(findings)}")

    to_ticket = tickets.group_by_image(findings, args.min_priority) if args.group_by_image else findings
    if args.create_tickets and args.jira_url and args.jira_project:
        created = jira.create_tickets(to_ticket, args.jira_url, args.jira_project, args.min_priority)
        where = "Jira"
    else:
        created = tickets.create_tickets(
            to_ticket, args.repo, args.min_priority, dry_run=not args.create_tickets
        )
        where = "GitHub" if args.create_tickets else "dry run"
    print(f"6. Tickets: {len(created)} ({where})")

    if args.splunk_hec_url:
        sent = splunk.send(findings, args.splunk_hec_url, args.splunk_index, verify_tls=not args.splunk_insecure)
        print(f"   Sent {sent} events to Splunk")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    paths = [
        report.write_findings(findings, out),
        report.write_report(findings, out, created),
        report.write_evidence(findings, out),
    ]
    print("7. Wrote " + ", ".join(str(p) for p in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
