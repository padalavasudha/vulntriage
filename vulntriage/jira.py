"""Open remediation tickets in Jira Cloud.

Auth: an Atlassian API token (id.atlassian.com -> Security -> API tokens).
  export JIRA_EMAIL=you@example.com
  export JIRA_API_TOKEN=...

Each ticket gets two labels: `vulntriage` and `fp-<fingerprint>`. The fingerprint
label is how re-runs find existing tickets and avoid duplicates.
"""

from __future__ import annotations

import os

import requests

from .tickets import PRIORITY_ORDER, ticket_body, ticket_title


def _auth() -> tuple[str, str]:
    return os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"]


def existing_fingerprints(base_url: str, project: str) -> set[str]:
    """Collect fp-* labels from existing vulntriage tickets in the project."""
    jql = f'project = "{project}" AND labels = vulntriage'
    found: set[str] = set()
    token = None
    while True:
        params = {"jql": jql, "fields": "labels", "maxResults": 100}
        if token:
            params["nextPageToken"] = token
        # Enhanced JQL search endpoint (replaces the older /rest/api/*/search).
        resp = requests.get(f"{base_url}/rest/api/3/search/jql", params=params, auth=_auth(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for issue in data.get("issues", []):
            for label in issue.get("fields", {}).get("labels", []):
                if label.startswith("fp-"):
                    found.add(label[3:])
        token = data.get("nextPageToken")
        if not token or data.get("isLast", True):
            return found


def _jira_text(body: str) -> str:
    """Convert the Markdown ticket body to Jira wiki markup (REST API v2 accepts it)."""
    lines = [ln for ln in body.splitlines() if not ln.startswith("<!-- fingerprint")]
    return "\n".join(lines).replace("**", "*").replace("`", "{{", 1).replace("`", "}}", 1)


def create_tickets(findings, base_url: str, project: str, min_priority: str = "P2",
                   issue_type: str = "Task") -> list[str]:
    base_url = base_url.rstrip("/")
    allowed = PRIORITY_ORDER[: PRIORITY_ORDER.index(min_priority) + 1]
    seen = existing_fingerprints(base_url, project)
    created: list[str] = []
    for f in findings:
        if not (f.is_open and f.priority in allowed) or f.fingerprint in seen:
            continue
        fields = {
            "project": {"key": project},
            "issuetype": {"name": issue_type},
            "summary": ticket_title(f),
            "description": _jira_text(ticket_body(f)),
            "labels": ["vulntriage", f.priority, f.source, f"fp-{f.fingerprint}"],
            "duedate": f.due_date,
        }
        resp = requests.post(f"{base_url}/rest/api/2/issue", json={"fields": fields}, auth=_auth(), timeout=30)
        if resp.status_code == 400 and "duedate" in resp.text:
            # Some project layouts don't show the Due date field; retry without it.
            fields.pop("duedate")
            resp = requests.post(f"{base_url}/rest/api/2/issue", json={"fields": fields}, auth=_auth(), timeout=30)
        resp.raise_for_status()
        created.append(f"{base_url}/browse/{resp.json()['key']}")
    return created
