"""Optional AI enrichment: a plain-English summary and fix suggestion per finding.

Guardrails:
- The LLM only writes text. Priority and SLA stay rule-based and auditable.
- Only finding metadata is sent (no secrets, logs or customer data).
- Output is labeled "verify before acting" in tickets and the report.
- Any API error is skipped, so the pipeline never fails because of the LLM.

Uses the Anthropic Messages API when ANTHROPIC_API_KEY is set.
"""

from __future__ import annotations

import os

import requests

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"

PROMPT = """You are helping a security operations engineer triage a finding.
Write 2-3 short sentences for the engineering team that owns the asset:
what the risk is in plain language, and the most practical fix.
Do not change or comment on the priority. Do not invent facts beyond the data.

Finding data:
{data}"""


def summarize(findings, max_items: int = 10) -> int:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return 0
    model = os.environ.get("VULNTRIAGE_LLM_MODEL", DEFAULT_MODEL)
    done = 0
    for f in [f for f in findings if f.is_open and f.priority in ("P1", "P2")][:max_items]:
        data = {
            "id": f.rule_id,
            "title": f.title,
            "package": f.package,
            "installed": f.installed_version,
            "fixed": f.fixed_version,
            "resource_type": f.kind,
            "exposure": f.exposure,
            "cvss": f.cvss,
            "epss": f.epss,
            "actively_exploited": f.kev,
            "scanner_remediation": f.remediation,
        }
        try:
            resp = requests.post(
                API_URL,
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 200,
                    "messages": [{"role": "user", "content": PROMPT.format(data=data)}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            f.ai_summary = resp.json()["content"][0]["text"].strip()
            done += 1
        except Exception as exc:  # never fail the pipeline because of enrichment
            f.ai_summary = ""
            print(f"  LLM summary skipped for {f.rule_id}: {exc}")
    return done
