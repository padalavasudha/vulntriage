# Postmortem: [incident title]

*Blameless: focus on systems and processes, not individuals.*
*Example below is a tabletop exercise, not a real incident.*

| | |
| --- | --- |
| Severity | SEV-1 (critical) |
| Incident Commander | [name] |
| Duration | Detected 09:12, contained 09:41, resolved 14:05 (UTC) |
| Status | Resolved; follow-ups in progress |

## Summary

Two to three sentences: what happened, impact, how it was fixed.
*Tabletop example:* An internet-facing container image (`shop-api:1.4`) included Log4j 2.14.1
(CVE-2021-44228, on CISA KEV). The vulnerability pipeline flagged it as P1. The image was rebuilt
with Log4j 2.17.1 and redeployed; logs showed exploitation attempts but no successful callbacks.

## Impact

Who and what was affected, data exposure (yes / no / unknown), customer impact.

## Timeline (UTC)

| Time | Event |
| --- | --- |
| 09:12 | Pipeline opened P1 ticket; on-call acknowledged |
| 09:20 | Incident declared, IC assigned, bridge opened |
| 09:41 | Containment: WAF rule blocking `${jndi:` patterns; affected pods isolated |
| 11:30 | Patched image built, scanned clean, deployed |
| 14:05 | Hunt in SIEM complete: no successful exploitation found; incident resolved |

## Root cause and contributing factors

Ask "why" until you reach a process gap, for example: the base image was pinned
for 14 months and scanning ran only at build time, not continuously.

## What went well / what didn't

## Action items

| Action | Owner | Due | Ticket |
| --- | --- | --- | --- |
| Continuous scanning of running images, not just at build | | | |
| Detection for JNDI lookup strings in web logs | | | |
| Base-image refresh SLA (30 days) | | | |
