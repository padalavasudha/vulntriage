"""Send findings to Splunk through the HTTP Event Collector (HEC).

  export SPLUNK_HEC_TOKEN=...
  --splunk-hec-url https://localhost:8088

Every finding (open, suppressed and passed) becomes one event with
sourcetype `vulntriage:finding`, so you can build SLA dashboards and
correlate with other security data in Splunk.
"""

from __future__ import annotations

import json
import os
import time

import requests


def send(findings, hec_url: str, index: str | None = None, verify_tls: bool = True,
         batch_size: int = 100) -> int:
    token = os.environ["SPLUNK_HEC_TOKEN"]
    url = hec_url.rstrip("/") + "/services/collector/event"
    now = time.time()
    events = []
    for f in findings:
        event = {
            "time": now,
            "source": "vulntriage",
            "sourcetype": "vulntriage:finding",
            "host": f.account or "vulntriage",
            "event": {**f.to_dict(), "open": f.is_open},
        }
        if index:
            event["index"] = index
        events.append(event)

    sent = 0
    for i in range(0, len(events), batch_size):
        # HEC accepts several JSON events concatenated in one request body.
        body = "\n".join(json.dumps(e) for e in events[i : i + batch_size])
        resp = requests.post(
            url,
            data=body,
            headers={"Authorization": f"Splunk {token}"},
            verify=verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        sent += len(events[i : i + batch_size])
    return sent
