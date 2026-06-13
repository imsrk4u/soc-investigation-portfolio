# INV-3381 — False Alert on Suspicious Domain Access

| Field | Detail |
|---|---|
| **Alert ID** | INV-3381 |
| **Severity** | LOW |
| **Source** | Elastic SIEM |
| **MITRE** | T1071 - Application Layer Protocol |
| **Verdict** | False Positive - Benign Activity |
| **Score** | 100 / 100 |

## Scenario

Elastic SIEM flagged a web request from MKT-WORKSTATION01 (192.168.77.12) by mkt_user to the domain example.com under a suspicious domain access detection rule. Investigation confirmed this was normal marketing department activity.

## Raw Log

```json
{
  "timestamp": "2026-06-05T08:20:00Z",
  "event_type": "web_request",
  "src_ip": "192.168.77.12",
  "dst_ip": null,
  "username": "mkt_user",
  "hostname": "MKT-WORKSTATION01",
  "request_body": null,
  "command_line": null,
  "domain": "example.com"
}
```

## Investigation Steps

1. Reviewed Elastic SIEM alert for suspicious domain access on example.com
2. Source host is MKT-WORKSTATION01 with mkt_user - Marketing department, known asset
3. Domain example.com is IANA-reserved, triggering the domain watchlist rule
4. No request_body - no data exfiltration
5. No command_line - no scripted or automated execution
6. dst_ip is null - DNS did not resolve or connection was blocked before establishing
7. Likely from a marketing template, test link, or web content referencing example.com
8. Verdict: False Positive - benign user activity triggered overly broad detection rule

## MITRE ATT&CK

- Tactic: Command and Control (initial suspicion only)
- Technique: T1071 - Application Layer Protocol
- Actual Activity: Benign web request to example domain

## Verdict

FALSE POSITIVE - mkt_user accessed example.com as part of normal work. No C2 indicators, no data exfiltration, no suspicious execution.

## Actions Taken

- Reviewed Elastic SIEM alert and raw log
- Confirmed mkt_user and MKT-WORKSTATION01 are authorised assets
- Verified example.com has no malicious reputation
- Closed Alert as False Positive

## Evidence

| Type | Value | OSINT | Critical |
|---|---|---|---|
| IP | 192.168.77.12 | Internal - Marketing subnet | - |
| Domain | example.com | IANA reserved domain | - |

## Tuning Recommendation

Add example.com to the SIEM allowlist scoped to the Marketing subnet only to suppress future false positives.

Elastic KQL suggestion:
```
event.type: "web_request" AND domain: "example.com" AND NOT source.ip: "192.168.77.0/24"
```
