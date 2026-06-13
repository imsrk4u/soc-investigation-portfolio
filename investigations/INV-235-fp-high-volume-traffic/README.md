# INV-235 — False Positive: High Volume Network Traffic Alert

| Field | Detail |
|---|---|
| **Alert ID** | INV-235 |
| **Severity** | LOW |
| **Source** | Firewall |
| **MITRE** | T1020 - Automated Exfiltration (initial suspicion) |
| **Verdict** | False Positive |
| **Score** | 100 / 100 |

## Scenario

A firewall alert triggered on high volume outbound traffic from data-server (192.168.1.10) to external IP 203.0.113.100, attributed to service_account. Pattern suggested automated exfiltration but investigation confirmed legitimate scheduled activity.

## Raw Log

```json
{
  "timestamp": "2023-10-01T13:45:12Z",
  "event_type": "network_connection",
  "src_ip": "192.168.1.10",
  "dst_ip": "203.0.113.100",
  "username": "service_account",
  "hostname": "data-server"
}
```

## Investigation Steps

1. Reviewed firewall alert for high-volume outbound traffic from data-server
2. Source 192.168.1.10 is a known internal data-server
3. Destination 203.0.113.100 mapped to an authorised backup/transfer endpoint
4. Account is service_account - a non-human automated account, consistent with scheduled jobs
5. Traffic pattern consistent with scheduled batch transfer, not human-driven exfiltration
6. Verdict: False Positive - legitimate scheduled data transfer

## MITRE ATT&CK

- Tactic: Exfiltration (initial suspicion only)
- Technique: T1020 - Automated Exfiltration
- Actual Activity: Authorised scheduled data transfer

## Verdict

FALSE POSITIVE - Authorised service_account performing a scheduled automated data transfer to an approved endpoint.

## Actions Taken

- Reviewed firewall logs for traffic pattern
- Verified service_account is a known, authorised account
- Confirmed destination IP is an approved transfer endpoint
- Closed alert as False Positive

## Tuning Recommendation

Whitelist this specific traffic pattern to reduce alert fatigue:
- Source: 192.168.1.10 (data-server)
- Destination: 203.0.113.100
- Account: service_account
- Time window: scheduled job window
