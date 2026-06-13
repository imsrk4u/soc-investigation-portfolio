# INV-234 — Suspicious Lateral Movement Detected via PSExec

| Field | Detail |
|---|---|
| **Alert ID** | INV-234 |
| **Severity** | MEDIUM |
| **Source** | Wazuh |
| **MITRE** | T1570 - Lateral Tool Transfer |
| **Verdict** | True Positive - Confirmed Threat |
| **Score** | 90 / 100 |

## Scenario

Wazuh detected a remote process execution event where admin_user on 10.0.0.20 initiated a remote process on server-02 (10.0.0.25), consistent with PSExec-based lateral movement.

## Raw Log

```json
{
  "timestamp": "2023-10-01T11:05:50Z",
  "event_type": "process_execution",
  "src_ip": "10.0.0.20",
  "dst_ip": "10.0.0.25",
  "username": "admin_user",
  "hostname": "server-02"
}
```

## Investigation Steps

1. Reviewed Wazuh alert for remote process execution
2. Both IPs are internal - confirms lateral movement, not external ingress
3. Flagged admin_user as critical - admin account used for lateral movement indicates credential compromise
4. Pattern matches PSExec/SMB-based lateral movement
5. Assessed blast radius - compromised admin has broad network access
6. Verdict: True Positive - active lateral movement

## MITRE ATT&CK

- Tactic: Lateral Movement
- Technique: T1570 - Lateral Tool Transfer
- Related: T1021.002 - SMB/Windows Admin Shares

## Verdict

TRUE POSITIVE - Attacker or compromised account moving laterally via PSExec from 10.0.0.20 to server-02.

## Containment Actions

- Isolate 10.0.0.20 and server-02
- Reset credentials for admin_user
- Collect forensics (memory dump, process list, network connections)
- Escalate to Incident Response

## Evidence

| Type | Value | OSINT | Critical |
|---|---|---|---|
| IP | 10.0.0.20 | Internal | - |
| IP | 10.0.0.25 | Internal | - |
| Username | admin_user | Internal Account | YES |

## Lessons Learned

- Respond faster - lateral movement escalates rapidly. Target under 10 minutes from detection to isolation.
- Score deduction of -10 for slow resolution time.
- Review SMB/445 traffic for the preceding 24 hours to trace initial access vector.
