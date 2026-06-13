# INV-243 — Critical RDP Brute Force Attack Detected

| Field | Detail |
|---|---|
| **Alert ID** | INV-243 |
| **Severity** | CRITICAL |
| **Source** | Firewall |
| **MITRE** | T1110 - Brute Force |
| **Verdict** | True Positive - Confirmed Threat |
| **Score** | 95 / 100 |

## Scenario

A CRITICAL firewall alert fired on 45 failed RDP login attempts from internal IP 192.168.1.25 targeting 10.0.0.4. Multiple usernames were attempted and timeline analysis revealed a prior successful Connection established event from the same source, significantly raising severity.

## Raw Log

```json
{
  "timestamp": "2023-10-24T18:35:24Z",
  "src_ip": "192.168.1.25",
  "dest_ip": "10.0.0.4",
  "attempt_count": 45,
  "usernames_attempted": ["admin", "guest", "user1"],
  "protocol": "RDP",
  "event": "Failed login attempt",
  "related_events": [
    {
      "timestamp": "2023-10-24T18:32:03Z",
      "src_ip": "192.168.1.25",
      "event": "Login attempt"
    },
    {
      "timestamp": "2023-10-24T18:34:16Z",
      "src_ip": "192.168.1.25",
      "event": "Connection established"
    }
  ]
}
```

## Investigation Steps

1. Reviewed CRITICAL firewall alert - RDP brute force with multiple usernames
2. Source IP 192.168.1.25 is internal - indicates compromised internal host or insider threat
3. Target 10.0.0.4 is also internal - internal-to-internal RDP brute force = lateral movement
4. Multiple usernames targeted: admin, guest, user1 - dictionary/credential stuffing behaviour
5. Critical finding: Connection established event at 18:34:16Z before the alert - attacker may have already gained access
6. Geo-location unknown - possible VPN or proxy use on compromised host
7. Verdict: True Positive - active RDP brute force with likely successful connection

## MITRE ATT&CK

- Tactic: Credential Access and Lateral Movement
- Technique: T1110 - Brute Force
- Sub-technique: T1110.001 - Password Guessing
- Related: T1021.001 - Remote Desktop Protocol

## Verdict

TRUE POSITIVE - Internal host 192.168.1.25 conducting RDP brute force against 10.0.0.4. Connection established event indicates possible successful breach.

## Containment Actions

- Isolate 192.168.1.25 (attacking machine)
- Block IP 192.168.1.25 from RDP port 3389 network-wide
- Reset credentials for admin, guest, user1
- Escalate to Incident Response
- Close Alert after escalation

## Evidence

| Type | Value | OSINT | Critical |
|---|---|---|---|
| IP Source | 192.168.1.25 | Internal - Compromised Host | YES |
| IP Target | 10.0.0.4 | Internal Host | - |

## Detection Query (Splunk SPL)

```spl
index=firewall sourcetype=firewall_logs
  dest_port=3389 action="failed"
| stats count as attempt_count values(user) as usernames by src_ip, dest_ip
| where attempt_count > 5
| sort - attempt_count
```

## Lessons Learned

- Always check for Connection established events alongside brute force - it changes severity from attempted to confirmed breach.
- Internal-source RDP brute force means compromised internal host. Isolate source immediately.
- Score deduction: missed Close Alert action after escalation (-5).
- Bonus: Solved quickly (+10).
