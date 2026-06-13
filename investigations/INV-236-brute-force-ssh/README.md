# INV-236 — Unauthorized Access Attempt via Credential Brute Force (SSH)

| Field | Detail |
|---|---|
| **Alert ID** | INV-236 |
| **Severity** | HIGH |
| **Source** | Firewall |
| **MITRE** | T1110 - Brute Force |
| **Verdict** | True Positive |
| **Score** | 100 / 100 |

## Scenario

Firewall alert triggered when 150 failed SSH login attempts were detected from external IP 192.0.2.45 targeting 203.0.113.5 on port 22 using the admin username. The Brute Force Detection Policy rule fired, indicating an automated credential attack.

## Raw Log

```json
{
  "timestamp": "2023-10-15T02:38:47Z",
  "source_ip": "192.0.2.45",
  "destination_ip": "203.0.113.5",
  "destination_port": "22",
  "event": "Failed login attempt",
  "username": "admin",
  "attempt_count": 150,
  "device": "Firewall",
  "location": "New York, USA",
  "rule_triggered": "Brute Force Detection Policy"
}
```

## Investigation Steps

1. Reviewed firewall alert - Brute Force Detection Policy triggered on SSH port 22
2. 150 failed attempts from single source IP - clearly automated/scripted attack
3. Username targeted is admin - generic high-value account, typical of credential stuffing tools
4. Source IP 192.0.2.45 is external with no business justification
5. Attack occurred at 02:38 AM - off-hours timing consistent with automated attacks
6. Verdict: True Positive - active brute force against SSH

## MITRE ATT&CK

- Tactic: Credential Access
- Technique: T1110 - Brute Force
- Sub-technique: T1110.001 - Password Guessing

## Verdict

TRUE POSITIVE - Automated brute force attack against SSH from 192.0.2.45 with 150 failed attempts on the admin account.

## Containment Actions

- Block source IP 192.0.2.45 at perimeter firewall
- Check for any successful logins from this IP
- Disable admin account if not required
- Implement SSH account lockout policy
- Restrict SSH access to VPN or allowlist only
- Enable fail2ban on target server

## Evidence

| Type | Value | Notes |
|---|---|---|
| IP Source | 192.0.2.45 | External attacker, New York |
| IP Target | 203.0.113.5 | Public-facing server |
| Port | 22 (SSH) | Attack vector |
| Username | admin | Targeted account |
| Attempts | 150 | Automated brute force |

## Detection Query (Splunk SPL)

```spl
index=firewall sourcetype=firewall_logs
  dest_port=22 action="failed"
| stats count as attempt_count by src_ip, dest_ip, user
| where attempt_count > 10
| sort - attempt_count
```
