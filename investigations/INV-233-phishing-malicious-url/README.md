# INV-233 — Phishing Attempt with Malicious URL

| Field | Detail |
|---|---|
| **Alert ID** | INV-233 |
| **Severity** | CRITICAL |
| **Source** | Proofpoint |
| **MITRE** | T1566 - Phishing |
| **Verdict** | True Positive |
| **Score** | 100 / 100 |

## Scenario

An email flagged by Proofpoint contained a suspicious URL (http://secure-bank.com/login) sent from noreply@secure-bank.com, indicating a credential harvesting phishing attempt.

## Raw Log

```json
{
  "timestamp": "2023-10-01T09:15:30Z",
  "event_type": "email_received",
  "src_ip": "198.51.100.22",
  "email_sender": "noreply@secure-bank.com",
  "url": "http://secure-bank.com/login",
  "username": "target_user"
}
```

## Investigation Steps

1. Reviewed Proofpoint alert on incoming email
2. Analysed sender domain - secure-bank.com uses HTTP, not HTTPS, indicating credential harvesting
3. Source IP 198.51.100.22 flagged as suspicious with no business justification
4. Confirmed phishing indicators: spoofed bank domain, insecure HTTP login URL
5. Verdict: True Positive - active phishing campaign

## MITRE ATT&CK

- Tactic: Initial Access
- Technique: T1566 - Phishing
- Sub-technique: T1566.002 - Spearphishing Link

## Verdict

TRUE POSITIVE - Phishing email with malicious login URL designed to steal credentials.

## Containment Actions

- Block sender domain at email gateway
- Block source IP at perimeter firewall
- Quarantine email from target mailbox
- Notify and brief target user
- Scan environment for similar emails

## Evidence

| Type | Value | Notes |
|---|---|---|
| IP | 198.51.100.22 | Source IP of phishing email |
| Domain | secure-bank.com | Spoofed banking domain |
| URL | http://secure-bank.com/login | Credential harvesting page |
| Email | noreply@secure-bank.com | Spoofed sender |
