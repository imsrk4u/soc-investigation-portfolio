# INV-304 — Spear Phishing Email Detected

| Field | Detail |
|---|---|
| **Alert ID** | INV-304 |
| **Severity** | MEDIUM |
| **Source** | Email Gateway |
| **MITRE** | T1566.002 - Spearphishing Link |
| **Verdict** | True Positive |
| **Score** | 100 / 100 |

## Scenario

An email gateway security alert triggered on a spear phishing email directed at internal company infrastructure. The message used lookalike techniques from `invoice@quickbooks-intuit.co` attempting to lure the recipient into opening a hazardous file attachment (`03 Report.docm`) and visiting a deceptive external URL impersonating a vendor support team.

## Raw Log

```json
{
  "timestamp": "2023-10-05T14:22:35Z",
  "email_id": "1234567890",
  "from": "invoice@quickbooks-intuit.co",
  "to": "john.doe@company.com",
  "subject": "Urgent: Q3 Financial Report",
  "attachment": "03 Report.docm",
  "attachment_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "url": "http://paypal-support.com/securelogin",
  "source_ip": "203.0.113.45",
  "destination_ip": "192.168.1.25"
}
```

## Investigation Steps

1. **Alert Validation:** Analyzed the inbound transaction flagged by the secure email gateway containing high-risk indicator attributes.
2. **Sender Profile Inspection:** Validated that `invoice@quickbooks-intuit.co` is utilizing an unauthorized lookalike domain designed to replicate official Intuit bookkeeping portals.
3. **Attachment Evaluation:** Evaluated file `03 Report.docm`. The macro-enabled document extension strongly indicates an initial stage delivery technique for malware execution. MD5 Hash verified via OSINT: `d41d8cd98f00b204e9800998ecf8427e`.
4. **URL Investigation:** Confirmed embedded URL `http://paypal-support.com/securelogin` points directly to an untrusted domain configured for fraud/credential theft.
5. **Verdict:** True Positive — Targeted spear phishing attempt incorporating file execution and web threats.

## MITRE ATT&CK

- **Tactic:** Initial Access
- **Technique:** T1566 - Phishing
- **Sub-technique:** T1566.002 - Spearphishing Link
- **Sub-technique:** T1566.001 - Spearphishing Attachment

## Verdict

TRUE POSITIVE - Valid spear phishing attack utilizing a weaponized `.docm` macro report, a fraudulent domain (`quickbooks-intuit.co`), and a financial spoof link.

## Containment Actions

- Block attacker source IP infrastructure `203.0.113.45` at edge boundaries.
- Append domain blocklist policies globally for `quickbooks-intuit.co` and `paypal-support.com`.
- Add attachment file hash `d41d8cd98f00b204e9800998ecf8427e` to EDR/AV block policies to prevent host execution.
- Isolate host `192.168.1.25` immediately to sweep for active macro-spawned processes.
- Retract the message from target user `john.doe@company.com` mailbox files.

## Evidence

| Type | Value | Notes |
|---|---|---|
| EMAIL | invoice@quickbooks-intuit.co | Fraudulent source address |
| HASH | d41d8cd98f00b204e9800998ecf8427e | Macro-enabled malware dropper hash |
| URL | http://paypal-support.com/securelogin | Fake support credential collector |
| IP | 203.0.113.45 | Threat origin server routing IP |

## Detection Query (Splunk SPL)

```spl
index=email sourcetype=gateway_logs 
| search (from="*quickbooks-intuit.co" OR attachment_hash="d41d8cd98f00b204e9800998ecf8427e" OR url="*paypal-support.com*")
| table timestamp, from, to, subject, attachment, url, source_ip
```