# SOC Investigation Portfolio — Srikanth

[![InfoSecLabs](https://img.shields.io/badge/InfoSecLabs-Level%2029-blue?style=flat-square)](https://infoseclabs.io/user/srikanth)
[![XP](https://img.shields.io/badge/XP-2880-green?style=flat-square)]()
[![Rank](https://img.shields.io/badge/Rank-%2399-orange?style=flat-square)]()
[![Score](https://img.shields.io/badge/Avg%20Score-97.5%2F100-brightgreen?style=flat-square)]()

> Real-world SOC analyst investigations completed on the InfoSecLabs platform.
> Each case documents the full triage workflow: alert analysis, evidence collection, MITRE mapping, verdict, and containment.

---

## Analyst Profile

| Field | Detail |
|---|---|
| **Platform** | InfoSecLabs SOC Analyst Training |
| **Level** | 29 |
| **XP** | 2,880 |
| **Global Rank** | #99 |
| **Avg Investigation Score** | 97.5 / 100 |
| **Tools Used** | Proofpoint, Wazuh, Elastic SIEM, Firewall Logs |

---

## Investigation Index

| ID | Alert Title | Severity | Source | MITRE | Verdict | Score |
|---|---|---|---|---|---|---|
| [INV-233](./investigations/INV-233-phishing-malicious-url/) | Phishing Attempt with Malicious URL | CRITICAL | Proofpoint | T1566 | True Positive | 100/100 |
| [INV-234](./investigations/INV-234-lateral-movement-psexec/) | Lateral Movement via PSExec | MEDIUM | Wazuh | T1570 | True Positive | 90/100 |
| [INV-235](./investigations/INV-235-fp-high-volume-traffic/) | High Volume Network Traffic | LOW | Firewall | T1020 | False Positive | 100/100 |
| [INV-236](./investigations/INV-236-brute-force-ssh/) | Credential Brute Force SSH | HIGH | Firewall | T1110 | True Positive | 100/100 |
| [INV-243](./investigations/INV-243-rdp-brute-force/) | RDP Brute Force Attack | CRITICAL | Firewall | T1110 | True Positive | 95/100 |
| [INV-3381](./investigations/INV-3381-fp-suspicious-domain/) | False Alert on Suspicious Domain | LOW | Elastic SIEM | T1071 | False Positive | 100/100 |

---

## Stats

- Total Investigations: 6
- True Positives: 4 (66.7%)
- False Positives: 2 (33.3%)
- Perfect Scores (100): 4
- Average Score: 97.5 / 100

---

*All investigations performed on the InfoSecLabs SOC simulation platform.*
