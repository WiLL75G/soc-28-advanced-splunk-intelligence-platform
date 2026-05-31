# Day 28 – SOC Tier 1 Incident Report: Advanced Splunk Intelligence Platform

---

## Incident Summary

- **Project Type:** Advanced SIEM Intelligence Platform — Detection Engineering + Threat Hunting
- **Severity:** Strategic — Production-Ready SOC Detection Capability
- **Scope:** 12 Detection Queries + 4 Threat Hunts + Full Hunting Playbook
- **Tools Used:** Splunk SPL, Sysmon, Windows Event Logs, Network/Proxy Logs
- **Status:** Complete — Advanced Detection Platform Delivered

---

## Executive Summary

The Advanced Splunk Intelligence Platform is the capstone project of the 28-day SOC analyst challenge. It delivers a production-ready detection and threat hunting platform built entirely in SPL (Splunk Processing Language). Twelve advanced detection queries were built covering credential attacks, execution techniques, persistence, lateral movement, and data exfiltration. Four threat hunting playbooks were produced covering LOLBAS, credential dumping, C2 communication, and insider threat detection. Every query is mapped to MITRE ATT&CK and includes tuning guidance and SOC analyst notes.

---

## Affected System

- **Platform:** Splunk Enterprise
- **Organisation:** Nexus Corp SOC
- **Detection Coverage:** 12 techniques across 6 MITRE ATT&CK tactics
- **Threat Hunts:** 4 proactive hunt scenarios
- **Log Sources:** Windows Events, Sysmon, Proxy, Firewall, DNS, Auth logs

---

## Investigation Methodology

---

### 1. Detection Query Library — 12 Production SPL Queries

Built and documented 12 advanced SPL detection queries across 6 attack categories.
Every query includes detection logic, tuning guidance, and analyst notes.

#### Category 1 — Credential Attack Detection
- Query 1: Brute force detection with dynamic risk scoring (T1110)
- Query 2: Password spray detection via unique user correlation (T1110.003)
- Query 3: Impossible travel detection via IP geolocation (T1078)

#### Category 2 — Execution Detection
- Query 4: PowerShell encoded command detection (T1059.001)
- Query 5: LOLBAS execution detection — certutil, mshta, regsvr32 (T1218)

#### Category 3 — Persistence Detection
- Query 6: Registry run key modification detection (T1547.001)
- Query 7: Scheduled task creation outside system processes (T1053.005)

#### Category 4 — Lateral Movement Detection
- Query 8: Pass-the-hash detection via NTLM logon analysis (T1550.002)
- Query 9: SMB admin share access detection (T1021.002)

#### Category 5 — Exfiltration Detection
- Query 10: Large outbound data transfer with risk scoring (T1041)

#### Category 6 — Threat Hunting Queries
- Query 11: Process injection hunt targeting sensitive processes (T1055)
- Query 12: C2 beacon pattern detection via connection regularity (T1071)

#### SOC Observations:

- Dynamic risk scoring in SPL lets analysts prioritise without manual review
- Password spray and brute force require different detection logic — know the difference
- C2 beacon detection uses behavioural analysis — not signatures — making it evasion-resistant

---

### 2. Threat Hunting Playbook — 4 Hunt Scenarios

Built a complete threat hunting playbook with 4 structured hunt scenarios.
Each hunt has a hypothesis, reasoning, SPL queries, and documentation template.

#### Hunt 1 — Living Off the Land (LOLBAS)
- Hypothesis: Attacker using legitimate Windows binaries to avoid AV/EDR detection
- Key technique: certutil.exe downloading files, mshta.exe executing remote scripts
- Expected result in clean environment: Zero results — any hit is high priority

#### Hunt 2 — Credential Dumping
- Hypothesis: Attacker accessing LSASS memory to harvest credentials
- Key technique: Process access to lsass.exe, volume shadow copy deletion
- Expected result: VSS deletion = ransomware imminent — CRITICAL response

#### Hunt 3 — C2 Communication
- Hypothesis: Compromised endpoint beaconing to C2 over encrypted channels
- Key technique: DNS queries to new domains, regular beacon pattern analysis
- Expected result: Regularity score > 5 = automated behaviour = C2 candidate

#### Hunt 4 — Insider Threat
- Hypothesis: Privileged user abusing access for bulk data download or exfiltration
- Key technique: Bulk file download analysis, off-hours access pattern detection
- Expected result: Off-hours logins + bulk downloads = high-priority investigation

#### SOC Observations:

- Threat hunting is proactive — it finds what alerts miss
- Every hunt starts with a hypothesis — not a query
- Documenting hunts that find nothing is as important as documenting confirmed threats
- A threat hunting calendar turns ad-hoc hunting into a systematic programme

---

## MITRE ATT&CK Coverage Map

| Tactic | Technique ID | Technique | Query/Hunt |
|---|---|---|---|
| Credential Access | T1110 | Brute Force | Query 1 |
| Credential Access | T1110.003 | Password Spray | Query 2 |
| Initial Access | T1078 | Valid Accounts | Query 3 |
| Execution | T1059.001 | PowerShell | Query 4 |
| Execution | T1218 | LOLBAS | Query 5, Hunt 1 |
| Persistence | T1547.001 | Registry Run Keys | Query 6 |
| Persistence | T1053.005 | Scheduled Task | Query 7 |
| Lateral Movement | T1550.002 | Pass-the-Hash | Query 8 |
| Lateral Movement | T1021.002 | SMB Admin Shares | Query 9 |
| Exfiltration | T1041 | Exfiltration Over C2 | Query 10 |
| Defense Evasion | T1055 | Process Injection | Query 11, Hunt 2 |
| Command & Control | T1071 | C2 Beaconing | Query 12, Hunt 3 |
| Collection | T1486 | VSS Deletion | Hunt 2 |
| Exfiltration | T1052 | Insider Exfiltration | Hunt 4 |

---

## SOC Analyst Findings

- 12 production-ready SPL detection queries built and documented
- Dynamic risk scoring implemented — analysts see priority without manual review
- Password spray and brute force detected using different correlation logic
- C2 beacon detection uses behavioural analysis — resistant to signature evasion
- 4 threat hunt scenarios documented with full SPL queries and analyst notes
- Threat hunting calendar built — daily, weekly, and monthly hunt schedule

---

## SOC Analyst Response

- Built complete Splunk detection library covering 6 MITRE ATT&CK tactics
- Implemented dynamic risk scoring across brute force and exfiltration queries
- Produced 4 threat hunting playbooks with structured hypothesis-driven methodology
- Built threat hunting calendar — converting ad-hoc hunting into systematic programme
- Documented tuning guidance for every query — reducing false positive rates
- Produced hunt documentation template — every hunt is evidence for compliance

---

## Analyst Insight

This platform represents the full arc of the 28-day challenge. Day 1 started with SSH brute force detection in Splunk. Day 28 ends with a production-ready detection and threat hunting platform that covers 14 MITRE ATT&CK techniques across 6 tactics. The difference between a SOC analyst and a detection engineer is this: analysts respond to what the platform tells them. Detection engineers build the platform that tells them. After 28 days of building, documenting, and hunting — you are no longer just an analyst. You are someone who can build the tools that other analysts depend on.

---

## Learning Outcome

- Write advanced SPL queries with dynamic risk scoring and statistical correlation
- Detect credential attacks — brute force, password spray, impossible travel, pass-the-hash
- Detect execution techniques — PowerShell encoding, LOLBAS abuse
- Detect persistence — registry run keys, scheduled tasks
- Detect lateral movement — pass-the-hash, SMB admin shares
- Detect exfiltration — large outbound transfers, C2 beaconing
- Build and execute structured threat hunts using the hypothesis-driven methodology
- Apply MITRE ATT&CK framework to detection engineering

---

## Repository Structure

```
soc-28-advanced-splunk-intelligence-platform/
├── README.md
├── queries/
│   └── detection_queries.md
├── playbooks/
│   └── threat_hunting_playbook.md
└── dashboards/
```

---

## The 28-Day SOC Portfolio — Complete

This project is the final piece of a 28-day SOC analyst portfolio
that covers every dimension of the role:

```
Days 1–6    Foundation — Linux, Networking, SIEM basics
Days 7–12   Detection — Malware analysis, Splunk, MITRE ATT&CK
Days 13–18  Investigation — PowerShell, Wireshark, Vulnerability scanning
Days 19–21  Career — Job search, Interview prep, EDR
Days 22–25  Advanced — Zero Trust, DFIR, Threat Modeling
Days 26–28  Leadership — Metrics, Compliance, Detection Engineering
```

28 projects. 28 GitHub repositories. One portfolio that proves
SOC readiness at the Tier 1 and Tier 2 level.

---

## Conclusion

The Advanced Splunk Intelligence Platform delivers 12 production-ready detection queries and 4 threat hunting playbooks — the technical foundation of a mature SOC detection programme. Every query is mapped to MITRE ATT&CK, documented with tuning guidance, and built for real-world deployment. This final project demonstrates the complete SOC analyst skillset — from writing a basic SPL query on Day 1 to building a detection engineering platform on Day 28.
