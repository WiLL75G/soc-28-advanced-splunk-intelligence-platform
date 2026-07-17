# Advanced Splunk Detection and Hunting Library

Twelve SPL detection queries and four hunt playbooks, written against the ATT&CK matrix. What each query is validated against is stated per query, because that distinction is the difference between a rule and a draft.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Detection engineering, SPL library and hunt playbooks |
| Platform | Splunk Enterprise |
| Delivered | 12 detection queries, 4 hunt playbooks, hunting calendar |
| Coverage | 14 techniques across 7 tactics |
| Validated | 4 of 14 against telemetry I generated |
| Log Sources Assumed | Windows Events, Sysmon, proxy, firewall, DNS, auth |

## What This Is

A detection library, not a deployed platform.

The queries are written from technique knowledge and mapped to ATT&CK. Four are validated against telemetry from my own labs. The rest are not, because I have not generated pass the hash, LOLBAS abuse, or process injection on a host I own, and a query that has never seen the technique it detects is a draft with good intentions.

That distinction is stated per query rather than buried, because a library that says what it is holds up better than one that overstates and gets tested on it.

What this demonstrates: SPL fluency, detection logic design, and hunts that start from a hypothesis rather than a search bar.

What it does not: a tuned pipeline with a baseline behind it.

## Validation

**Validated against my own lab telemetry:**

Query 1, brute force. Fired against real SSH brute force in Splunk with rex extraction on linux_secure.

Query 2, password spray. Logic validated against the 4625 cross account correlation from the Windows spray lab.

Query 4, PowerShell encoded command. Validated against Sysmon EID 1 and 4104 from the Windows endpoint forensics lab, including base64 deobfuscation.

Query 9, large outbound transfer. Logic validated against the exfiltration pattern in the AI era detection lab.

**Written from technique knowledge, not validated:**

Queries 3, 5, 6, 7, 8, 10, 11, 12.

Correct in logic, untested in practice. Deploying any of them means tuning against a baseline that does not exist yet, and that is the work rather than a footnote.

## The Query Library

[queries/detection_queries.md](queries/detection_queries.md)

**Credential Access.** Brute force with risk scoring. Password spray via unique user correlation. Impossible travel.

**Execution.** PowerShell encoded command. LOLBAS.

**Persistence.** Scheduled task creation outside system processes.

**Lateral Movement.** Pass the hash via NTLM burst. SMB admin share access.

**Exfiltration.** Large outbound transfer with risk scoring.

**Hunting.** Process injection into sensitive processes. C2 beacon via connection regularity. Shadow copy deletion.

The pair worth reading together is Query 1 and Query 2. Same event ID, opposite correlation. Brute force counts failures *within* an account. Spray counts distinct accounts hit *by* a source. A rule tuned for one is blind to the other, and that is the mistake most rule sets make.

## The Hunt Playbooks

[playbooks/threat_hunting_playbook.md](playbooks/threat_hunting_playbook.md)

**Hunt 1, LOLBAS.** Signed binaries used maliciously. Expected result in a clean environment is zero, which makes it a cheap hunt with a clear success condition.

**Hunt 2, credential dumping.** LSASS access and shadow copy deletion. A hit on the second one is not a finding, it is a countdown.

**Hunt 3, C2 communication.** Beacon regularity and rarely seen domains. Behavioural rather than signature based, and honest about what a jittered beacon defeats.

**Hunt 4, insider threat.** Bulk collection and off hours access. The hardest of the four, because every action is authorised and nothing fires.

## Why Hunts and Not Just Rules

Rules answer questions you already asked. Hunts ask new ones.

Every hunt starts with a hypothesis, a claim about what an attacker would be doing right now if they were here. The query is only how you check.

**Hunts that find nothing get documented.** That is the point, not the consolation. A zero result hunt is a negative finding with a timestamp, and it is what lets you state that the environment was clean against a technique on a date. Undocumented, it proves nothing.

A calendar turns hunting from something someone does when the queue is quiet into a programme with coverage you can point at.

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Query or Hunt | Validated |
| --- | --- | --- | --- | --- |
| Credential Access | Brute force | T1110 | Query 1 | Yes |
| Credential Access | Password spraying | T1110.003 | Query 2 | Yes |
| Credential Access | OS credential dumping, LSASS | T1003.001 | Hunt 2 | No |
| Initial Access | Valid accounts | T1078 | Query 3 | No |
| Execution | PowerShell | T1059.001 | Query 4 | Yes |
| Defence Evasion | System binary proxy execution | T1218 | Query 5, Hunt 1 | No |
| Defence Evasion | Process injection | T1055 | Query 10 | No |
| Persistence | Scheduled task | T1053.005 | Query 6 | No |
| Lateral Movement | Pass the hash | T1550.002 | Query 7 | No |
| Lateral Movement | SMB admin shares | T1021.002 | Query 8 | No |
| Command and Control | Application layer protocol | T1071 | Query 11, Hunt 3 | No |
| Collection | Data staged | T1074 | Hunt 4 | No |
| Exfiltration | Exfiltration over C2 channel | T1041 | Query 9, Hunt 4 | Yes |
| Impact | Inhibit system recovery | T1490 | Query 12, Hunt 2 | No |

4 of 14 validated. The other 10 are written correctly and untested, and the table says so.

## Honest Assessment

Ten of these have never fired against the technique they detect.

That is not a flaw in the logic, it is an absence of ground truth, and the two are hard to tell apart from the outside. A query that looks right and has never been tested is exactly what an untuned rule looks like on the day before it floods a queue.

The four validated ones are the four where I generated the attack, watched the detection fire, and know what the false positive rate looks like. The rest need the same treatment, and that is a lab per technique, not a tuning pass.

Three known limits, stated rather than discovered:

Query 3, impossible travel, will fire on VPN and CGNAT. The exclusion list is the work, and it does not exist yet.

Query 11 catches commodity beacons. A jittered beacon defeats it by design.

Hunt 4 uses absolute thresholds where it needs per user baselines. Absolute thresholds on insider hunting produce accusations, not findings.

## Where It Goes Next

Generate each unvalidated technique in the lab and run its query against real telemetry. Pass the hash and LOLBAS first, since both are cheap to reproduce.

Baseline before tuning. A threshold set without knowing normal volume is a guess wearing a number.

Build the impossible travel exclusion list before that query goes near a queue.

Convert validated queries to scheduled searches with alert actions.

Re run the coverage table with the validated column filled in. That is the real measure of this repo's progress.

## Repository Structure

```
soc-28-advanced-splunk-intelligence-platform/
├── README.md
├── queries/
│   └── detection_queries.md
└── playbooks/
    └── threat_hunting_playbook.md
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-@WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
