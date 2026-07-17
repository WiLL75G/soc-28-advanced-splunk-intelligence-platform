# Threat Hunting Playbook

Nexus Corp SOC
Analyst: William | @WilliamInCyber | GitHub: WiLL75G

---

## What Hunting Is

Hunting is looking for what the alerts missed.

```
REACTIVE   Alert fires  →  Investigate  →  Respond
PROACTIVE  Hypothesis   →  Hunt         →  Find or rule out
```

The premise is uncomfortable and deliberate: assume the environment is already compromised and go looking for the evidence. A hunter does not wait to be told.

The rules you have answer questions you already thought to ask. Hunting asks the ones you did not.

---

## The Process

```
1  HYPOTHESIS
   A claim about what an attacker would be doing right now
   if they were here. Built from threat intel, TTPs, or an
   anomaly you noticed.

2  DATA
   Which sources would hold the evidence.
   SIEM, EDR, network, proxy, DNS.

3  INVESTIGATE
   Write the SPL. Iterate. The first query is never right.

4  PATTERN
   Look for shape, not events. One failed login is noise.
   Forty seven is signal.

5  RESOLVE
   Confirmed: escalate and contain.
   Ruled out: document, and write the rule so next time
   it is an alert instead of a hunt.
```

Step 1 is the whole discipline. A query without a hypothesis is not a hunt, it is browsing.

---

## Hunt 1, Living Off the Land

**Hypothesis:** An attacker has access and is using signed Windows binaries to avoid EDR.

**Why:** certutil, mshta, and regsvr32 are legitimate Microsoft tools. AV does not flag them because there is nothing to flag. The binary is not the signal — the command line is.

**Data:** Windows 4688, Sysmon Event 1.

**Hunt 1a, certutil downloading**

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
NewProcessName="*certutil.exe*"
(CommandLine="*-urlcache*" OR CommandLine="*-decode*"
OR CommandLine="*-encode*" OR CommandLine="*http*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

Looking for:
`-urlcache -split -f` — downloading a file.
`-decode` — decoding a base64 payload.
Any certutil execution by a non IT user.

**Hunt 1b, mshta executing remote script**

```spl
index=windows EventCode=4688
NewProcessName="*mshta.exe*"
(CommandLine="*http*" OR CommandLine="*vbscript*"
OR CommandLine="*javascript*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

Looking for: mshta reaching a URL. That is remote HTA execution, and it is a delivery technique with no legitimate use case in most environments.

**Expected in a clean environment: zero.**

That is what makes this a good hunt. A clear success condition and a cheap run. Any hit is high priority by definition, because the baseline is nothing.

---

## Hunt 2, Credential Dumping

**Hypothesis:** An attacker with a foothold is reading credentials from memory to move laterally.

**Why:** Credential access is the pivot. Before it, the attacker owns one machine. After it, they own credentials, and credentials work everywhere the credentials work. Catching this stage is the difference between an incident and a breach.

**Data:** Sysmon Event 10, Windows 4656, EDR.

**Hunt 2a, LSASS memory access**

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10 TargetImage="*lsass.exe*"
| where NOT (
    SourceImage="*MsMpEng.exe*" OR
    SourceImage="*csrss.exe*" OR
    SourceImage="*wininit.exe*" OR
    SourceImage="*services.exe*"
  )
| table _time, ComputerName, SourceImage, TargetImage,
  GrantedAccess, CallTrace
| sort - _time
```

Looking for:
Any unexpected process touching LSASS. Nothing legitimate reads it.
GrantedAccess `0x1010` or `0x1410` — the credential dumping access masks.
SourceImage running from a temp directory — that settles it.

**Hunt 2b, shadow copy deletion**

```spl
index=windows EventCode=4688
(CommandLine="*vssadmin*delete*shadows*" OR
CommandLine="*wmic*shadowcopy*delete*" OR
CommandLine="*bcdedit*recoveryenabled*no*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

Looking for: any result at all.

**This one is not a finding, it is an emergency.** Shadow copy deletion is the step immediately before encryption. It removes the recovery path first, which means the ransomware is already staged and the window is minutes.

A hit here does not go in a queue. It goes to containment.

---

## Hunt 3, C2 Communication

**Hypothesis:** A compromised endpoint is beaconing on a schedule over a channel that looks normal.

**Why:** C2 blends with HTTPS by design. Signature detection fails because there is no signature — it is legitimate protocol carrying illegitimate intent. Behaviour is the only angle left.

**Data:** Proxy, firewall, NetFlow, DNS.

**Hunt 3a, queries to rarely seen domains**

```spl
index=network sourcetype=dns
| stats count as query_count, dc(src_ip) as unique_hosts by query
| where query_count < 3 AND unique_hosts < 2
| table query, query_count, unique_hosts
| sort query_count
```

Looking for:
Domains almost nobody queried. A real site has traffic. A C2 domain has one victim.
Random looking names — DGA output.

**Note:** The domain age angle needs a lookup table populated from a domain registration feed. That does not exist by default in Splunk and has to be built. This query works on rarity instead, which is available without any lookup, and it approximates the same signal.

**Hunt 3b, beaconing pattern**

```spl
index=network sourcetype=proxy
| bucket _time span=1h
| stats count as hourly_connections,
  dc(bytes_out) as unique_sizes
  by src_ip, dest_domain, _time
| where hourly_connections > 10 AND unique_sizes < 3
| eval regularity_score = round(hourly_connections / unique_sizes, 1)
| where regularity_score > 5
| eval risk = "C2 Beacon Pattern Detected"
| sort - regularity_score
```

Looking for:
Repeated identical payload sizes — a machine, not a person.
High connection count to one domain.
Regular intervals — a heartbeat.

**Limit worth naming:** mature C2 jitters both the interval and the payload size specifically to defeat this. A sophisticated beacon will not score. This catches commodity tooling, which is most of it, and misses the operator who read the same blog posts.

---

## Hunt 4, Insider Threat

**Hypothesis:** A privileged user is bulk collecting data.

**Why this is the hardest hunt:** Every action is authorised. Nothing fires. There is no rule for a person doing their job for the wrong reason, and that is precisely why it has to be a hunt rather than an alert. The signal is not the action, it is the deviation from that person's own pattern.

**Data:** DLP, file access, proxy, email gateway.

**Hunt 4a, bulk download volume**

```spl
index=proxy OR index=fileshare
| bucket _time span=1d
| stats sum(bytes) as total_bytes,
  count as file_count,
  dc(resource) as unique_resources
  by user, _time
| where total_bytes > 104857600
| eval total_mb = round(total_bytes/1024/1024, 2)
| eval risk = case(
    total_mb > 1000, "CRITICAL - Possible Exfiltration",
    total_mb > 500,  "HIGH - Unusual Download Volume",
    true(),          "MEDIUM - Elevated Download Volume"
  )
| table _time, user, total_mb, file_count, unique_resources, risk
| sort - total_mb
```

Added a daily bucket — the original grouped by exact `_time`, which meant every event was its own row and the volume threshold could never fire.

**Hunt 4b, off hours access**

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4624
| eval hour = strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count as off_hours_logins by user, src_ip, dest
| where off_hours_logins > 3
| eval risk = "MEDIUM - Off Hours Access Pattern"
| table user, src_ip, dest, off_hours_logins, risk
```

Looking for:
Non IT users authenticating between midnight and 06:00.
Bulk downloads in the weeks around a resignation or termination.
Access to resources that user has never touched.

**Note:** Volume alone is not a finding. A finance analyst pulling 500MB at quarter end is doing their job. The threshold that works is per user, against that user's own baseline, and this query does not have one. Absolute thresholds on insider hunting produce accusations, not findings.

---

## Documentation Template

Every hunt is documented. Including the ones that find nothing.

```
Hunt ID:        HUNT-2026-[number]
Date:           [date]
Analyst:        William
Hypothesis:     [what you claimed an attacker would be doing]
Data Sources:   [which logs]
Queries Used:   [reference IDs]
Period:         [from] to [to]
Findings:       [what you found, or confirmed clean]
Actions:        [escalated / rule created / ruled out]
Outcome:        [threat confirmed / ruled out / new rule]
```

**The zero result hunts are the ones that matter most here.**

A hunt returning nothing is a negative finding with a timestamp. It is what lets someone say the environment was clean against this technique, on this date, across this period. Undocumented, it proves nothing, and a hunt nobody wrote down did not happen.

It is also the only way to build coverage you can state rather than assume.

---

## Hunting Calendar

```
DAILY, 15 minutes
  New external IPs in proxy logs
  Admin share access events
  Scheduled task creation outside system processes

WEEKLY, 1 hour
  LOLBAS execution
  Beaconing patterns in network logs
  Off hours authentication

MONTHLY, 4 hours
  Full credential dumping hunt
  Insider threat behavioural analysis
  Implement detection for one new ATT&CK technique
```

The calendar is what turns hunting from something someone does when the queue is quiet into a programme with coverage you can point at. Ad hoc hunting is not a capability, it is a hobby with good intentions.
```

---

## File 3: `README.md`

```markdown
# Advanced Splunk Detection and Hunting Library

Twelve SPL detection queries and four hunt playbooks, written against the ATT&CK matrix. What each query is validated against is stated per query, because that distinction is the difference between a rule and a draft.

## At a Glance

| Field | Detail |
| --- | --- |
| Work Type | Detection engineering, SPL library and hunt playbooks |
| Platform | Splunk Enterprise |
| Delivered | 12 detection queries, 4 hunt playbooks, hunting calendar |
| Coverage | 13 techniques across 7 tactics |
| Validated | 4 of 13 against telemetry I generated |
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

Every hunt starts with a hypothesis — a claim about what an attacker would be doing right now if they were here. The query is only how you check.

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
