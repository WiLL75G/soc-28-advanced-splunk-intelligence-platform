# Threat Hunting Playbook
## Nexus Corp SOC Intelligence Platform
## Analyst: William | @WilliamInCyber | GitHub: WiLL75G

---

## What is Threat Hunting?

Threat hunting is the proactive search for threats that have
evaded existing security controls before an alert fires.

The difference between reactive and proactive SOC work:

```
REACTIVE  Wait for alert → Investigate → Respond
PROACTIVE Form hypothesis → Hunt → Find → Respond
```

A threat hunter assumes the environment is already compromised
and goes looking for evidence rather than waiting to be told.

---

## The Threat Hunting Process

```
Step 1 — HYPOTHESIS
Form a theory about what an attacker might be doing
based on threat intelligence, TTPs, or anomalies observed.

Step 2 — DATA COLLECTION
Identify which data sources contain evidence of the hypothesis.
SIEM, EDR, network logs, proxy logs, DNS logs.

Step 3 — INVESTIGATION
Write SPL queries to search for indicators of the hypothesis.
Iterate and refine as you find evidence.

Step 4 — PATTERN IDENTIFICATION
Look for patterns — not just individual events.
One failed login = noise. 47 failed logins = signal.

Step 5 — RESPOND OR RULE OUT
If confirmed: escalate and contain.
If ruled out: document findings and tune detection rules.
```

---

## Hunt 1 — Hunt for Living Off the Land (LOLBAS)

**Hypothesis:**
An attacker has gained access and is using legitimate
Windows binaries to avoid detection by AV and EDR.

**Why hunt this:**
LOLBAS attacks are hard to detect because the tools
used (certutil, mshta, regsvr32) are legitimate.
Traditional AV won't flag them.

**Data sources needed:**
- Windows Security Event Logs (Event ID 4688)
- Sysmon process creation logs (Event ID 1)

**Hunt queries:**

```spl
Hunt 1a — Certutil downloading files
index=windows EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
NewProcessName="*certutil.exe*"
(CommandLine="*-urlcache*" OR CommandLine="*-decode*"
OR CommandLine="*-encode*" OR CommandLine="*http*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

**What to look for:**
- certutil.exe with -urlcache -split -f = downloading a file
- certutil.exe with -decode = decoding a base64 payload
- Any certutil.exe execution by a non-IT user

```spl
Hunt 1b — Mshta executing remote scripts
index=windows EventCode=4688
NewProcessName="*mshta.exe*"
(CommandLine="*http*" OR CommandLine="*vbscript*"
OR CommandLine="*javascript*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

**What to look for:**
- mshta.exe connecting to a URL = remote HTA script execution
- This is a classic malware delivery technique

**Expected findings in a clean environment:** Zero results.
Any result here should be investigated immediately.

---

## Hunt 2 — Hunt for Credential Dumping

**Hypothesis:**
An attacker with initial access is attempting to dump
credentials from memory to enable lateral movement.

**Why hunt this:**
After initial access, credential dumping is almost always
the next step. Finding it early prevents lateral movement.

**Data sources needed:**
- Sysmon logs (Event ID 10 process access)
- Windows Security logs (Event ID 4656)
- EDR telemetry

**Hunt queries:**

```spl
Hunt 2a — LSASS memory access
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

**What to look for:**
- Any unexpected process accessing lsass.exe memory
- GrantedAccess value 0x1010 or 0x1410 = credential dumping access mask
- SourceImage from temp directories = confirmed malicious

```spl
Hunt 2b — Volume shadow copy deletion (ransomware prep)
index=windows EventCode=4688
(CommandLine="*vssadmin*delete*" OR
CommandLine="*wmic*shadowcopy*delete*" OR
CommandLine="*bcdedit*/set*recoveryenabled*no*")
| table _time, ComputerName, user, CommandLine
| sort - _time
```

**What to look for:**
- Deletion of volume shadow copies = ransomware pre-encryption step
- Any result here is a CRITICAL alert ransomware may be imminent

---

## Hunt 3 — Hunt for C2 Communication

**Hypothesis:**
A compromised endpoint is beaconing to a C2 server
over encrypted channels to avoid detection.

**Why hunt this:**
C2 communication often blends with normal HTTPS traffic.
Behavioural analysis finds it when signature detection fails.

**Data sources needed:**
- Proxy logs
- Firewall/NetFlow logs
- DNS logs

**Hunt queries:**

```spl
Hunt 3a — DNS requests to newly registered domains
index=network sourcetype=dns
| stats count by query, src_ip
| where count < 3
| lookup dnsdomain_age query as query OUTPUT domain_age
| where domain_age < 30
| eval risk = "HIGH - New Domain + Low Query Count"
| table src_ip, query, count, domain_age, risk
```

**What to look for:**
- DNS queries to domains registered less than 30 days ago
- Low query count = not a popular site = suspicious
- Random-looking domain names = DGA (domain generation algorithm)

```spl
Hunt 3b — HTTP beaconing pattern detection
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

**What to look for:**
- Same bytes_out size repeated = automated not human
- High connection count to same domain = beaconing
- Regular intervals = C2 heartbeat

---

## Hunt 4 - Hunt for Insider Threat

**Hypothesis:**
A privileged user is abusing their access downloading
bulk data, accessing unusual resources, or exfiltrating data.

**Why hunt this:**
Insider threats are the hardest to detect because the
activity looks legitimate on the surface.

**Data sources needed:**
- DLP logs
- File access logs
- Proxy logs
- Email gateway logs

**Hunt queries:**

```spl
Hunt 4a — Bulk file downloads by single user
index=proxy OR index=fileshare
| stats sum(bytes) as total_bytes,
  count as file_count,
  dc(resource) as unique_resources
  by user, _time
| where total_bytes > 104857600
| eval total_mb = round(total_bytes/1024/1024, 2)
| eval risk = case(
    total_mb > 1000, "CRITICAL - Possible Exfiltration",
    total_mb > 500,  "HIGH - Unusual Download Volume",
    total_mb > 100,  "MEDIUM - Elevated Download Volume"
  )
| table user, total_mb, file_count, unique_resources, risk
```

```spl
Hunt 4b — Access to resources outside normal working hours
index=auth sourcetype=WinEventLog:Security EventCode=4624
| eval hour = strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count as off_hours_logins by user, src_ip, dest
| where off_hours_logins > 3
| eval risk = "MEDIUM - Off Hours Access Pattern"
| table user, src_ip, dest, off_hours_logins, risk
```

**What to look for:**
- Logins between midnight and 6 AM for non-IT users
- Large file downloads immediately before resignations or terminations
- Access to resources the user has never touched before

---

## Hunt Documentation Template

Every hunt must be documented even if nothing is found.

```
Hunt ID: HUNT-2026-[number]
Date: [date]
Analyst: James
Hypothesis: [what you were looking for]
Data Sources: [which logs were searched]
SPL Queries Used: [reference query IDs]
Time Period Searched: [from date] to [to date]
Findings: [what you found or confirmed clean]
Actions Taken: [escalated / rule created / false positive]
Outcome: [confirmed threat / ruled out / new detection rule created]
```

---

## Threat Hunting Calendar

```
DAILY HUNTS (15 minutes)
- Review new external IPs in proxy logs
- Check for new persistence mechanisms in registry
- Review admin share access events

WEEKLY HUNTS (1 hour)
- Hunt for LOLBAS execution
- Review scheduled task changes
- Hunt for beaconing patterns in network logs

MONTHLY HUNTS (4 hours)
- Full credential dumping hunt
- Insider threat behaviour analysis
- New MITRE ATT&CK technique implementation
```
