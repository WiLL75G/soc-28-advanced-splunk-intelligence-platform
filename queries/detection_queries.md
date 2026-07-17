# Advanced Splunk Detection Queries

Nexus Corp SOC
Analyst: William | @WilliamInCyber | GitHub: WiLL75G

---

## Overview

SPL detection queries mapped to MITRE ATT&CK. Each includes detection logic, tuning guidance, and analyst notes.

Validation status is stated per query. Some are validated against telemetry from my own labs. Most are written from technique knowledge and have never fired against the technique they detect, which is a different thing and worth saying.

---

## Credential Access

### Query 1, Brute Force. T1110.

**Validated** against real SSH brute force in my Splunk lab.

```spl
index=auth sourcetype=linux_secure OR sourcetype=WinEventLog:Security
(EventCode=4625 OR "Failed password")
| bucket _time span=5m
| stats count as failed_attempts by _time, src_ip, user
| where failed_attempts > 10
| eval risk_score = case(
    failed_attempts > 50, "CRITICAL",
    failed_attempts > 25, "HIGH",
    true(), "MEDIUM"
  )
| sort - failed_attempts
| table _time, src_ip, user, failed_attempts, risk_score
```

Detects more than 10 failed logins from one source inside a 5 minute window.

**Tuning:**
Raise to 20 in noisy environments.
Whitelist known vulnerability scanners.
Add a geo lookup to flag non domestic sources.

**Note:** The failures are not the finding. Check for a 4624 from the same source after the 4625s. Forty seven failures is an attack that failed. Forty seven failures and one success is an attacker with a shell.

**Build quirk:** On my lab, linux_secure ingests fragmented. The sourcetype is pinned and every linux_secure search needs a rex extraction on top. That is environment specific, not a query flaw.

---

### Query 2, Password Spray. T1110.003.

**Validated** against the 4625 cross account correlation from my Windows spray lab.

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=30m
| stats dc(user) as unique_users, count as attempts by _time, src_ip
| where unique_users > 5 AND attempts > 10
| eval attack_type = "Password Spray"
| eval risk = "HIGH"
| table _time, src_ip, unique_users, attempts, attack_type, risk
```

Detects one source touching many usernames.

**The distinction:**
Brute force is many attempts against one account. Count within.
Spray is few attempts against many accounts. Count across.

Same event ID. Opposite correlation. `dc(user)` is the entire rule — a per account threshold cannot see this, which is exactly why attackers use it.

**Note:** Spray stays under lockout on purpose. The low attempt count per user is the design, not an accident, and it is why the unique_users correlation is the only thing that catches it.

---

### Query 3, Impossible Travel. T1078.

**Not validated.**

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4624
| iplocation src_ip
| stats list(Country) as countries, list(_time) as times,
  list(src_ip) as ips by user
| eval country_count = mvcount(countries)
| where country_count > 1
| eval risk = "HIGH - Impossible Travel"
| table user, countries, times, ips, risk
```

Detects one account authenticating from multiple countries.

**Note:** This is the noisiest rule in most SIEMs. VPN, mobile CGNAT, cloud sync clients, and badly geolocated IP blocks all fire it on innocent users. The query is easy. The exclusion list is the work.

Contact the user out of band before containment — if the account is compromised, the attacker reads the email. And check the interval: 5,000 miles in 30 minutes is physics. 5,000 miles in 14 hours is a flight.

---

## Execution

### Query 4, PowerShell Encoded Command. T1059.001.

**Validated** against Sysmon EID 1 and 4104 from my Windows endpoint forensics lab, including base64 deobfuscation.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *"
OR CommandLine="*-e *" OR CommandLine="*-ec *")
| rex field=CommandLine "(?i)-(?:EncodedCommand|enc|e|ec)\s+(?P<encoded_cmd>\S+)"
| table _time, ComputerName, user, ParentProcessName,
  CommandLine, encoded_cmd
| sort - _time
```

Detects PowerShell run with a base64 payload.

**Note:** `-EncodedCommand` takes base64, not URL encoding, so Splunk cannot decode it natively without an app. The query extracts the string. Decode it in CyberChef, or pull the decoded version from Event 4104 script block logging, which logs it in the clear.

**Read ParentProcessName first.** `-EncodedCommand` alone is not conclusive — plenty of legitimate tooling uses it. WINWORD.EXE or EXCEL.EXE as the parent is what makes it malicious before anything is decoded.

The `-e` pattern will match broadly. Expect false positives and tune it.

---

### Query 5, LOLBAS Execution. T1218.

**Not validated.** No lab in my portfolio has generated certutil or mshta abuse.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
(NewProcessName="*certutil.exe*" OR NewProcessName="*mshta.exe*"
OR NewProcessName="*regsvr32.exe*" OR NewProcessName="*wscript.exe*"
OR NewProcessName="*cscript.exe*" OR NewProcessName="*rundll32.exe*"
OR NewProcessName="*msiexec.exe*")
| where NOT (ParentProcessName="*msiexec*" AND NewProcessName="*msiexec*")
| stats count by _time, ComputerName, user,
  ParentProcessName, NewProcessName, CommandLine
| sort - _time
```

Detects signed Windows binaries used to download or execute payloads.

**Note:** These are Microsoft signed tools doing what they were built to do, which is why AV does not flag them and why the binary name is not the signal. The command line is. certutil with `-urlcache` is downloading. regsvr32 with a URL is executing remote script.

rundll32 and msiexec are noisy in any real environment. This query as written needs a baseline before deployment.

---

## Persistence

### Query 6, Scheduled Task Creation. T1053.005.

**Not validated.**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4698
| rex field=_raw "Task Name:\s+(?P<task_name>[^\n]+)"
| rex field=_raw "Task Content:\s+(?P<task_content>[^\n]+)"
| where NOT (user="SYSTEM" AND like(task_name, "%Microsoft%"))
| table _time, ComputerName, user, task_name, task_content
| sort - _time
```

Detects tasks created outside system processes.

**Note:** Scheduled tasks are legitimate constantly, so the exclusion is the rule. PowerShell or cmd.exe in the task action is what raises it. Task names impersonating Microsoft paths are evasion aimed at a human scanning a list, not at a rule.

The original used a wildcard inside `NOT (...)` which does not glob. Uses `like()` now.

---

## Lateral Movement

### Query 7, Pass the Hash. T1550.002.

**Not validated.**

```spl
index=windows sourcetype=WinEventLog:Security
EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where user != "ANONYMOUS LOGON"
| bucket _time span=10m
| stats count by _time, src_ip, dest, user, Logon_Type
| where count > 3
| eval risk = "HIGH - Possible Pass-the-Hash"
| table _time, src_ip, dest, user, count, risk
| sort - count
```

Detects bursts of NTLM network logons from one source.

**Note:** NTLM is legitimate. Bursts of it are not, especially where Kerberos would be expected. This rule needs to know what normal NTLM looks like in the environment, which is a baseline I do not have. Deploying it without one produces noise.

Added a bucket — the original grouped by exact `_time`, so `count > 3` could never fire.

---

### Query 8, SMB Admin Share Access. T1021.002.

**Not validated.**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=5140
(ShareName="*ADMIN$*" OR ShareName="*C$*" OR ShareName="*IPC$*")
| bucket _time span=10m
| stats count by _time, src_ip, dest, user, ShareName
| where count > 2
| eval risk = case(
    like(ShareName, "%ADMIN$%"), "CRITICAL - Admin Share Access",
    like(ShareName, "%C$%"), "HIGH - C Drive Share Access",
    true(), "MEDIUM"
  )
| table _time, src_ip, dest, user, ShareName, count, risk
```

Detects access to administrative shares used for remote tool staging and execution.

**Note:** The original case statement used wildcards, which `case()` does not glob — everything fell through to MEDIUM. Uses `like()` now.

Workstation to server SMB outside a mapped drive is the shape worth alerting on.

---

## Exfiltration

### Query 9, Large Outbound Transfer. T1041.

**Validated** against the exfiltration pattern in my AI era detection lab.

```spl
index=network sourcetype=firewall OR sourcetype=proxy
dest_ip!=10.0.0.0/8 dest_ip!=192.168.0.0/16
dest_ip!=172.16.0.0/12
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 52428800
| eval total_mb = round(total_bytes/1024/1024, 2)
| eval risk = case(
    total_mb > 500, "CRITICAL",
    total_mb > 100, "HIGH",
    true(), "MEDIUM"
  )
| sort - total_bytes
| table src_ip, dest_ip, dest_port, total_mb, risk
```

Detects outbound transfers over 50MB to external destinations.

**Note:** Enrich the destination on VirusTotal and AbuseIPDB before acting. Whitelist cloud backup.

The structural weakness of any volume rule: it fires after the data has left. It is coverage at the end of the kill chain, which means the alert arrives when the loss is complete. Detection earlier in the chain is cheaper by orders of magnitude.

---

## Hunting Queries

### Query 10, Process Injection. T1055.

**Not validated.**

```spl
index=windows sourcetype=sysmon EventCode=10
(TargetImage="*lsass.exe*" OR TargetImage="*svchost.exe*"
OR TargetImage="*explorer.exe*")
| where NOT (SourceImage="*MsMpEng.exe*"
  OR SourceImage="*csrss.exe*"
  OR SourceImage="*services.exe*")
| table _time, ComputerName, SourceImage,
  TargetImage, GrantedAccess, CallTrace
| sort - _time
```

Detects processes reading the memory of sensitive system processes.

**Note:** lsass.exe as the target is the one that matters. Nothing legitimate reads LSASS. GrantedAccess masks of 0x1010 and 0x1410 are the credential dumping access patterns.

svchost and explorer generate volume. Start with lsass only.

---

### Query 11, C2 Beacon via Regularity. T1071.

**Not validated.**

```spl
index=network sourcetype=proxy OR sourcetype=firewall
| bucket _time span=1h
| stats count as connections,
  dc(dest_port) as unique_ports,
  sum(bytes_out) as total_bytes
  by src_ip, dest_ip, _time
| where connections > 20 AND unique_ports < 3
| eval beacon_score = round((connections / unique_ports), 2)
| where beacon_score > 10
| eval risk = "HIGH - Possible C2 Beacon"
| sort - beacon_score
| table src_ip, dest_ip, connections,
  unique_ports, beacon_score, risk
```

Detects repeated connections to one destination on few ports.

**Note:** Behavioural, not signature based, which makes it resistant to the evasion that defeats IOC matching. Humans do not generate traffic at fixed intervals. A clean rhythm means a scheduler, and a scheduler talking outbound is a beacon until proven otherwise.

Real C2 jitters the interval to defeat exactly this. A sophisticated beacon will not have a clean regularity score.

---

### Query 12, Shadow Copy Deletion. T1490.

**Not validated.**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*vssadmin*delete*shadows*" OR
CommandLine="*wmic*shadowcopy*delete*" OR
CommandLine="*bcdedit*recoveryenabled*no*")
| table _time, ComputerName, user, CommandLine
| eval risk = "CRITICAL - Ransomware Pre-Encryption"
| sort - _time
```

Detects deletion of volume shadow copies.

**Note:** This is not an indicator, it is a countdown. Nothing legitimate deletes shadow copies. Ransomware does it immediately before encryption, to remove the recovery path first.

Any hit is a containment action, not a triage queue item.
