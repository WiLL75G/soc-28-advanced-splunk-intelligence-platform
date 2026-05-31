# Advanced Splunk Detection Queries
## Nexus Corp SOC Intelligence Platform
## Analyst: James | @WilliamCyberSec | GitHub: WiLL75G

---

## Overview

This document contains production-ready SPL (Splunk Processing Language)
queries for detecting real attack techniques mapped to MITRE ATT&CK.
Each query includes detection logic, tuning guidance, and SOC analyst notes.

---

## Category 1 — Credential Attack Detection

### Query 1: Brute Force Detection (T1110)

```spl
index=auth sourcetype=linux_secure OR sourcetype=WinEventLog:Security
(EventCode=4625 OR "Failed password")
| bucket _time span=5m
| stats count as failed_attempts by _time, src_ip, user
| where failed_attempts > 10
| eval risk_score = case(
    failed_attempts > 50, "CRITICAL",
    failed_attempts > 25, "HIGH",
    failed_attempts > 10, "MEDIUM"
  )
| sort - failed_attempts
| table _time, src_ip, user, failed_attempts, risk_score
```

**What it detects:** More than 10 failed login attempts from the same
source IP within a 5-minute window — classic brute force pattern.

**Tuning guidance:**
- Increase threshold to 20 for noisy environments
- Whitelist known vulnerability scanners
- Add geo lookup to flag non-domestic source IPs

**SOC Analyst Note:** Always check if failed attempts were followed
by a successful login — Event ID 4624 after 4625s = confirmed compromise.

---

### Query 2: Password Spray Detection (T1110.003)

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=30m
| stats dc(user) as unique_users, count as attempts by _time, src_ip
| where unique_users > 5 AND attempts > 10
| eval attack_type = "Password Spray"
| eval risk = "HIGH"
| table _time, src_ip, unique_users, attempts, attack_type, risk
```

**What it detects:** One source IP attempting multiple different
usernames — characteristic of password spray vs brute force.

**Key difference from brute force:**
- Brute force: many attempts, one username
- Password spray: fewer attempts, many usernames

**SOC Analyst Note:** Password spray is designed to avoid lockout
policies. Low attempt count per user makes it harder to detect
without the unique_users correlation.

---

### Query 3: Impossible Travel Detection (T1078)

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

**What it detects:** The same user account logging in from
multiple countries — indicates credential compromise or VPN use.

**SOC Analyst Note:** Always contact the user to verify before
blocking. VPN usage can cause false positives. Check time
between logins — logins 5,000 miles apart in 30 minutes = confirmed impossible.

---

## Category 2 — Execution Detection

### Query 4: PowerShell Encoded Command Detection (T1059.001)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *"
OR CommandLine="*-e *" OR CommandLine="*-ec *")
| rex field=CommandLine "(?i)-(?:EncodedCommand|enc|e|ec)\s+(?P<encoded_cmd>\S+)"
| eval decoded = urldecode(encoded_cmd)
| table _time, ComputerName, user, ParentProcessName,
  CommandLine, encoded_cmd
| sort - _time
```

**What it detects:** PowerShell executed with base64 encoded commands
— a classic technique to hide malicious activity from simple log inspection.

**SOC Analyst Note:** Legitimate PowerShell encoded commands are rare.
Any encoded command from a non-IT user should be investigated immediately.
Decode the base64 command in CyberChef to see what it actually does.

---

### Query 5: LOLBAS Execution Detection (T1218)

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

**What it detects:** Living off the Land Binaries (LOLBAS) — legitimate
Windows tools used maliciously to download or execute payloads.

**SOC Analyst Note:** certutil.exe downloading files and
regsvr32.exe executing remote scripts are confirmed red flags.
Check the command line arguments for URLs or unusual file paths.

---

## Category 3 — Persistence Detection

### Query 6: Registry Run Key Persistence (T1547.001)

```spl
index=windows sourcetype=WinEventLog:System EventCode=4657
(ObjectName="*\\CurrentVersion\\Run*"
OR ObjectName="*\\CurrentVersion\\RunOnce*")
| table _time, ComputerName, user, ObjectName,
  NewValue, OldValue, ProcessName
| sort - _time
```

**What it detects:** Changes to registry run keys — the most common
persistence mechanism used by malware.

**SOC Analyst Note:** Any new entry pointing to temp directories,
AppData, or encoded commands is malicious. Cross-reference
NewValue file path with Prefetch and AV logs.

---

### Query 7: Scheduled Task Creation (T1053.005)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4698
| rex field=_raw "Task Name:\s+(?P<task_name>[^\n]+)"
| rex field=_raw "Task Content:\s+(?P<task_content>[^\n]+)"
| where NOT (user="SYSTEM" AND task_name="*Microsoft*")
| table _time, ComputerName, user, task_name, task_content
| sort - _time
```

**What it detects:** New scheduled tasks created outside of
Microsoft system processes — attackers use scheduled tasks
for persistence and lateral movement.

**SOC Analyst Note:** Tasks created by non-system users at
unusual hours are high-fidelity indicators. Check the task
action — PowerShell or cmd.exe in task actions = suspicious.

---

## Category 4 — Lateral Movement Detection

### Query 8: Pass-the-Hash Detection (T1550.002)

```spl
index=windows sourcetype=WinEventLog:Security
EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where user != "ANONYMOUS LOGON"
| stats count by _time, src_ip, dest, user, Logon_Type
| where count > 3
| eval risk = "HIGH - Possible Pass-the-Hash"
| table _time, src_ip, dest, user, count, risk
| sort - count
```

**What it detects:** Multiple NTLM network logons from the same
source in a short time — characteristic of pass-the-hash attacks
where stolen password hashes are used without knowing the plaintext.

**SOC Analyst Note:** Legitimate NTLM network logons happen but
rarely burst. Multiple rapid NTLM logons to different destinations
from one source = lateral movement in progress.

---

### Query 9: SMB Lateral Movement (T1021.002)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=5140
ShareName="\\\\*\\ADMIN$" OR ShareName="\\\\*\\C$"
OR ShareName="\\\\*\\IPC$"
| stats count by _time, src_ip, dest, user, ShareName
| where count > 2
| eval risk = case(
    ShareName="\\\\*\\ADMIN$", "CRITICAL - Admin Share Access",
    ShareName="\\\\*\\C$", "HIGH - C Drive Share Access",
    true(), "MEDIUM"
  )
| table _time, src_ip, dest, user, ShareName, count, risk
```

**What it detects:** Access to administrative shares (ADMIN$, C$)
which attackers use to copy tools and execute commands remotely
during lateral movement.

---

## Category 5 — Exfiltration Detection

### Query 10: Large Outbound Data Transfer (T1041)

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
    total_mb > 50, "MEDIUM"
  )
| sort - total_bytes
| table src_ip, dest_ip, dest_port, total_mb, risk
```

**What it detects:** Outbound data transfers exceeding 50MB to
external IPs — a strong indicator of data exfiltration.

**SOC Analyst Note:** Always check the destination IP on VirusTotal
and AbuseIPDB. Legitimate large transfers (cloud backups) should
be whitelisted. Encrypted traffic to unknown IPs = highest priority.

---

## Category 6 — Threat Hunting Queries

### Query 11: Process Injection Hunt (T1055)

```spl
index=windows sourcetype=sysmon EventCode=10
TargetImage="*lsass.exe*" OR TargetImage="*svchost.exe*"
OR TargetImage="*explorer.exe*"
| where NOT (SourceImage="*MsMpEng.exe*"
  OR SourceImage="*csrss.exe*"
  OR SourceImage="*services.exe*")
| table _time, ComputerName, SourceImage,
  TargetImage, GrantedAccess, CallTrace
| sort - _time
```

**What it detects:** Processes attempting to access the memory
of sensitive system processes — a technique used for credential
dumping and code injection.

---

### Query 12: C2 Beacon Detection (T1071)

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

**What it detects:** Regular, repeated connections to the same
external IP on the same port — the characteristic heartbeat
pattern of C2 malware beaconing home for instructions.

**SOC Analyst Note:** Real C2 beacons are designed to look like
normal traffic. Low unique_ports + high connection count =
automated behaviour, not human browsing.
```
