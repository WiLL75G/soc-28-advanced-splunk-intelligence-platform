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

**Why:** certutil, mshta, and regsvr32 are legitimate Microsoft tools. AV does not flag them because there is nothing to flag. The binary is not the signal, the command line is.

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

SourceImage running from a temp directory. That settles it.

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

**Why:** C2 blends with HTTPS by design. Signature detection fails because there is no signature. It is legitimate protocol carrying illegitimate intent. Behaviour is the only angle left.

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

Random looking names. DGA output.

**Note:** The domain age angle needs a lookup table populated from a domain registration feed. That does not exist by default in Splunk and has to be built. This query works on rarity instead, which is available without any lookup and approximates the same signal.

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

Repeated identical payload sizes. A machine, not a person.

High connection count to one domain.

Regular intervals. A heartbeat.

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
