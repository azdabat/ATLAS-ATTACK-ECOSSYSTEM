# ATTACK_ECOSYSTEM_ATLAS.md
**Author:** Ala Dabat  
**Purpose:** A simplified, complete “atlas” of real-world attack ecosystems (Tier-1 + Tier-2) that maps how intrusions *actually* unfold, and how to respond (IR) when they do.  
**Design Philosophy:** *Behaviour-first → Minimum Truth → Reinforcement → Scoring → Analyst Action (HuntingDirectives)*  
**Audience:** Senior Threat Hunters, Detection Engineers, DFIR / Incident Owners (SOC → IR → Hunting)  
**Platform-Agnostic:** Works across Microsoft Defender XDR / Sentinel, CrowdStrike, QRadar, Splunk, etc.  
**How to use this Atlas:**  
- **Tier-1** ecosystems are your baseline “must cover” for enterprise security (90%+ of real intrusions).  
- **Tier-2** ecosystems are advanced / emerging / environment-dependent (high-impact, lower-frequency, or telemetry-gated).  
- Every ecosystem contains:
  - **What it is** (real chain)
  - **Minimum Truth Anchors** (non-negotiable observable events)
  - **Reinforcements** (convergence signals that reduce noise)
  - **Common Branches** (how attackers pivot)
  - **IR Playbook (PICERL-style)** (Triage → Contain → Investigate → Eradicate → Recover → Lessons)
  - **IR Pivots (KQL)** (*short, investigation-first queries — not full production composites*)

---

## 0) Global Operating Model (applies to every ecosystem)

### 0.1 Minimum Truth (Baseline Anchor)
**Definition:** The smallest high-fidelity observable behaviour that must happen for that attack class to be real.  
**Rule:** Never rely on rarity, TI hits, or “weirdness” as truth. Rarity is *prioritisation only.*

### 0.2 Reinforcement (Contextual Convergence)
**Definition:** Secondary behaviours that converge near-time to increase confidence and reduce false positives.  
Examples: Near-time network, cross-surface persistence, encoded execution, signer anomalies, org prevalence suppression, unusual parentage.

### 0.3 Scoring and Severity
**Definition:** Explainable points for truth + reinforcements → severity tiers.  
- **CRITICAL:** truth + ≥2 strong reinforcements OR immediate blast radius  
- **HIGH:** truth + 1 strong reinforcement OR high-risk context  
- **MEDIUM:** truth only OR weak reinforcements  
- **LOW/INFO:** informational leads (not scheduled analytics unless environment justifies)

### 0.4 Org Prevalence vs Device Count (how to think)
- **Device Count:** how often *that device* exhibits the behaviour (per-host rarity, role-aware).  
- **Org Prevalence:** how common the behaviour is across the estate (suppression / prioritisation).  
**Rule:** Prevalence should adjust **priority**, not define **truth**.

### 0.5 Incident Response (Unified)
When in doubt: **PICERL**  
1) **Prepare** (visibility + playbooks)  
2) **Identify** (is it real?)  
3) **Contain** (stop blast radius)  
4) **Eradicate** (remove footholds)  
5) **Recover** (restore trust)  
6) **Lessons Learned** (controls + detections + hardening)

---

# TIER-1 ECOSYSTEMS (Baseline Coverage)
These are the “must have” ecosystems. If these are incomplete, you will have blindspots.

---

## T1-01) Identity Takeover Ecosystem (Cloud + Entra ID)
**What it is:** Attacker gains access via credentials/session/token and expands through cloud control planes.  
**Typical Chain:**  
Phish / password spray → MFA fatigue / token theft → new sessions → OAuth consent / app persistence → Graph/Exchange access → data theft / lateral movement

**MITRE (core):**  
- Initial Access: Phishing (T1566)  
- Credential Access: Valid Accounts (T1078)  
- Persistence: Account Manipulation / OAuth app persistence (varies by platform mapping)  
- Discovery/Collection: Cloud service discovery + mailbox access  
- Exfiltration: Exfiltration Over Web Service (T1567)

### Minimum Truth Anchors
- Successful sign-in / session issuance (identity platform logs)
- Consent grant / service principal creation / privileged role assignment (cloud audit)
- High-risk sign-in / abnormal authentication requirement downgrade

### Reinforcements
- New Country + New ASN + New UA family (baseline deviation)
- Weak auth + new network + new client app
- Token refresh anomalies, impossible travel with real corroboration
- App permissions grant + immediate Graph/Exchange activity

### Common Branches
- Identity → Email takeover (inbox rules, forwarding)
- Identity → Cloud resource abuse (storage, keys, subscriptions)
- Identity → Device enrolment / rogue endpoints

### IR Playbook
- **Triage:** Confirm telemetry health (SignInLogs/AuditLogs/CA/diagnostic settings).  
- **Contain:** Revoke sessions/refresh tokens, block sign-in, CA temporary block, disable risky app consents.  
- **Investigate:** Scope sign-ins, app grants, mailbox rules, Graph calls, risky IP/ASN reuse across users.  
- **Eradicate:** Remove malicious enterprise apps/service principals, reset creds, enforce phishing-resistant auth.  
- **Recover:** Validate CA baselines, monitor re-auth attempts, restore mailbox settings.  
- **Lessons:** Lock down consent, enforce CA, token protection, risky sign-in policies.

### IR Pivots (KQL)
**Pivot A — “New Country + New ASN” (investigation lead)**
```kql
let lookback = 7d;
let hist = 30d;
let Baseline =
SigninLogs
| where TimeGenerated between (ago(hist) .. ago(lookback))
| where ResultType == 0
| summarize
    SeenCountries = make_set(tostring(LocationDetails.countryOrRegion), 200),
    SeenASNs      = make_set(tostring(NetworkLocationDetails[0].asn), 500)
  by UserPrincipalName;

SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| join kind=leftouter Baseline on UserPrincipalName
| extend Country = tostring(LocationDetails.countryOrRegion),
         ASN     = tostring(NetworkLocationDetails[0].asn)
| extend NewCountry = toint(isnull(SeenCountries) or Country !in (SeenCountries)),
         NewASN     = toint(isnull(SeenASNs) or ASN !in (SeenASNs))
| where NewCountry == 1 and NewASN == 1
| project TimeGenerated, UserPrincipalName, IPAddress, Country, ASN, AppDisplayName, ClientAppUsed, UserAgent
| order by TimeGenerated desc
```

**Pivot B — OAuth / Consent / App persistence (scope surface)**
```kql
let lookback = 30d;
AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has_any ("Consent", "Add service principal", "Add application", "Add delegated permission", "Add app role assignment")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

---

## T1-02) Initial Access Ecosystem (Email / Web / Drive-by)
**What it is:** The first step into the environment: user execution or remote exploitation.  
**Typical Chain:**  
Phish → user execution → script/LOLBIN → payload stage → beacon

**MITRE (core):** T1566, T1204, T1059, T1218, T1105

### Minimum Truth Anchors
- User executes/opens malicious content (process creation / Office spawning)
- Browser spawns abnormal child processes
- Download + immediate execute pattern

### Reinforcements
- Mark-of-the-Web + execution
- Parent/child anomalies (Office → script host / LOLBin)
- Near-time outbound network to new domain/IP
- File written to writable path + executed

### Common Branches
- Initial Access → Persistence surfaces
- Initial Access → Credential access
- Initial Access → C2 beaconing

### IR Playbook
- **Triage:** Identify patient zero, parent chain, initial file URL/source.  
- **Contain:** Isolate host, block domain/IP, quarantine artifacts, disable account if suspicious.  
- **Investigate:** Identify dropper, follow child processes, check for persistence, scope across endpoints.  
- **Eradicate:** Remove binaries/scripts, clean autoruns/tasks, reset credentials if theft likely.  
- **Recover:** Reimage if needed, restore trusted baseline.  
- **Lessons:** Harden mail controls, attachment detonation, user protections, block macros/child processes.

### IR Pivots (KQL)
**Pivot A — Office → high-risk child**
```kql
let lookback = 7d;
let OfficeParents = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]);
let HighRiskChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ (OfficeParents)
| where FileName in~ (HighRiskChildren)
| project Timestamp, DeviceName, AccountName,
          Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          Child=FileName, ChildCmd=ProcessCommandLine
| order by Timestamp desc
```

**Pivot B — Browser → suspicious child**
```kql
let lookback = 7d;
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe"]);
let SuspChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ (Browsers)
| where FileName in~ (SuspChildren)
| project Timestamp, DeviceName, AccountName,
          Browser=InitiatingProcessFileName, BrowserCmd=InitiatingProcessCommandLine,
          Child=FileName, ChildCmd=ProcessCommandLine
| order by Timestamp desc
```

---

## T1-03) Loader & Staging Ecosystem (Drop → Execute → Beacon)
**What it is:** The core “implant pipeline” used by most modern malware families (stealers/RAT/loader chains).  
**Typical Chain:**  
Drop file in writable path → execute via LOLBin or loader → persistence optional → beacon / download modules

**MITRE (core):** T1105, T1059, T1218, T1027

### Minimum Truth Anchors
- File created in writable directory (exe/dll/sys/script)
- Execution of high-risk interpreter/LOLBin near-time after drop

### Reinforcements
- Fast network egress within 60–120s
- Low org prevalence hash / rare signer mismatch
- Encoded command line / staging tokens

### Common Branches
- Stage → Credential access
- Stage → Persistence surfaces
- Stage → Exfiltration

### IR Playbook
- **Triage:** Identify dropped file, hash, signer, lineage, first execution time.  
- **Contain:** Isolate host, block hash, block domains, stop processes.  
- **Investigate:** Search fleet for hash/path/command-line, find persistence, check for lateral movement.  
- **Eradicate:** Remove binaries, clean persistence, reset creds if stealer suspected.  
- **Recover:** Monitor re-infection attempts, validate endpoints patched/hardened.  
- **Lessons:** Strengthen application control, ASR rules, reduce LOLBin abuse.

### IR Pivots (KQL)
**Pivot A — Drop then execute (tight window)**
```kql
let lookback = 7d;
let window = 10m;
let Writable = dynamic(["\\users\\","\\programdata\\","\\windows\\temp\\","\\temp\\","\\downloads\\","\\appdata\\local\\temp\\"]);
let Drops =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where FolderPath has_any (Writable)
| where tolower(FileName) matches regex @".*\.(exe|dll|sys|js|vbs|ps1)$"
| project DeviceId, DeviceName, DropTime=Timestamp, DropPath=FolderPath, DropFile=FileName, DropSha=SHA256, Dropper=InitiatingProcessFileName, DropperCmd=InitiatingProcessCommandLine;

let Exec =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| project DeviceId, DeviceName, ExecTime=Timestamp, ExecProc=FileName, ExecCmd=ProcessCommandLine, Parent=InitiatingProcessFileName;

Drops
| join kind=inner Exec on DeviceId, DeviceName
| where ExecTime between (DropTime .. DropTime + window)
| where ExecCmd has DropFile or ExecProc =~ DropFile
| project DeviceName, DropTime, ExecTime, DropPath, DropFile, DropSha, Dropper, DropperCmd, ExecProc, ExecCmd, Parent
| order by ExecTime desc
```

**Pivot B — Fast egress after suspicious execution**
```kql
let lookback = 7d;
let window = 2m;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| project DeviceId, DeviceName, ProcTime=Timestamp, FileName, ProcessCommandLine, ProcessId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "ConnectionSuccess"
    | project DeviceId, NetTime=Timestamp, InitiatingProcessId, RemoteIP, RemotePort, RemoteUrl
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where isnotempty(NetTime) and NetTime between (ProcTime .. ProcTime + window)
| project DeviceName, ProcTime, FileName, ProcessCommandLine, NetTime, RemoteIP, RemotePort, RemoteUrl
| order by ProcTime desc
```

---

## T1-04) LOLBin Proxy Execution Ecosystem (Living-off-the-Land)
**What it is:** Attackers abuse legitimate binaries to execute payloads without dropping custom EXEs.  
**Typical Chain:**  
Office/script → mshta/regsvr32/rundll32/wscript/powershell → remote staging → payload execution

**MITRE (core):** T1218, T1059, T1105, T1027

### Minimum Truth Anchors
- LOLBin invoked with execution proxy semantics (script/protocol/UNC/remote)
- Script host / interpreter invoked in suspicious context

### Reinforcements
- Network URL/UNC + execution token
- Encoded payload patterns
- Writable path referenced
- Unusual parent process (Office, browser, installer chain)

### Common Branches
- LOLBin → persistence
- LOLBin → C2
- LOLBin → credential dumping

### IR Playbook
- **Triage:** Decode commands, reconstruct chain, confirm user intent.  
- **Contain:** Block URL/domain, isolate host if follow-on suspicious.  
- **Investigate:** Find other hosts running same command or same parent chain.  
- **Eradicate:** Remove staged scripts/binaries, clean persistence.  
- **Recover:** Enforce ASR + block child process from Office if feasible.  
- **Lessons:** Create composite rules and suppress legit admin tooling via allowlists.

### IR Pivots (KQL)
**Pivot A — LOLBin with URL/UNC/protocol indicators**
```kql
let lookback = 7d;
let LOL = dynamic(["mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","powershell.exe","pwsh.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (LOL)
| where ProcessCommandLine has_any ("http://","https://","\\\\","javascript:","scrobj.dll","mshtml")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Pivot B — Encoded execution indicators**
```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| where tolower(ProcessCommandLine) has_any (" -enc","-encodedcommand","frombase64string","iex ","invoke-expression")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## T1-05) Fileless Execution Ecosystem (WMI / COM / Script Substrate)
**What it is:** Execution that looks like normal Windows subsystems until reinforced.  
**Typical Chain:**  
WMI eventing / consumer → scrcons/script engine loads → spawn child process → network beacon

**MITRE (core):** T1546 (Event Triggered Execution), T1059, T1105

### Minimum Truth Anchors
- scrcons.exe loads script engine DLL (vbscript/jscript/scrobj)
- wmiprvse.exe spawns high-risk children

### Reinforcements
- Near-time network from scrcons/wmiprvse lineage
- Non-system DLL path anomalies
- Rare device prevalence (role-aware)
- Correlated suspicious child processes (powershell/cmd/mshta etc.)

### Common Branches
- WMI fileless → persistence subscriptions
- WMI fileless → lateral movement
- WMI fileless → stealthy C2

### IR Playbook
- **Triage:** Check if host is SCCM/management, validate expected WMI use.  
- **Contain:** Isolate if reinforced by network/odd DLL paths/encoded exec.  
- **Investigate:** Look for WMI subscription artifacts and related payload drops.  
- **Eradicate:** Remove subscriptions, delete payloads, reset creds if lateral suspected.  
- **Recover:** Validate management tooling baselines.  
- **Lessons:** Build substrate rules + victim rules + near-time correlation (your model).

### IR Pivots (KQL)
**Pivot A — scrcons script engines (truth anchor)**
```kql
let lookback = 14d;
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName =~ "scrcons.exe"
| where FileName in~ ("vbscript.dll","jscript.dll","scrobj.dll")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Pivot B — wmiprvse spawning high-risk children**
```kql
let lookback = 14d;
let HighRiskChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ (HighRiskChildren)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## T1-06) Persistence Surface Ecosystem (Tasks / RunKeys / Services)
**What it is:** Attackers need a way back. Persistence concentrates into a small set of surfaces.  
**Typical Chain:**  
Initial execution → create persistence → re-entry → C2

**MITRE (core):**  
- Scheduled Tasks: T1053.005  
- Services: T1543.003  
- Run Keys: T1547.001

### Minimum Truth Anchors
- schtasks.exe / Register-ScheduledTask create/change
- sc.exe create / service ImagePath changes
- Registry Run/RunOnce / autoruns modifications

### Reinforcements
- Writable path binaries
- Encoded commands or LOLBins in /TR / binpath
- Suspicious parentage (Office/script host)
- Near-time file creation or network

### Common Branches
- Persistence → re-entry execution
- Persistence → defense evasion (disable tools)
- Persistence → lateral movement

### IR Playbook
- **Triage:** Extract action payload (task / service binpath / registry value).  
- **Contain:** Disable task/service, isolate if malicious.  
- **Investigate:** Identify dropper, check other hosts for same persistence string.  
- **Eradicate:** Remove persistence artifacts and staged payloads.  
- **Recover:** Validate change control; restore known-good tasks/services.  
- **Lessons:** Maintain baselines for approved tasks/services, and add composites for “surface intent + context”.

### IR Pivots (KQL)
**Pivot A — schtasks create/change**
```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("schtasks.exe","at.exe")
| where tolower(ProcessCommandLine) has_any ("/create","/change")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Pivot B — sc.exe create (service persistence)**
```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "sc.exe"
| where tolower(ProcessCommandLine) has " create " and tolower(ProcessCommandLine) has "binpath="
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Pivot C — Run key writes (registry truth)**
```kql
let lookback = 30d;
DeviceRegistryEvents
| where Timestamp >= ago(lookback)
| where RegistryKey has_any ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

---

## T1-07) Credential Access Ecosystem (LSASS / Tokens / Secrets)
**What it is:** The crown jewel. Attackers go for credentials early.  
**Typical Chain:**  
Foothold → credential dump / theft → privilege escalation / lateral movement

**MITRE (core):** T1003.001 (LSASS Memory), T1555 (Credentials from Password Stores), T1078 (Valid Accounts)

### Minimum Truth Anchors
- LSASS access/dump indicators (process + dump artefacts)
- Token/session abuse in identity logs (cloud)

### Reinforcements
- Dump file creation + signer anomalies
- Unusual access tools (rundll32 comsvcs, procdump style)
- Rapid privileged use across hosts
- Follow-on Kerberos spikes

### Common Branches
- Cred access → lateral movement
- Cred access → persistence
- Cred access → exfil

### IR Playbook
- **Triage:** Determine if creds likely compromised; identify target accounts.  
- **Contain:** Disable/rotate creds, isolate host, revoke sessions.  
- **Investigate:** Check for lateral movement and new privileged sessions.  
- **Eradicate:** Remove tools, clean persistence, patch.  
- **Recover:** Reissue tokens/keys, enforce protected users where possible.  
- **Lessons:** Harden LSASS protections, credential guard, reduce local admin.

### IR Pivots (KQL)
**Pivot A — Common LSASS dump tooling patterns**
```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where tolower(ProcessCommandLine) has_any ("comsvcs.dll","minidump","lsass.dmp","procdump","rundll32")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Pivot B — Dump artefact creation (dmp in writable locations)**
```kql
let lookback = 14d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where tolower(FileName) endswith ".dmp"
| where FolderPath has_any ("\\users\\","\\programdata\\","\\windows\\temp\\","\\temp\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## T1-08) Kerberos / AD Abuse Ecosystem (Ticket Storms / Rogue Devices)
**What it is:** Domain environments are attacked via ticket abuse and rogue devices.  
**Typical Chain:**  
Cred foothold → TGS bursts / SPN abuse → lateral movement → domain escalation

**MITRE (core):** T1558 (Kerberos), T1021 (Remote Services), T1078 (Valid Accounts)

### Minimum Truth Anchors
- Abnormal ticket request volume or patterns (domain logs/SIEM)
- Unrecognized device participating in authentication patterns

### Reinforcements
- Rogue hostname pattern deviation
- EDR onboarding gaps / health issues
- Same account authenticating from new host pairs

### IR Playbook
- **Triage:** Identify which accounts/services are targeted.  
- **Contain:** Disable suspected devices/accounts, isolate rogue devices, reset impacted secrets.  
- **Investigate:** Look for persistence on DCs and privileged activity.  
- **Eradicate:** Remove rogue devices, re-baseline AD trust.  
- **Recover:** Rejoin hosts cleanly, rotate keys.  
- **Lessons:** Device inventory hygiene, EDR coverage enforcement, AD monitoring.

### IR Pivots (KQL)
**Pivot A — Ticket/request spikes (Windows SecurityEvent, SIEM)**
```kql
let lookback = 7d;
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID in (4769, 4768)   // TGS, TGT
| summarize Count=count() by Account=tostring(TargetUserName), bin(TimeGenerated, 1h)
| where Count > 200
| order by TimeGenerated desc
```

---

## T1-09) Command & Control Ecosystem (Beaconing)
**What it is:** C2 is the heartbeat of compromise.  
**Typical Chain:**  
Execution → periodic beaconing → tasking → exfil or movement

**MITRE (core):** T1071 (Application Layer Protocol), T1102 (Web Service), T1095 (Non-Application Layer)

### Minimum Truth Anchors
- Process making repeated outbound connections (frequency / periodicity)
- Network from suspicious lineage (script/LOLBins/subsystems)

### Reinforcements
- Rare destinations, rare ports
- Near-time after drop/execution

### IR Playbook
- **Triage:** Identify process, dests, periodicity; confirm not legitimate updater.  
- **Contain:** Block dests, isolate host if confirmed.  
- **Investigate:** Fleet-wide search for same dests/processes.  
- **Eradicate:** Remove implant, persistence.  
- **Recover:** Monitor for callbacks.  
- **Lessons:** Use behavioural convergence: execution + fast net + prevalence.

### IR Pivots (KQL)
**Pivot A — Repeated destinations per process**
```kql
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, Proc=tostring(InitiatingProcessFileName), RemoteIP, RemoteUrl, RemotePort
| where ConnCount >= 50
| project DeviceName, Proc, RemoteIP, RemoteUrl, RemotePort, ConnCount, FirstSeen, LastSeen
| order by ConnCount desc
```

---

## T1-10) Lateral Movement Ecosystem (Remote Exec + SMB + WMI)
**What it is:** After initial foothold, attackers expand.  
**Typical Chain:**  
Creds → remote exec (WMI/SMB/service) → new host foothold → repeat

**MITRE (core):** T1021 (Remote Services), T1047 (WMI), T1569.002 (Service Execution)

### Minimum Truth Anchors
- Remote process creation / remote admin activity
- Authentication from unusual host pairs

### Reinforcements
- New host pairings (user→host baseline deviation)
- Near-time file transfers and service/task creation

### IR Playbook
- **Triage:** Identify pivot host(s) and account used.  
- **Contain:** Disable accounts, isolate pivot host.  
- **Investigate:** Backtrack to initial access, forward-track to new hosts.  
- **Eradicate:** Remove persistence across touched hosts.  
- **Recover:** Reset passwords/tokens, verify MFA posture.  
- **Lessons:** Build remote exec composites as “truth + convergence”.

### IR Pivots (KQL)
**Pivot A — psexec/impacket-ish service execution (endpoint)**
```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("psexec.exe","paexec.exe","wmic.exe","sc.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Pivot B — SMB lateral writes (if file telemetry available)**
```kql
let lookback = 7d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath has_any ("\\\\","\\ADMIN$","\\C$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName
| order by Timestamp desc
```

---

## T1-11) Defense Evasion Ecosystem (Tamper + Log Killing)
**What it is:** Attackers degrade visibility to persist.  
**Typical Chain:**  
Foothold → disable AV/logging/EDR → continue operations quietly

**MITRE (core):** T1562.001 (Impair Defenses), T1070 (Indicator Removal)

### Minimum Truth Anchors
- Security tool configuration changes (Defender/EDR tamper attempts)
- Log service stops / audit policy changes (if visible)

### Reinforcements
- Immediate follow-on execution or network activity
- Persistence creation after tamper
- EDR health degradation signals

### IR Playbook
- **Triage:** Validate if changes authorized.  
- **Contain:** Isolate if unauthorized tamper plus reinforcement.  
- **Investigate:** Identify initiating account/process and adjacent activity.  
- **Eradicate:** Restore controls, remove persistence.  
- **Recover:** Validate telemetry pipelines end-to-end.  
- **Lessons:** Lock tamper protection + monitor policy changes as “truth”.

### IR Pivots (KQL)
**Pivot A — Defender tamper commands**
```kql
let lookback = 14d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where tolower(ProcessCommandLine) has_any ("set-mppreference","disablerealtimemonitoring","disableioavprotection","mpcmdrun")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## T1-12) Discovery & Recon Ecosystem (Secrets + Environment Mapping)
**What it is:** Attackers must learn before they steal.  
**Typical Chain:**  
Recon tools → credential/secret search → staging → exfil

**MITRE (core):** T1083 (File and Directory Discovery), T1552 (Unsecured Credentials), T1005 (Data from Local System)

### Minimum Truth Anchors
- High-risk keyword search for secrets in user paths (role-aware)
- Recon commands executed in suspicious context

### Reinforcements
- Recursive scans, user-profile targeting
- Archive creation near-time
- Outbound transfer shortly after recon

### IR Playbook
- **Triage:** Determine if user/admin legitimate; check concurrent suspicious chains.  
- **Contain:** If high confidence, isolate and block outbound exfil.  
- **Investigate:** Identify files accessed/created; look for archiving/exfil.  
- **Eradicate:** Remove tools, persistence.  
- **Recover:** Re-issue secrets/keys if accessed.  
- **Lessons:** Reduce secret sprawl; push secrets into managed stores.

### IR Pivots (KQL)
**Pivot A — High-risk secret keyword searches (common tooling)**
```kql
let lookback = 7d;
let Tokens = dynamic(["password","passwd","secret","apikey","api_key","token","privatekey","-----BEGIN","connectionstring","aws_access_key_id"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("findstr.exe","powershell.exe","pwsh.exe","ripgrep.exe","rg.exe","grep.exe")
| where tolower(ProcessCommandLine) has_any (Tokens)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Pivot B — Archive creation (staging precursor)**
```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("7z.exe","winrar.exe","rar.exe","zip.exe","tar.exe","powershell.exe","pwsh.exe")
| where tolower(ProcessCommandLine) has_any (".zip",".7z",".rar","compress-archive")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

# TIER-2 ECOSYSTEMS (Advanced / Emerging / Telemetry-Gated)
Tier-2 ecosystems build on Tier-1 anchors. They are “additive,” not replacements.

---

## T2-01) Supply Chain & Trusted Abuse Ecosystem (Signed Loader / Updates)
**What it is:** Abuse of trusted software distribution or signed binaries (signed-but-abused loaders, update hijacks, sideloading).  

**MITRE (core):** T1553 (Subvert Trust Controls), T1574 (Hijack Execution Flow), T1105

### Minimum Truth Anchors
- Signed process executes from abnormal location OR loads untrusted module from writable path
- Update mechanism spawns suspicious child activity

### Reinforcements
- DLL path anomaly (non-system dirs)
- Near-time network to new infra
- Rare-but-signed binary executing outside expected install paths

### IR Pivots (KQL)
**Pivot — “Signed loader → module from writable path” (IR lead, not full composite)**
```kql
let lookback = 14d;
let Writable = dynamic(["\\users\\","\\programdata\\","\\windows\\temp\\","\\temp\\","\\downloads\\","\\appdata\\local\\temp\\"]);
DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where FolderPath has_any (Writable)
| project Timestamp, DeviceName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, SHA256
| order by Timestamp desc
```

---

## T2-02) BYOVD / Kernel Abuse Ecosystem
**What it is:** Driver abuse to disable EDR and elevate (BYOVD chains).  

**MITRE (core):** T1068 (Privilege Escalation), T1562.001 (Impair Defenses), T1543.003 (Service)

### Minimum Truth Anchors
- Driver load event (where available) OR service registration for driver
- Security tooling impairment after driver activity

### IR Pivots (KQL)
**Pivot — Driver-like service creation (sc.exe)**
```kql
let lookback = 30d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName =~ "sc.exe"
| where tolower(ProcessCommandLine) has " create " and tolower(ProcessCommandLine) has_any (" type= kernel"," type= driver"," binpath=")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## T2-03) Polymorphism / Variant Flood Ecosystem
**What it is:** Hash changes constantly; behaviour stays stable.  

**MITRE (core):** T1027, T1059, T1105, T1218

### Minimum Truth Anchors
- Repeatable behavioural chain: writable staging → suspicious exec → near-time egress

### Reinforcements
- Same parentage patterns
- Same infra clusters (domains/IP ranges) even if payload hashes rotate
- Org prevalence suppression based on *behaviour*, not SHA256

### IR Pivots (KQL)
**Pivot — “Same command structure across many devices”**
```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| where tolower(ProcessCommandLine) has_any ("http://","https://","frombase64string"," -enc","\\\\")
| summarize Devices=dcount(DeviceName), Events=count() by FileName, CmdPrefix=substring(tolower(ProcessCommandLine), 0, 120)
| where Devices >= 5
| order by Devices desc, Events desc
```

---

## T2-06) WSL / Boundary Abuse Ecosystem
**What it is:** WSL used as a visibility gap + execution boundary (host-observable entry + effects).  

**MITRE (core):** T1059, T1105, T1562.001 (if used for evasion), environment-specific mapping

### Minimum Truth Anchors (Windows-observable)
- Suspicious parent spawning `wsl.exe` with shell tokens / risky flags
- Host-visible WSL VHDX interaction (optional reinforcement)
- Network egress from WSL process family (optional reinforcement)

### IR Pivots (KQL)
**Pivot A — High-risk parent → wsl.exe**
```kql
let lookback = 14d;
let WslBins = dynamic(["wsl.exe","wslhost.exe","bash.exe","ubuntu.exe","kali.exe","debian.exe","vmmemwsl.exe"]);
let HighRiskParents = dynamic(["mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe","powershell.exe","pwsh.exe","cmd.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (WslBins)
| where InitiatingProcessFileName in~ (HighRiskParents)
| project Timestamp, DeviceName, AccountName, Parent=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine, Child=FileName, ChildCmd=ProcessCommandLine
| order by Timestamp desc
```

**Pivot B — WSL VHDX touched**
```kql
let lookback = 30d;
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where tolower(FileName) endswith ".vhdx"
| where tolower(FolderPath) has "wsl" or FolderPath has_any ("\\AppData\\Local\\Packages\\","\\AppData\\Local\\lxss\\","\\ProgramData\\Microsoft\\Windows\\WSL\\")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

# TIER-1 OPERATIONAL COVERAGE CHECKLIST (Anchor Rules)
This is the minimum Tier-1 rule set required to operationalise the Atlas.

| # | Anchor Rule | Ecosystem | Minimum Truth | Core Telemetry |
|---|------------|----------|--------------|----------------|
| 1 | Identity Session Anomaly | Identity | Successful sign-in deviation | SigninLogs |
| 2 | OAuth / App Persistence | Identity | Consent or SP creation | AuditLogs |
| 3 | User-Context Execution | Initial Access | Office/browser abnormal child | DeviceProcessEvents |
| 4 | Drop-and-Execute | Loader | Writable drop + execution | DeviceFileEvents + DeviceProcessEvents |
| 5 | LOLBin Proxy Exec | LOLBins | URL/UNC/protocol abuse | DeviceProcessEvents |
| 6 | Fileless Substrate | WMI | scrcons/wmiprvse truth anchors | DeviceImageLoadEvents + DeviceProcessEvents |
| 7 | Persistence Surface | Persistence | Task/service/run key change | DeviceRegistryEvents + DeviceProcessEvents |
| 8 | Endpoint Credential Access | Creds | LSASS access/dump | DeviceProcessEvents + DeviceFileEvents |
| 9 | Beaconing Anchor | C2 | Repeated outbound suspicious lineage | DeviceNetworkEvents |
|10 | Lateral Movement Anchor | Lateral | Remote exec / host anomaly | SecurityEvent + DeviceProcessEvents |
|11 | Defense Tamper Anchor | Evasion | Security control modification | DeviceProcessEvents (+ DeviceEvents where available) |
|12 | Secrets Recon Anchor | Discovery | High-risk search behaviour | DeviceProcessEvents |
|13 | Telemetry Health Anchor | Visibility | Unmanaged/rogue devices | DeviceInfo |

---

## DEFINITION: Tier-1 Complete
Tier-1 coverage is complete when:
- Every ecosystem has ≥1 Minimum Truth anchor  
- Identity + Endpoint + Network + Persistence are all covered  
- Incidents can always be reconstructed from anchor telemetry  
- No ecosystem relies on one fragile detection  

---

# CROSS-ECOSYSTEM RULE CLASSES (Rules that sit “outside” a single ecosystem)
Some rules are designed to flag **intent** across multiple ecosystems.  
They are **wide surface detectors** that feed deeper ecosystem hunts (your framework’s “flag → pivot → classify” philosophy).

### Class A: Wide Persistence Surface Detector
- Flags persistence intent via tasks/services/runkeys/WMI/PowerShell  
- Pivot into: Scheduled Task classifier, Service creation classifier, Registry truth rules

### Class B: Rogue/Unmanaged Device Detector
- Flags unknown/unmanaged devices + identity authentications  
- Pivot into: Kerberos/AD abuse, identity takeover, lateral movement ecosystems

### Class C: Secrets Recon Detector
- Flags secrets discovery behaviour  
- Pivot into: credential access, exfiltration, ransomware ecosystems

---

# Incident Response Atlas (How to handle incidents by ecosystem)

## 1) Classify Incident by Ecosystem First
**Rule:** Always classify into an ecosystem before chasing artefacts.  
Examples:
- Sign-ins + consent grants → **Identity Takeover**
- scrcons engine loads → **Fileless WMI**
- schtasks create + payload → **Persistence Surfaces**
- writable drop + exec + fast net → **Loader/Staging**
- LSASS dump + ticket spikes → **Credential + Kerberos**

## 2) Choose the Correct Containment Lever
- **Identity:** revoke sessions, disable accounts, CA blocks  
- **Endpoint:** isolate device, block domain/IP/hash, remove persistence  
- **AD/Kerberos:** reset secrets, isolate pivot hosts, validate DCs  
- **Exfil:** block egress, preserve evidence, scope access  

## 3) Scope by Behaviour, Not IOCs
Scope on:
- parent chain
- command tokens
- persistence payload structure
- identity deviation profile
- repeated infrastructure patterns

## 4) Convert Findings into Detection Improvements
Every incident produces:
- allowlist knowledge
- better reinforcements
- stronger Minimum Truth anchors if gaps exposed
- Tier-2 expansions where tradecraft evolved

---

# Practical “Complete Coverage” Checklist (Baseline)
If your repo has these, you’re baseline-complete:
- Identity takeover (sign-in deviation + consent persistence)
- Initial access (Office/browser child abuse)
- Loader/staging (drop + exec + net)
- LOLBin proxy execution (mshta/rundll32/regsvr32/pwsh)
- Fileless substrate (scrcons + wmiprvse anchors)
- Persistence surfaces (tasks/services/runkeys)
- Credential access (LSASS + dump artefacts)
- Kerberos/AD abuse (ticket spikes + rogue device hygiene)
- C2 beaconing (repeated outbound per process)
- Lateral movement (remote exec + SMB/WMI pivots)
- Defense evasion (tamper + logging degradation)
- Discovery/secrets recon (keyword search + archive staging)
- Telemetry health checks (coverage gaps are incidents)

---

## Versioning Notes
- Keep this Atlas stable.  
- Add new threats as **variants within ecosystems**, not new ecosystems, unless it truly changes the chain.

---

## Recommended Repo Integration
- Place this file at repo root: `ATTACK_ECOSYSTEM_ATLAS.md`  
- Reference it in `README.md` as the “Map” layer.  
- Each ecosystem folder contains:
  - `README.md` (links back to this atlas section)
  - `/pivots` (IR queries)
  - `/composites` (your full Minimum Truth + reinforcement + scoring rules)
````0
