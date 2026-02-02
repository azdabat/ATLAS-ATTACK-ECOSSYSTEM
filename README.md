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

---

## T1-02) Initial Access Ecosystem (Email / Web / Drive-by)
**What it is:** The first step into the environment: user execution or remote exploitation.  
**Typical Chain:**  
Phish → user execution → script/LOLBIN → payload stage → beacon

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

---

## T1-03) Loader & Staging Ecosystem (Drop → Execute → Beacon)
**What it is:** The core “implant pipeline” used by most modern malware families (Lumma/Remcos/stealers/rat).  
**Typical Chain:**  
Drop file in writable path → execute via LOLBin or loader → persistence optional → beacon / download modules

### Minimum Truth Anchors
- File created in writable directory (exe/dll/sys/script)
- Execution of high-risk interpreter/LOLBin near-time after drop

### Reinforcements
- Fast network egress within 60–120s
- Low org prevalence hash / rare signer mismatch
- Encoded command line / staging tokens
- Process injection follow-on signals (if available)

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

---

## T1-04) LOLBin Proxy Execution Ecosystem (Living-off-the-Land)
**What it is:** Attackers abuse legitimate binaries to execute payloads without dropping custom EXEs.  
**Typical Chain:**  
Office/script → mshta/regsvr32/rundll32/wscript/powershell → remote staging → payload execution

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

---

## T1-05) Fileless Execution Ecosystem (WMI / COM / Script Substrate)
**What it is:** Execution that looks like normal Windows subsystems until reinforced.  
**Typical Chain:**  
WMI eventing / consumer → scrcons/script engine loads → spawn child process → network beacon

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

---

## T1-06) Persistence Surface Ecosystem (Tasks / RunKeys / Services)
**What it is:** Attackers need a way back. Persistence concentrates into a small set of surfaces.  
**Typical Chain:**  
Initial execution → create persistence → re-entry → C2

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

---

## T1-07) Credential Access Ecosystem (LSASS / Tokens / Secrets)
**What it is:** The crown jewel. Attackers go for credentials early.  
**Typical Chain:**  
Foothold → credential dump / theft → privilege escalation / lateral movement

### Minimum Truth Anchors
- LSASS access/dump indicators (process + dump artefacts)
- Secrets file reconnaissance in user paths (when high fidelity)
- Token/session abuse in identity logs (cloud)

### Reinforcements
- Dump file creation + signer anomalies
- Unusual access tools (rundll32 comsvcs, procdump style)
- Rapid privilege use across hosts
- Follow-on Kerberos ticket spikes

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

---

## T1-08) Kerberos / AD Abuse Ecosystem (Ticket Storms / Rogue Devices)
**What it is:** Domain environments are attacked via ticket abuse and rogue devices.  
**Typical Chain:**  
Cred foothold → TGS bursts / SPN abuse → lateral movement → domain escalation

### Minimum Truth Anchors
- Abnormal ticket request volume or patterns (domain logs/SIEM)
- Unrecognized device participating in authentication patterns

### Reinforcements
- Rogue hostname pattern deviation
- EDR onboarding gaps / health issues
- Same account authenticating from new host pairs
- Privileged group membership changes (if present)

### Common Branches
- Kerberos abuse → DC compromise
- Kerberos abuse → service account compromise
- Rogue devices → persistence and stealth

### IR Playbook
- **Triage:** Identify which accounts/services are targeted.  
- **Contain:** Disable suspected devices/accounts, isolate rogue devices, reset impacted secrets.  
- **Investigate:** Look for persistence on DCs, check for golden/silver ticket signs where visible.  
- **Eradicate:** Remove rogue devices, re-baseline AD trust.  
- **Recover:** Rejoin hosts cleanly, rotate keys.  
- **Lessons:** Device inventory hygiene, EDR coverage enforcement, AD monitoring.

---

## T1-09) Command & Control Ecosystem (Beaconing)
**What it is:** C2 is the heartbeat of compromise.  
**Typical Chain:**  
Execution → periodic beaconing → tasking → exfil or movement

### Minimum Truth Anchors
- Process making repeated outbound connections (frequency / periodicity)
- Network from suspicious lineage (script/LOLBins/subsystems)

### Reinforcements
- Rare destinations, rare ports, uncommon SNI/JA3 (if available)
- Near-time after drop/execution
- Correlated named pipe / injection signals (platform dependent)

### Common Branches
- C2 → download modules (staging)
- C2 → lateral movement
- C2 → data theft

### IR Playbook
- **Triage:** Identify process, dests, periodicity; confirm not legitimate updater.  
- **Contain:** Block dests, isolate host if confirmed.  
- **Investigate:** Fleet-wide search for same dests/processes.  
- **Eradicate:** Remove implant, persistence.  
- **Recover:** Monitor for callbacks.  
- **Lessons:** Add composites: execution + net near-time + prevalence suppression.

---

## T1-10) Lateral Movement Ecosystem (Remote Exec + SMB + WMI)
**What it is:** After initial foothold, attackers expand.  
**Typical Chain:**  
Creds → remote exec (WMI/SMB/service) → new host foothold → repeat

### Minimum Truth Anchors
- Remote process creation / remote admin activity (platform dependent)
- Authentication from unusual host pairs

### Reinforcements
- New host pairings (user→host baseline deviation)
- Same tool usage across hosts
- Near-time file transfers and service/task creation

### Common Branches
- Lateral movement → domain escalation
- Lateral movement → data staging
- Lateral movement → defense evasion

### IR Playbook
- **Triage:** Identify pivot host(s) and account used.  
- **Contain:** Disable accounts, isolate pivot host.  
- **Investigate:** Backtrack to initial access, forward-track to new hosts.  
- **Eradicate:** Remove persistence across touched hosts.  
- **Recover:** Reset passwords/tokens, verify MFA posture.  
- **Lessons:** Build user-host pairing baselines and remote execution composites.

---

## T1-11) Defense Evasion Ecosystem (Tamper + Log Killing)
**What it is:** Attackers degrade visibility to persist.  
**Typical Chain:**  
Foothold → disable AV/logging/EDR → continue operations quietly

### Minimum Truth Anchors
- Security tool configuration changes (Defender/EDR tamper attempts)
- Log service stops / audit policy changes (if visible)

### Reinforcements
- Immediate follow-on execution or network activity
- Persistence creation after tamper
- EDR health degradation signals

### Common Branches
- Evasion → persistence
- Evasion → exfil
- Evasion → lateral

### IR Playbook
- **Triage:** Validate if changes authorized.  
- **Contain:** Isolate if unauthorized tamper plus any reinforcement.  
- **Investigate:** Identify who initiated change and what else happened around it.  
- **Eradicate:** Restore controls, remove persistence.  
- **Recover:** Validate telemetry pipelines.  
- **Lessons:** Harden tamper protection, enforce policy-as-code where possible.

---

## T1-12) Discovery & Recon Ecosystem (Secrets + Environment Mapping)
**What it is:** Attackers must learn before they steal.  
**Typical Chain:**  
Recon tools → credential/secret search → staging → exfil

### Minimum Truth Anchors
- High-risk keyword search for secrets in user paths
- Recon commands executed (role/context aware)

### Reinforcements
- Recursive scans, content search, user-profile targeting
- Archive creation near-time
- Outbound transfer shortly after recon

### Common Branches
- Recon → credential access
- Recon → exfiltration
- Recon → persistence

### IR Playbook
- **Triage:** Determine if user/admin legitimate; check concurrent suspicious chains.  
- **Contain:** If high confidence, isolate and block outbound exfil.  
- **Investigate:** Identify files accessed/created; look for archiving/exfil.  
- **Eradicate:** Remove tools, persistence.  
- **Recover:** Re-issue secrets/keys if accessed.  
- **Lessons:** Tighten access to secret stores, DLP, and detection composites.

---

# TIER-2 ECOSYSTEMS (Advanced / Emerging / Telemetry-Gated)
These are not “optional,” but they are not universal. They depend on environment and threat model.

---

## T2-01) Supply Chain & Trusted Abuse Ecosystem (Signed Loader / Updates)
**What it is:** Abuse of trusted software distribution or signed binaries.  
**Minimum Truth Anchors**
- Signed process executes from abnormal location or loads untrusted module
- Update mechanism spawning suspicious children

**Reinforcements**
- DLL sideload path anomalies
- Rare signer + writable path loads
- Near-time network to new infra

**IR**
- Confirm trust chain; check vendor update integrity; isolate if suspicious; scope across fleet.

---

## T2-02) BYOVD / Kernel Abuse Ecosystem
**What it is:** Driver abuse to disable EDR and elevate.  
**Minimum Truth Anchors**
- Driver load events (actual kernel driver load where available)
- Service creation for driver registration

**Reinforcements**
- Signed-but-abused driver names/hashes
- Preceded by sideload chain or payload staging
- Post-driver security tool failures

**IR**
- Immediate isolation, collect driver artifacts, verify EDR health, reimage if needed.

---

## T2-03) Polymorphism / Variant Flood Ecosystem
**What it is:** Constantly changing hashes, stable behaviour.  
**Minimum Truth Anchors**
- Behavioural invariants: staging + LOLBin execution + near-time C2
- Repeated chain patterns across devices

**Reinforcements**
- Similar commandline structure, same parentage patterns
- Same destinations or infrastructure clusters
- Org-wide prevalence suppression of hash (hash changes; behaviour repeats)

**IR**
- Focus on chain, not hash. Block infra, isolate hosts, reset creds if stealer-class.

---

## T2-04) Cloud Resource Abuse Ecosystem (Storage/Keys/Subscriptions)
**What it is:** Abuse of cloud resources after identity takeover.  
**Minimum Truth Anchors**
- Key vault access, secret retrieval, storage access patterns

**Reinforcements**
- New principal, new app, new location + high-volume reads/writes

**IR**
- Lock down identities, rotate keys, audit resource access, implement conditional policies.

---

## T2-05) Email Manipulation Ecosystem (BEC + Inbox Rules)
**What it is:** Email becomes the attack surface and persistence layer.  
**Minimum Truth Anchors**
- Inbox forwarding rules / hidden rules creation
- OAuth app accessing mailbox

**Reinforcements**
- New sign-in deviations + rule creation
- External forwarding spikes

**IR**
- Remove rules, reset tokens, block forwarding, review mailbox audit and Graph access.

---

## T2-06) WSL / Boundary Abuse Ecosystem
**What it is:** Using WSL to create a visibility gap and run tooling.  
**Minimum Truth Anchors**
- Suspicious parent spawning wsl.exe + shell tokens
- Windows-observable VHDX interactions (host-side)

**Reinforcements**
- Rare port egress from WSL process family
- VHDX touched by non-standard actor

**IR**
- Determine if dev machine; isolate if not expected; gather process and disk context; consider Linux-side telemetry if required.

---

## T2-07) Ransomware Kill-Chain Ecosystem
**What it is:** High-speed intrusion culminating in encryption/extortion.  
**Minimum Truth Anchors**
- Mass file modifications / encryption signals
- Backup deletion / shadow copy deletion patterns

**Reinforcements**
- Preceded by credential theft + lateral movement
- Tamper with security tooling
- High-volume SMB writes

**IR**
- Contain immediately (isolate segments), stop spread, preserve evidence, engage recovery.

---

## T2-08) Data Exfiltration & Staging Ecosystem
**What it is:** Compression + transfer, often hidden in normal channels.  
**Minimum Truth Anchors**
- Archive creation + outbound transfer patterns

**Reinforcements**
- Unusual destinations, unusual tools, unusual timing
- Access to high-value data locations before transfer

**IR**
- Block egress, isolate, determine data accessed, notify stakeholders, rotate secrets.

---

## T2-09) Insider / Abuse-of-Access Ecosystem
**What it is:** Legitimate access misused.  
**Minimum Truth Anchors**
- Policy/role abuse, abnormal admin actions, unusual access patterns

**Reinforcements**
- Off-hours, unusual systems, rapid privilege changes, data staging

**IR**
- HR/legal coordination, least-privilege reviews, strong auditing, behaviour baselines.

---

## T2-10) “Telemetry Broken” Ecosystem (Control Plane Failure)
**What it is:** The hardest reality: you get alerts but lack logs.  
**Minimum Truth Anchors**
- Detection with missing expected telemetry (ingestion gaps)

**Reinforcements**
- Diagnostic settings disabled, retention gaps, agent failures, log pipeline breaks

**IR**
- Treat as incident: restore visibility, validate sensors, enforce diagnostics, then hunt using what remains.

---

# CROSS-ECOSYSTEM RULE CLASSES (Rules that sit “outside” a single ecosystem)
Some rules are designed to *flag intent* across multiple ecosystems. They are not “random tangents.”  
They are **wide surface detectors** that feed deeper ecosystem composites.

### Class A: Wide Persistence Surface Detector
- Flags “persistence intent” via tasks/services/runkeys/wmi/powershell  
- Then pivots into:
  - ScheduledTask composite
  - Registry persistence composite
  - Service creation composite

### Class B: Rogue/Unmanaged Device Detector
- Flags unknown devices across telemetry + inventory + EDR health  
- Then pivots into:
  - Kerberos abuse ecosystem
  - Identity ecosystem
  - Lateral movement ecosystem

### Class C: Secrets Recon Detector
- Flags recon/search behaviour across multiple attack chains  
- Then pivots into:
  - Credential access ecosystem
  - Exfiltration ecosystem
  - Ransomware ecosystem

---

# Incident Response Atlas (How to handle incidents by ecosystem)

## 1) Classify Incident by Ecosystem First
**Rule:** Always classify the incident into an ecosystem before you chase artefacts.  
Examples:
- Suspicious sign-ins + consent grants → **Identity Takeover**
- scrcons script engine loads + net → **Fileless WMI**
- schtasks /create + encoded /TR → **Persistence Surfaces**
- drop in writable + LOLBin exec + fast net → **Loader/Staging**
- LSASS dump + ticket spikes → **Credential + Kerberos**

## 2) Choose the Correct Containment Lever
- **Identity:** revoke sessions, disable accounts, CA blocks
- **Endpoint malware:** isolate device, block hash/domains
- **Persistence:** disable tasks/services, remove autoruns
- **Kerberos/AD:** reset impacted secrets, isolate rogue devices, audit DCs
- **Exfiltration:** block egress, preserve evidence, scope access

## 3) Scope by Behaviour, Not IOCs
- Look for the **same chain pattern** across fleet:
  - same parent chain
  - same command tokens
  - same persistence payload structure
  - same identity deviation profile

## 4) Convert Findings into Detection Improvements
Every incident produces:
- new allowlist knowledge
- new reinforcement signals
- better prevalence suppression
- new “minimum truth” anchors if gaps were exposed

---

# Practical “Complete Coverage” Checklist (Baseline)
If your repo has these covered, you are baseline-complete:

- Identity takeover composites (sign-in deviation, consent abuse)
- Initial access execution composites (Office/browser child abuse)
- Loader/staging composites (drop + exec + net)
- LOLBin proxy execution composites (mshta/rundll32/regsvr32)
- Fileless substrate composites (WMI scrcons + victim rule)
- Persistence surfaces composites (tasks/services/runkeys)
- Credential access composites (LSASS + secrets recon)
- Kerberos/AD composites (ticket spikes + rogue devices)
- C2 composites (beaconing / rare destinations)
- Lateral movement composites (remote exec + host pair anomalies)
- Defense evasion composites (tamper + logging failures)
- Exfiltration composites (archive + outbound)
- Control-plane failure / telemetry health checks

---

## Versioning Notes
- Keep this Atlas stable.  
- Add new threats as **variants within ecosystems**, not brand-new sections, unless it truly creates a new ecosystem.

---

## Recommended Repo Integration
- Place this file at repo root: `ATTACK_ECOSYSTEM_ATLAS.md`  
- Reference it in `README.md` as the “Map” layer.  
- Each ecosystem folder contains rules + README that link back to relevant atlas sections.

---
