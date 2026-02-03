# ATTACK_ECOSYSTEM_ATLAS.md
**Author:** Ala Dabat  
**Purpose:** A simplified, complete “atlas” of real-world attack ecosystems (Tier-1 + Tier-2) that maps how intrusions *actually* unfold, and how to respond (IR) when they do.  
**Design Philosophy:** *Behaviour-first → Minimum Truth → Reinforcement → Scoring → Analyst Action (HuntingDirectives)*  
**Audience:** Senior Threat Hunters, Detection Engineers, DFIR / Incident Owners (SOC → IR → Hunting)  
**Platform-Agnostic:** Works across Microsoft Defender XDR / Sentinel, CrowdStrike, QRadar, Splunk, etc.

---

## How to use this Atlas
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
**Examples:** Near-time network, cross-surface persistence, encoded execution, signer anomalies, org prevalence suppression, unusual parentage.

### 0.3 Scoring and Severity
**Definition:** Explainable points for truth + reinforcements → severity tiers.  
- **CRITICAL:** truth + ≥2 strong reinforcements OR immediate blast radius  
- **HIGH:** truth + 1 strong reinforcement OR high-risk context  
- **MEDIUM:** truth only OR weak reinforcements  
- **LOW/INFO:** informational leads (not scheduled analytics unless environment justifies)

### 0.4 Org Prevalence vs Device Count
- **Device Count:** how often *that device* exhibits the behaviour (per-host rarity, role-aware).  
- **Org Prevalence:** how common the behaviour is across the estate (suppression / prioritisation).  
**Rule:** Prevalence adjusts **priority**, not defines **truth**.

### 0.5 Incident Response (Unified)
When in doubt: **PICERL**  
1) Prepare  
2) Identify  
3) Contain  
4) Eradicate  
5) Recover  
6) Lessons Learned

---

# TIER-1 ECOSYSTEMS (Baseline Coverage)

## T1-01) Identity Takeover Ecosystem (Cloud + Entra ID)
**What it is:** Attacker gains access via credentials/session/token and expands through cloud control planes.  
**Typical Chain:** Phish / password spray → MFA fatigue / token theft → new sessions → OAuth consent / app persistence → Graph/Exchange access → data theft / lateral movement

**Minimum Truth Anchors**
- Successful sign-in / session issuance
- Consent grant / service principal creation / privileged role assignment
- High-risk sign-in / auth downgrade

**Reinforcements**
- New Country + New ASN + New UA family
- Weak auth + new network + new client app
- Token refresh anomalies
- App grant + immediate Graph/Exchange activity

**Common Branches**
- Identity → Email takeover
- Identity → Cloud resource abuse
- Identity → Device enrolment

**IR Playbook**
- Triage: confirm telemetry health
- Contain: revoke sessions, CA blocks, disable risky consents
- Investigate: scope sign-ins, apps, mailbox rules, Graph calls
- Eradicate: remove apps, reset creds
- Recover: validate CA baselines
- Lessons: lock down consent, enforce phishing-resistant auth

---

## T1-02) Initial Access Ecosystem (Email / Web / Drive-by)
**Typical Chain:** Phish → user execution → script/LOLBIN → payload → beacon

**Minimum Truth Anchors**
- User-context execution
- Browser/Office abnormal child processes
- Download + immediate execute

**Reinforcements**
- MOTW + execution
- Office → script host
- Near-time outbound network
- Writable path execution

**IR Playbook**
- Triage patient zero
- Contain isolate host
- Investigate persistence
- Eradicate payloads
- Recover baseline
- Lessons harden email and Office

---

## T1-03) Loader & Staging Ecosystem
**Typical Chain:** Writable drop → execute → beacon

**Minimum Truth Anchors**
- Writable file creation
- Near-time execution

**Reinforcements**
- Fast egress
- Rare signer/hash
- Encoded commands

---

## T1-04) LOLBin Proxy Execution Ecosystem
**Typical Chain:** Office/script → LOLBin → remote staging

**Minimum Truth Anchors**
- LOLBin proxy semantics (URL/UNC/script)

---

## T1-05) Fileless Execution Ecosystem (WMI / COM)
**Typical Chain:** WMI → scrcons/script → network

**Minimum Truth Anchors**
- scrcons loads script engine
- wmiprvse spawns high-risk child

---

## T1-06) Persistence Surface Ecosystem
**Typical Chain:** Execution → task/service/runkey → re-entry

**Minimum Truth Anchors**
- Task/service/runkey modification

---

## T1-07) Credential Access Ecosystem
**Typical Chain:** Foothold → credential theft → escalation

**Minimum Truth Anchors**
- LSASS access/dump
- Cloud token abuse

---

## T1-08) Kerberos / AD Abuse Ecosystem
**Typical Chain:** Creds → ticket abuse → lateral

**Minimum Truth Anchors**
- Abnormal auth patterns
- Rogue devices

---

## T1-09) Command & Control Ecosystem
**Typical Chain:** Execution → beaconing → tasking

**Minimum Truth Anchors**
- Repeated outbound connections

---

## T1-10) Lateral Movement Ecosystem
**Typical Chain:** Remote exec → new host

**Minimum Truth Anchors**
- Remote execution or host-pair anomaly

---

## T1-11) Defense Evasion Ecosystem
**Typical Chain:** Foothold → tamper → persistence

**Minimum Truth Anchors**
- Security control tamper

---

## T1-12) Discovery & Recon Ecosystem
**Typical Chain:** Recon → secrets → exfil

**Minimum Truth Anchors**
- High-risk recon/search

---

# TIER-2 ECOSYSTEMS (Advanced / Telemetry-Gated)

## T2-01) Supply Chain & Trusted Abuse
**Minimum Truth Anchors**
- Signed binary from abnormal location
- Untrusted module load

## T2-02) BYOVD / Kernel Abuse
**Minimum Truth Anchors**
- Driver load
- Driver service creation

## T2-03) Polymorphism / Variant Flood
**Minimum Truth Anchors**
- Stable behaviour across variants

## T2-04) Cloud Resource Abuse
**Minimum Truth Anchors**
- Secret/storage access

## T2-05) Email Manipulation (BEC)
**Minimum Truth Anchors**
- Inbox rule creation
- OAuth mailbox access

## T2-06) WSL / Boundary Abuse
**Minimum Truth Anchors**
- wsl.exe abuse

## T2-07) Ransomware Kill-Chain
**Minimum Truth Anchors**
- Mass encryption
- Backup deletion

## T2-08) Data Exfiltration & Staging
**Minimum Truth Anchors**
- Archive + outbound transfer

## T2-09) Insider Abuse
**Minimum Truth Anchors**
- Policy/role misuse

## T2-10) Telemetry Broken
**Minimum Truth Anchors**
- Missing expected telemetry

---

# Tier-1 Operational Coverage Checklist (Anchor Rules)

| # | Anchor Rule | Ecosystems | Minimum Truth | Core Telemetry |
|---|------------|-----------|---------------|----------------|
| 1 | Identity Session Anomaly | Identity | Baseline sign-in deviation | SigninLogs |
| 2 | OAuth/App Persistence | Identity | Consent / app creation | AuditLogs |
| 3 | User-Context Execution | Initial Access | High-risk process | DeviceProcessEvents |
| 4 | Drop-and-Execute | Loader | Writable drop + exec | DeviceFileEvents |
| 5 | LOLBin Proxy Exec | LOLBin | Proxy semantics | DeviceProcessEvents |
| 6 | Fileless Substrate | Fileless | scrcons/wmiprvse | DeviceImageLoadEvents |
| 7 | Wide Persistence Surface | Persistence | Task/service/runkey | DeviceRegistryEvents |
| 8 | Endpoint Cred Access | Credentials | LSASS access | DeviceProcessEvents |
| 9 | Identity Cred Abuse | Identity | Token misuse | SigninLogs |
|10 | Kerberos Pattern | AD | Auth anomaly | SecurityEvent |
|11 | Beaconing Anchor | C2 | Repeated outbound | DeviceNetworkEvents |
|12 | Lateral Movement | Lateral | Remote exec | SecurityEvent |
|13 | Defense Tamper | Evasion | Tool tamper | DeviceEvents |
|14 | Secrets Recon | Recon | High-risk search | DeviceProcessEvents |
|15 | Telemetry Health | Visibility | Missing telemetry | DeviceInfo |

---

# Incident Response Atlas

## 1) Classify by Ecosystem
Always classify before chasing artefacts.

## 2) Choose Correct Containment Lever
Identity, Endpoint, Persistence, AD, Exfiltration.

## 3) Scope by Behaviour, Not IOCs
Same parent chain, commands, persistence, identity deviation.

## 4) Feed Improvements Back
Every incident must improve coverage.

---

# Practical “Complete Coverage” Checklist
- Identity takeover
- Initial access
- Loader/staging
- LOLBin proxy exec
- Fileless substrate
- Persistence surfaces
- Credential access
- Kerberos/AD
- C2
- Lateral movement
- Defense evasion
- Exfiltration
- Telemetry health

---

## Versioning Notes
Keep stable. Add variants within ecosystems.

## Recommended Repo Integration
Place at repo root as `ATTACK_ECOSYSTEM_ATLAS.md`. Reference from README.

