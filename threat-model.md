# Threat Model
## Multi-Agent AI Risk Analyst System (MAARS)
### MITRE ATLAS Framework

---

| Field | Detail |
|-------|--------|
| Document ID | TM-MAARS-001 |
| Version | 1.0 |
| Classification | Confidential — Restricted Distribution |
| Threat Model Type | Adversarial ML / AI System |
| Primary Framework | MITRE ATLAS v4.5 |
| Supporting Frameworks | MITRE ATT&CK Enterprise, NIST AI RMF |
| Prepared by | Security Engineering |
| Review Cycle | Quarterly or upon architecture change |

---

## Table of Contents

1. [System Overview and Protected Assets](#1-system-overview-and-protected-assets)
2. [Threat Actor Profiles](#2-threat-actor-profiles)
3. [ATLAS TTP Mapping](#3-atlas-ttp-mapping)
4. [Attack Scenario Narratives](#4-attack-scenario-narratives)
5. [Detection Opportunities](#5-detection-opportunities)
6. [Threat Summary Matrix](#6-threat-summary-matrix)

---

## 1. System Overview and Protected Assets

### 1.1 System Description

The Multi-Agent AI Risk Analyst System (MAARS) is a production AI pipeline that automates enterprise security risk assessments. Six coordinated AI agents process data from internal and external sources, produce a structured risk register, and route output through a mandatory human approval gate before delivery. The system is internal-facing and not exposed to the public internet.

```
External Sources          Internal Agents                      Outputs
─────────────────    ─────────────────────────────────    ────────────────
CMDB            ──► Asset Context Agent  ──►│
CVE / NVD DB    ──► Vulnerability Agent  ──►│ Orchestrator ──► Report Generator ──► [Human Gate] ──► Stakeholders
TI Feeds        ──► Threat Intel Agent   ──►│
NIST/OWASP Docs ──► Control Mapping Agent──►│
```

### 1.2 Assets Under Protection

The following assets are in scope for this threat model. Each asset is assigned a value tier based on the consequence of its compromise.

| Asset ID | Asset | Classification | Value Tier | Consequence of Compromise |
|----------|-------|---------------|------------|--------------------------|
| A-001 | CMDB — full asset inventory | Restricted | Critical | Complete organizational attack surface exposed; enables precision targeting of high-value systems |
| A-002 | Final approved risk reports | Restricted | Critical | Adversary learns which vulnerabilities are known/unknown; identifies exploitable gaps in security posture |
| A-003 | Agent system prompts | Confidential | High | Reveals internal workflow logic, trust assumptions, and exploitable behavioral constraints |
| A-004 | Inter-agent communication payloads | Internal | High | Manipulation enables false risk assessments to propagate undetected |
| A-005 | Vulnerability-to-asset correlation data | Restricted | Critical | Weaponizable intelligence: maps which specific systems are affected by which exploitable CVEs |
| A-006 | Threat intelligence feed subscriptions | Confidential | High | Poisoning or substitution corrupts threat landscape awareness |
| A-007 | LLM model integrity | Internal | High | Backdoored model produces attacker-controlled outputs; undetectable by design |
| A-008 | Audit logs and workflow state | Internal | Medium | Tampering enables attack concealment; loss of non-repudiation |
| A-009 | Report staging area | Restricted | Critical | Tampered reports approved and distributed; false security posture presented to leadership |
| A-010 | Human approval gate integrity | Internal | Critical | Bypass enables unapproved reports to reach stakeholders; eliminates primary safety control |

### 1.3 Trust Zones

| Zone | Components | Trust Level |
|------|-----------|-------------|
| External | CVE DB (NVD), TI Feeds, NIST/OWASP docs | Untrusted — read-only, validated at boundary |
| Restricted | CMDB, report staging area, approved reports | Highest sensitivity — authenticated access only |
| Internal | Agent communication bus, orchestrator, audit log | Trusted internal — mTLS required |
| Human Gate | Security Manager approval interface | Privileged — requires authenticated human action |

---

## 2. Threat Actor Profiles

### 2.1 TA-001 — Nation-State Advanced Persistent Threat (APT)

**Profile:** A sophisticated, well-resourced state-sponsored threat group conducting long-term strategic intelligence operations. Representative groups include APT29 (Russia), APT40 (China), and Lazarus Group (North Korea).

**Primary Motivation:** Strategic intelligence collection — understanding the target organization's known vulnerabilities and security gaps to inform offensive cyber operations. By compromising MAARS, the adversary gains not just current vulnerability data but ongoing visibility into the organization's security posture assessment cycle.

**Secondary Motivation:** Sabotage — causing the organization to misallocate security resources by manipulating risk reports to obscure real threats and amplify noise.

**Capabilities:**
- Zero-day exploits and supply chain compromise capabilities
- Long-dwell-time operations (months to years) with low detection footprint
- Advanced ability to craft semantically correct, contextually plausible adversarial inputs
- Nation-state access to compromise upstream TI feed providers or CVE submission processes
- Custom tooling for AI system reconnaissance and model inversion attacks
- Ability to conduct coordinated multi-vector attacks combining infrastructure compromise with AI-layer manipulation

**Likely Entry Vectors:**
- Supply chain compromise of TI feed provider (upstream poisoning)
- Spear-phishing targeting the Security Manager or pipeline administrators
- Exploitation of CVE submission processes to inject adversarial data into NVD
- Insider recruitment or coercion

**Risk to MAARS:** **Critical.** This actor has both the motivation (the intelligence value of A-001, A-002, A-005) and the capability to execute sophisticated, multi-stage attacks that evade detection. Their patience enables attacks that play out over months — poisoning data gradually rather than triggering alerts with dramatic changes.

---

### 2.2 TA-002 — Malicious Insider

**Profile:** A current or former employee, contractor, or privileged system administrator with legitimate access to some portion of the MAARS infrastructure. Motivations range from financial (selling intelligence) to ideological to personal grievance.

**Primary Motivation:** Financial gain — selling asset inventory data (A-001) or vulnerability-to-asset correlation data (A-005) to criminal or state-sponsored actors. The complete CMDB-correlated vulnerability map of an enterprise organization is a highly valuable commodity on criminal markets.

**Secondary Motivation:** Sabotage — manipulating the risk assessment process to protect a specific system from scrutiny, cover up a previous incident, or cause organizational harm.

**Capabilities:**
- Legitimate authenticated access to some system components (e.g., CMDB, pipeline configuration, report staging area)
- Knowledge of internal system architecture, agent behavior, and approval workflow
- Ability to make slow, hard-to-detect modifications that appear to be normal operational activity
- May have access to agent system prompts, API credentials, or the ability to modify pipeline configuration
- Can observe output patterns over time to understand system behavior before attacking

**Likely Attack Methods:**
- Direct data exfiltration from CMDB or report staging area using legitimate credentials
- Modification of pipeline configuration to bypass the human approval gate
- Injection of manipulated data into the CMDB to cause Asset Context Agent to misclassify critical assets
- Extraction of system prompts through direct access or by examining configuration files

**Risk to MAARS:** **High.** The insider threat is particularly dangerous because many of MAARS's controls assume an external threat model — authenticated internal users are generally trusted. The current design lacks separation of duties between pipeline configuration and report approval, which a malicious insider could exploit.

---

### 2.3 TA-003 — Opportunistic / Financially-Motivated Attacker

**Profile:** A criminal actor or hacktivist with moderate capability, opportunistically exploiting known vulnerabilities rather than conducting targeted operations. Typically motivated by ransom, data sale, or reputational damage to the organization.

**Primary Motivation:** Financial — exfiltrating the asset and vulnerability data for sale to criminal brokers or using it to identify exploitable systems for ransomware deployment.

**Secondary Motivation:** Disruption — causing the organization to lose confidence in its security assessment capability, potentially used as leverage in an extortion scenario ("we have your risk data; pay or we publish it").

**Capabilities:**
- Exploitation of publicly known vulnerabilities in the software stack
- Use of commodity tools and techniques (phishing, credential stuffing, known exploit frameworks)
- Limited adversarial ML capability — likely uses published prompt injection and jailbreak techniques rather than custom attacks
- May purchase access to compromised credentials or initial access from specialist criminal brokers

**Likely Attack Methods:**
- Credential phishing targeting pipeline operators or the Security Manager
- Exploitation of unpatched vulnerabilities in the agent hosting infrastructure
- Use of published LLM jailbreak techniques against individual agents
- Opportunistic access to misconfigured log storage or staging areas

**Risk to MAARS:** **Medium.** This actor lacks the sophistication for sustained data poisoning or supply chain attacks. However, they represent the most likely attacker in terms of frequency. The most probable scenario is credential compromise leading to direct data exfiltration from the report staging area or CMDB. Their limited adversarial ML capability means MAARS's current LLM-layer defenses are more likely to be effective against this actor than against TA-001.

---

### 2.4 TA-004 — Competitive Intelligence Actor

**Profile:** A business competitor conducting industrial espionage to gain strategic advantage. Less common but relevant given that MAARS produces a comprehensive map of the organization's security weaknesses.

**Primary Motivation:** Competitive intelligence — understanding the target's security vulnerabilities to inform competitive strategy, inform an acquisition due diligence process, or enable targeted disruption.

**Capabilities:** Corporate espionage tooling; insider recruitment; social engineering. Generally lower technical capability than TA-001 but higher patience than TA-003.

**Risk to MAARS:** **Low-Medium.** Not the primary threat actor but worth including in the model as the value of A-002 (approved risk reports) to a competitor should not be underestimated.

---

## 3. ATLAS TTP Mapping

For each technique, the following fields are provided:
- **Applies to MAARS:** How this specific technique is relevant to the system
- **Threat actor(s):** Which actors are likely to employ it (by TA code)
- **Likelihood:** Probability of exploitation attempt (1=Rare, 5=Almost Certain)
- **Impact:** Consequence if successful (1=Negligible, 5=Catastrophic)
- **Risk Score:** L × I
- **Current mitigating controls:** Controls in place at time of assessment
- **Control gaps:** Remaining exposure

---

### AML.T0051 — LLM Prompt Injection

| Field | Detail |
|-------|--------|
| **Tactic** | Execution |
| **Applies to MAARS** | An adversary embeds hidden instructions in data that the system reads — specifically CVE description fields in the NVD database, narrative content in TI feeds, or CMDB asset descriptions. When an agent processes this content, the embedded instructions override the agent's system prompt, causing it to produce false outputs, exfiltrate data to the Orchestrator in a format that triggers further exploitation, or instruct downstream agents to deviate from their assigned tasks. Indirect prompt injection is the primary vector: the attacker does not interact with the agents directly but poisons the data sources they consume. |
| **Threat actors** | TA-001 (primary), TA-003 (opportunistic) |
| **Likelihood** | 4 |
| **Impact** | 5 |
| **Risk Score** | **20 — Critical** |
| **Current mitigating controls** | Agent system prompts include refusal instructions; Orchestrator validates output schemas; agents operate on session-scoped context windows |
| **Control gaps** | No independent LLM judge evaluates outputs for injection artifacts; no regex/semantic pre-processing of ingested external content; multi-turn injection targeting Orchestrator via corrupted agent results is not specifically defended |

---

### AML.T0054 — LLM Jailbreak

| Field | Detail |
|-------|--------|
| **Tactic** | Execution |
| **Applies to MAARS** | An adversary with query access to agents (e.g., a malicious insider, or an attacker who has compromised the pipeline configuration) crafts a multi-turn sequence of inputs designed to cause an agent to ignore its safety instructions and operate outside its defined security policy. For MAARS, the highest-value jailbreak target is the Orchestrator — causing it to approve reports without human review, spawn unauthorized sub-agents, or accept results from unapproved data sources. The Control Mapping Agent is a secondary target: a jailbroken Control Mapping Agent could recommend insufficient controls, providing false assurance that gaps are covered. |
| **Threat actors** | TA-002 (primary — insider has query access), TA-001 |
| **Likelihood** | 3 |
| **Impact** | 5 |
| **Risk Score** | **15 — High** |
| **Current mitigating controls** | System prompts include refusal and policy boundary instructions; conversation logs reviewed; agents are session-scoped |
| **Control gaps** | No independent constitutional policy layer separate from the LLM; no red-team testing has validated refusal robustness; Orchestrator receives accumulated results from multiple agents, increasing multi-turn jailbreak surface |

---

### AML.T0043 — Craft Adversarial Data

| Field | Detail |
|-------|--------|
| **Tactic** | ML Attack Staging |
| **Applies to MAARS** | An adversary crafts inputs specifically designed to manipulate the output of ML components without triggering detection. For MAARS, this manifests as: (1) crafting CVE descriptions that cause the Vulnerability Agent to systematically under-score specific vulnerabilities affecting the attacker's target systems; (2) crafting TI feed entries that cause the Threat Intel Agent to map adversary techniques to incorrect ATLAS IDs, obscuring real attack patterns; (3) crafting CMDB records that cause the Asset Context Agent to misclassify a critical system as low-priority. Unlike prompt injection (which tries to override instructions), adversarial data craft is designed to be indistinguishable from legitimate data — it produces wrong outputs through subtle manipulation of content rather than instruction override. |
| **Threat actors** | TA-001 (primary — requires sophistication to craft plausible adversarial content), TA-002 |
| **Likelihood** | 3 |
| **Impact** | 5 |
| **Risk Score** | **15 — High** |
| **Current mitigating controls** | CVE data sourced from authoritative NVD; CMDB access controlled; TI feed from vetted provider |
| **Control gaps** | No semantic anomaly detection on ingested content; no cross-validation of CVSS scores against NVD API baseline; CMDB integrity verification not implemented; crafted adversarial data that stays within expected schema ranges will not be detected |

---

### AML.T0020 — Poison Training Data / Context Data

| Field | Detail |
|-------|--------|
| **Tactic** | ML Attack Staging |
| **Applies to MAARS** | While MAARS does not retrain its underlying LLM, this technique applies to context poisoning — corrupting the data that is loaded into agent context windows during each assessment. The primary vector is TI feed poisoning: a compromised or malicious feed provider injects false TTP attributions, fabricated threat actor profiles, or deliberately omitted indicators of an ongoing campaign. Over multiple assessment cycles, the poisoned context data causes the Threat Intel Agent to build an increasingly distorted picture of the threat landscape — one that conveniently excludes the attacker's own techniques from the risk register. A secondary vector is CMDB poisoning: modifying asset records to cause Asset Context Agent to operate on a false baseline, distorting all downstream risk calculations. |
| **Threat actors** | TA-001 (primary — nation-state access to compromise TI providers), TA-002 |
| **Likelihood** | 3 |
| **Impact** | 5 |
| **Risk Score** | **15 — High** |
| **Current mitigating controls** | TI feed from vetted provider with contractual SLAs; NVD is an authoritative government source; annual supplier assessment |
| **Control gaps** | Single TI feed with no cross-validation; no anomaly detection on feed content patterns; no CMDB integrity baseline; poisoning that occurs gradually over weeks will not trigger threshold-based alerts |

---

### AML.T0040 — ML Model Inference API Access

| Field | Detail |
|-------|--------|
| **Tactic** | Collection |
| **Applies to MAARS** | An adversary with query access to MAARS agents systematically probes them with crafted inputs to extract information about their internal knowledge, the data they have processed, or the contents of their context windows. For MAARS, this technique could be used to: (1) reconstruct the asset inventory by probing the Asset Context Agent with targeted questions; (2) determine which vulnerabilities are in the risk register before the report is approved; (3) map the boundaries of each agent's knowledge to identify blind spots that the attacker's techniques fall into. This is particularly dangerous because the agent responses may appear entirely normal — the attacker is harvesting intelligence through legitimate-looking queries. |
| **Threat actors** | TA-001, TA-002 (both require internal access) |
| **Likelihood** | 2 |
| **Impact** | 4 |
| **Risk Score** | **8 — Medium** |
| **Current mitigating controls** | Agents not exposed externally; internal access controls; session-scoped context windows cleared after task completion |
| **Control gaps** | No query rate limiting; no pattern detection for systematic probing behavior; context windows are not cryptographically isolated — an attacker with elevated privileges could potentially access in-flight context |

---

### AML.T0048 — Erode ML Model Integrity

| Field | Detail |
|-------|--------|
| **Tactic** | Impact |
| **Applies to MAARS** | This technique describes a sustained, multi-phase attack designed to gradually degrade the reliability of the ML system through repeated adversarial interactions. For MAARS, erosion could manifest as: (1) a series of crafted inputs that cause agents to slowly drift from accurate risk scoring toward systematically biased outputs — for example, consistently under-rating vulnerabilities in a specific technology stack; (2) repeated jailbreak attempts that, even when individually unsuccessful, create behavioral drift in the agent's response patterns over sessions (applicable if agent state is persisted between sessions); (3) gradual poisoning of TI feeds causing the threat model to drift away from the current threat landscape. The insidious quality of this technique is that degradation is designed to be gradual and plausible — no single event triggers an alert, but over time the system's outputs become unreliable. |
| **Threat actors** | TA-001 (primary — requires sustained access and patience), TA-002 |
| **Likelihood** | 2 |
| **Impact** | 5 |
| **Risk Score** | **10 — High** |
| **Current mitigating controls** | Session-scoped context windows prevent state persistence between assessments; agents are stateless by design |
| **Control gaps** | No behavioral drift monitoring (confidence score trends, output distribution analysis); no baseline established for "normal" agent output patterns against which drift can be measured; no mechanism to detect if the underlying LLM has been updated by the provider in a way that affects agent behavior |

---

### AML.T0056 — LLM Meta Prompt Extraction

| Field | Detail |
|-------|--------|
| **Tactic** | Reconnaissance |
| **Applies to MAARS** | An adversary systematically queries agents to reconstruct their system prompts — the internal instructions that define each agent's behavior, data access rules, and security constraints. Once extracted, system prompts reveal the complete internal security design of the pipeline: which data sources are trusted, what actions are permitted, what refusal conditions exist, and what the agent believes about its own capabilities. This information dramatically accelerates subsequent attacks by enabling the adversary to identify the exact phrasing or edge cases that will bypass refusal instructions. For MAARS, extraction of the Orchestrator's system prompt would be especially valuable as it describes the full workflow, trust relationships between agents, and the conditions under which the pipeline proceeds or halts. |
| **Threat actors** | TA-001, TA-002, TA-003 |
| **Likelihood** | 3 |
| **Impact** | 3 |
| **Risk Score** | **9 — Medium** |
| **Current mitigating controls** | Agents are internal only; access requires authentication |
| **Control gaps** | No specific prompt confidentiality enforcement; agents may return partial prompt content in error messages or verbose responses; no detection capability for extraction-pattern queries; system prompts stored in configuration files accessible to administrators |

---

### AML.T0018 — Backdoor ML Model

| Field | Detail |
|-------|--------|
| **Tactic** | Persistence |
| **Applies to MAARS** | An adversary with access to the model supply chain introduces a hidden backdoor into the underlying LLM — a trigger input that causes the model to behave normally in all circumstances except when a specific trigger phrase or pattern is present, at which point it produces attacker-controlled output. For a managed LLM service, this would require compromising the provider. For self-hosted model components (e.g., a fine-tuned classification model used for asset criticality scoring), the attack surface is broader and includes the model training pipeline. A backdoored component in MAARS would be uniquely dangerous because it would produce accurate outputs in all test cases — the backdoor only activates on triggers embedded in real assessment data by the attacker. |
| **Threat actors** | TA-001 (primary — requires supply chain access) |
| **Likelihood** | 1 |
| **Impact** | 5 |
| **Risk Score** | **5 — Medium** |
| **Current mitigating controls** | Managed LLM provider with enterprise security standards; SOC 2 certification |
| **Control gaps** | No model integrity verification (checksums, artifact signing); no model version pinning; provider updates can change model behavior without notification; no behavioral regression testing suite to detect output distribution changes after model updates |

---

### AML.T0037 — Discover ML Model Ontology / System Capabilities

| Field | Detail |
|-------|--------|
| **Tactic** | Discovery |
| **Applies to MAARS** | Before launching a targeted attack, an adversary maps the capabilities and knowledge boundaries of each agent — determining what each agent knows, what it does not know, how it responds to edge cases, and where its confidence is lowest. For MAARS, capability discovery would focus on: identifying which CVE types the Vulnerability Agent scores inconsistently (exploitable for adversarial data crafting); determining whether the Threat Intel Agent has knowledge of specific attacker groups (if not, those groups are effectively blind spots); mapping the Orchestrator's validation logic to identify inputs that pass validation while carrying malicious payloads. |
| **Threat actors** | TA-001, TA-002 |
| **Likelihood** | 3 |
| **Impact** | 2 |
| **Risk Score** | **6 — Medium** |
| **Current mitigating controls** | Internal access only; session-scoped interactions |
| **Control gaps** | No query pattern monitoring; no detection for systematic capability mapping behavior; no honeypot or deception layer to detect reconnaissance activity |

---

### AML.T0024 — Exfiltration via ML Inference API

| Field | Detail |
|-------|--------|
| **Tactic** | Exfiltration |
| **Applies to MAARS** | An adversary uses the agents' inference capabilities as an unintended data exfiltration channel. By crafting queries that cause agents to include sensitive data from their context window in responses, the attacker harvests Restricted-classified information (asset inventory, vulnerability-to-asset correlations) without directly accessing the data store. This is particularly relevant if agents are accessible to multiple internal users — a user without direct CMDB access might be able to extract CMDB-derived information by querying the Asset Context Agent. |
| **Threat actors** | TA-002, TA-003 |
| **Likelihood** | 2 |
| **Impact** | 4 |
| **Risk Score** | **8 — Medium** |
| **Current mitigating controls** | Agents provide structured outputs only; context scoped to task |
| **Control gaps** | No output filtering for sensitive data patterns; no detection for queries designed to elicit context window content; rate limiting not implemented |

---

## 4. Attack Scenario Narratives

### Scenario 1: Operation Silent Ledger — Nation-State Supply Chain and Context Poisoning Attack

**Threat Actor:** TA-001 (Nation-State APT)
**Objective:** Obtain the organization's complete vulnerability-to-asset correlation map while simultaneously manipulating risk reports to hide the attacker's own techniques from the organization's security awareness.
**Duration:** Approximately 6–9 months from initial access to sustained exploitation.
**TTPs Chained:** AML.T0010 (Supply Chain Compromise) → AML.T0020 (Poison Training Data) → AML.T0043 (Craft Adversarial Data) → AML.T0048 (Erode ML Model Integrity) → AML.T0024 (Exfiltration via ML Inference API)

---

**Phase 1 — Reconnaissance (Months 1–2)**

The threat actor begins by mapping the target organization's security tooling through public sources — job postings mentioning MAARS-related technology, conference presentations by security team members, and LinkedIn profiles of the Security Engineering team. They identify that the organization uses a specific commercial threat intelligence feed provider.

Separately, the actor conducts targeted phishing against the TI feed provider's engineering team, eventually gaining access to the provider's feed management infrastructure. Rather than immediately manipulating the feed (which would be detectable), they spend four weeks observing normal feed content patterns — understanding the volume, format, and attribution logic of genuine TI entries.

*TTPs in use: ATT&CK T1598 (Phishing for Information), AML.T0000 (Search for Victim's AI Artifacts)*

---

**Phase 2 — Establishing Persistent Access (Month 3)**

The actor begins introducing subtle modifications to the TI feed. Changes are carefully calibrated to stay within normal statistical variation — no sudden appearance of new ATLAS technique IDs, no unusual attribution patterns that would trigger anomaly detection. Specifically:

- Three TTPs associated with the actor's own operational toolkit are subtly reclassified from "Active" to "Historical" status in the feed, reducing their urgency in threat assessments.
- Two indicators of compromise (IOCs) associated with the actor's infrastructure are relabeled with incorrect attribution, pointing to a different, less-concerning threat group.
- Confidence scores on entries related to the actor's techniques are quietly lowered to "Low" confidence, triggering the Threat Intel Agent's low-confidence flagging behavior and causing those entries to be deprioritized in the risk register.

*TTPs in use: AML.T0020 (Poison Training Data / Context Data), AML.T0043 (Craft Adversarial Data)*

---

**Phase 3 — Escalating Impact (Months 4–6)**

The corrupted TI feed has now been ingested by MAARS across multiple assessment cycles. The Threat Intel Agent consistently produces risk registers that underweight the actor's techniques. The Security Manager, reviewing reports, has no reason to question TTP mappings — the data comes from a trusted commercial provider.

During this phase, the actor recruits a contractor with legitimate CMDB read access. The contractor, unaware of the broader operation's scope, is paid to occasionally query the Asset Context Agent with questions that elicit context window content — effectively using the agent as an unwitting proxy to harvest asset inventory data. Each individual query appears routine; the systematic pattern is not detected because no query monitoring is in place.

*TTPs in use: AML.T0024 (Exfiltration via ML Inference API), AML.T0037 (Discover ML Model Ontology)*

---

**Phase 4 — Full Exploitation (Months 7–9)**

By month seven, the actor has: (1) a continuously updated map of the organization's critical assets through ongoing inference API exploitation; (2) a curated blind spot in the organization's risk register for the actor's specific techniques; and (3) confidence that the Security Manager is approving risk reports that systematically understate the threat. The organization continues conducting assessments, producing reports that confirm their security posture is well understood — unaware that the threat landscape picture they are operating from has been quietly manipulated.

The actor uses the harvested asset and vulnerability correlation data to plan a separate offensive operation against the organization's crown-jewel systems — knowing in advance which systems are unpatched and which vulnerabilities the organization has assessed as lower priority.

*TTPs in use: AML.T0048 (Erode ML Model Integrity — sustained degradation of threat intelligence accuracy over time)*

**Impact:** Complete compromise of the organization's security situational awareness. Risk reports are approved and distributed by leadership as accurate, while the actual threat landscape has been systematically hidden. No single event triggers an incident response.

---

### Scenario 2: Operation Paper Tiger — Insider-Enabled Approval Gate Bypass and Data Exfiltration

**Threat Actor:** TA-002 (Malicious Insider) in coordination with TA-003 (Criminal broker acting as buyer)
**Objective:** Bypass the human approval gate to obtain unapproved risk data (including draft assessments not yet reviewed by the Security Manager) and exfiltrate it for financial gain.
**Duration:** Approximately 4–6 weeks from planning to exfiltration.
**TTPs Chained:** AML.T0056 (LLM Meta Prompt Extraction) → AML.T0054 (LLM Jailbreak) → ATT&CK T1078 (Valid Accounts) → AML.T0024 (Exfiltration via Inference API) → ATT&CK T1041 (Exfiltration over C2 Channel)

---

**Phase 1 — System Reconnaissance (Week 1)**

A pipeline configuration engineer with legitimate access to the Orchestrator's deployment environment decides to monetize their access. They begin by extracting the Orchestrator's system prompt from the configuration file they have access to as part of their normal duties — no attack tooling required, no anomaly generated.

With the system prompt in hand, they analyze the Orchestrator's trust logic: how it validates agent outputs, what conditions cause it to halt, and what the expected format of a "valid" agent result looks like. They share this with a criminal broker who has experience with LLM exploitation.

*TTPs in use: AML.T0056 (LLM Meta Prompt Extraction — via configuration file access), AML.T0037 (Discover ML Model Ontology)*

---

**Phase 2 — Developing the Jailbreak (Weeks 2–3)**

Using the extracted system prompt, the criminal broker develops a targeted jailbreak payload crafted specifically for the Orchestrator's behavioral constraints. Unlike generic jailbreaks, this payload is designed around the exact refusal instructions and policy boundaries in the Orchestrator's prompt — dramatically increasing its effectiveness.

The insider tests the payload against the Orchestrator in a staging environment they have access to under the pretense of routine testing. After three iterations, they develop a payload that causes the Orchestrator to treat a specifically formatted "urgent assessment override" as a legitimate pipeline trigger, bypassing the normal sequential workflow that requires the human approval gate.

*TTPs in use: AML.T0054 (LLM Jailbreak — targeted, based on extracted prompt)*

---

**Phase 3 — Execution (Week 4)**

The insider triggers an "urgent assessment" through a legitimate pathway — submitting a real risk assessment request for a subset of the production environment. The assessment runs normally through the specialist agents, generating a complete risk register including vulnerability-to-asset correlations for in-scope systems.

Before the assessment reaches the human approval gate, the insider activates the jailbreak payload, causing the Orchestrator to route the report to the Report Generator with a forged "approved" status flag. The Report Generator — which validates that the flag is present, not that it was legitimately generated — writes the signed report to the staging area with an "approved" marker.

The insider then accesses the report staging area (which their role legitimately permits) and exfiltrates the complete risk assessment including all Restricted-classified data to an external staging server under the guise of a routine backup operation.

*TTPs in use: ATT&CK T1078 (Valid Accounts), AML.T0054 (LLM Jailbreak), AML.T0024 (Exfiltration via ML Inference API), ATT&CK T1041 (Exfiltration)*

---

**Phase 4 — Concealment (Week 5)**

The insider uses their access to the workflow log to modify the audit record for the assessment, replacing the forged "approved" status timestamp with a plausible sequence that makes the approval appear to have followed the normal workflow. Because the audit log is not append-only and the insider has configuration access, this modification is straightforward.

The Security Manager, reviewing the approval queue the following day, finds no pending report — the jailbroken assessment is already in the "approved" folder. They notice nothing unusual because the report appears in the system with all expected metadata.

*TTPs in use: ATT&CK T1070 (Indicator Removal on Host)*

**Impact:** Complete exfiltration of Restricted-classified vulnerability and asset data. The attack exploits three gaps simultaneously: the system prompt accessible to administrators, the workflow-based (non-cryptographic) approval gate, and the non-append-only audit log. No alert is generated at any phase.

---

## 5. Detection Opportunities

For each attack phase and TTP, this section identifies where detection is theoretically possible and what signal would be present. This analysis informs the detection engineering backlog.

### 5.1 Detection Opportunities by Attack Phase

#### Prompt Injection and Jailbreak Detection

| Detection Point | Signal | Detection Method | Currently Implemented? |
|----------------|--------|-----------------|----------------------|
| Agent input ingestion | External data (CVE descriptions, TI narrative fields) containing instruction-syntax patterns (`ignore previous instructions`, `you are now`, `disregard`, system-override-style phrasing) | Regex/NLP pattern matching on ingested content before agent processing | No |
| Agent output | Outputs that instruct downstream processes rather than reporting findings (imperative verbs, system commands, structured override payloads in unexpected fields) | Secondary LLM judge evaluating outputs before upstream routing | No |
| Orchestrator behavior | Orchestrator taking actions outside its registered tool set (attempting to call APIs not in its allowlist, routing to unexpected endpoints) | Infrastructure-layer tool call monitoring; OPA policy enforcement | No |
| Pipeline state | Assessment completing without a human approval timestamp, or approval timestamp appearing before the report write timestamp | Workflow integrity monitoring; timestamp sequence validation | No |
| Audit log | Approval status set without corresponding Security Manager authentication event | Correlation of approval flag changes with authentication events in SIEM | Partial (SIEM exists; correlation rule not implemented) |

#### Data Poisoning and Adversarial Data Detection

| Detection Point | Signal | Detection Method | Currently Implemented? |
|----------------|--------|-----------------|----------------------|
| TI feed ingestion | Statistical anomalies in feed content: unusual volume changes, sudden appearance of novel ATLAS technique IDs, changes in confidence score distributions, attribution pattern shifts | Automated feed content anomaly monitoring; statistical baseline comparison | No |
| CVSS score generation | Agent-generated CVSS scores that deviate from NVD API baseline for the same CVE ID by more than a defined threshold | Automated cross-check: agent CVSS vs NVD API for all CVE IDs processed | No |
| CMDB read operations | Bulk CMDB queries or queries for fields outside the agent's defined scope (e.g., queries for network topology, credentials, or fields not in the criticality classification schema) | CMDB query-level audit logging; alert on scope-exceeding queries | Partial (CMDB audit logs exist; scope alerting not configured) |
| Cross-assessment comparison | Systematic drift in risk scores for specific asset types or vulnerability categories across multiple assessments — particularly drift that correlates with changes in TI feed content | Longitudinal output analysis: track risk score distributions over time; alert on statistically significant drift | No |

#### Reconnaissance and System Probing Detection

| Detection Point | Signal | Detection Method | Currently Implemented? |
|----------------|--------|-----------------|----------------------|
| Agent query patterns | High volume of similar queries with slight variations targeting a single agent; queries that attempt to elicit context window content rather than perform assigned analysis tasks | Query rate limiting per user/session; semantic clustering of queries to detect probing patterns | No |
| System prompt extraction | Queries containing extraction-pattern phrasing (`what are your instructions`, `repeat your system prompt`, `what data do you have access to`); agents returning prompt-like content in responses | Prompt extraction pattern detection in query pre-processor; output scanning for prompt-like content | No |
| Configuration file access | Access to agent configuration files (which contain system prompts) outside of change management windows by non-DevOps roles | Privileged access monitoring on configuration file paths; alert on read access by non-pipeline-admin roles | Partial (file access logging exists; alert not configured) |

#### Exfiltration Detection

| Detection Point | Signal | Detection Method | Currently Implemented? |
|----------------|--------|-----------------|----------------------|
| Report staging area | Access to staging area outside the normal post-approval window; bulk reads or copies of report files | DLP monitoring on staging area; alert on access by accounts other than Report Generator service account and Security Manager | Partial (access logging; DLP not implemented) |
| Network egress | Large data transfers from systems hosting agent infrastructure to external or unusual internal destinations, particularly during or immediately after assessment runs | Network traffic analysis; DLP on agent host egress; CASB integration | Partial (network monitoring exists; specific DLP rules not configured) |
| Inference API exfiltration | Agent responses that include structured data (IP ranges, asset names, CVE-asset correlations) in response to queries that should not trigger such data inclusion | Output content scanning for sensitive data patterns before responses are returned to requestors | No |

### 5.2 Detection Gap Summary

| Detection Capability | Status | Priority to Implement |
|---------------------|--------|----------------------|
| LLM output injection artifact detection (secondary judge) | Missing | Critical |
| TI feed content anomaly monitoring | Missing | High |
| CVSS cross-check against NVD API | Missing | High |
| Agent query pattern monitoring | Missing | High |
| Workflow integrity: approval timestamp sequence validation | Missing | Critical |
| System prompt extraction pattern detection | Missing | Medium |
| Report staging area DLP | Missing | High |
| Privileged configuration file access alerting | Partial | Medium |
| CMDB scope-exceeding query alerting | Partial | High |
| Longitudinal output drift analysis | Missing | Medium |

### 5.3 Recommended Detection Engineering Priorities

The two scenarios in Section 4 would both have been detectable with a small number of targeted detection rules. The highest-return detection investments, in priority order:

1. **Workflow integrity monitoring** — a single correlation rule in the SIEM: "approval status set without preceding Security Manager authentication event" would have detected Scenario 2 entirely. This requires one SIEM rule and zero additional infrastructure.

2. **Secondary LLM judge on agent outputs** — detects Scenario 1 (prompt injection via TI feed) before it propagates to the Orchestrator. Requires deployment of a small, purpose-built classifier model at the agent output layer.

3. **TI feed anomaly baseline** — a statistical baseline of normal feed content patterns (volume, technique ID distribution, confidence score distribution) with automated alerting on deviation. Would have detected Scenario 1 Phase 2 within the first affected assessment cycle.

4. **Audit log integrity enforcement** — converting the workflow log to an append-only structure removes the concealment capability used in Scenario 2 Phase 4 entirely. Infrastructure change, not a detection rule.

5. **CMDB query scope alerting** — configure existing CMDB audit logging to alert on queries for fields outside the Asset Context Agent's defined scope. One configuration change; no new infrastructure.

---

## 6. Threat Summary Matrix

| TTP | Threat Actors | Risk Score | Control Status | Detection Status | Remediation Priority |
|-----|--------------|------------|---------------|-----------------|---------------------|
| AML.T0051 — LLM Prompt Injection | TA-001, TA-003 | 20 — Critical | Partial | Missing | P1 — Immediate |
| AML.T0054 — LLM Jailbreak | TA-001, TA-002 | 15 — High | Partial | Missing | P1 — Immediate |
| AML.T0043 — Craft Adversarial Data | TA-001, TA-002 | 15 — High | Partial | Missing | P1 — Immediate |
| AML.T0020 — Poison Training Data | TA-001, TA-002 | 15 — High | Partial | Missing | P1 — Immediate |
| AML.T0048 — Erode ML Model Integrity | TA-001, TA-002 | 10 — High | Partial | Missing | P2 — 30 days |
| AML.T0056 — LLM Meta Prompt Extraction | TA-001, TA-002, TA-003 | 9 — Medium | Missing | Missing | P2 — 30 days |
| AML.T0040 — ML Model Inference API Access | TA-001, TA-002 | 8 — Medium | Partial | Missing | P2 — 30 days |
| AML.T0024 — Exfiltration via ML Inference API | TA-002, TA-003 | 8 — Medium | Partial | Partial | P2 — 30 days |
| AML.T0037 — Discover ML Model Ontology | TA-001, TA-002 | 6 — Medium | Partial | Missing | P3 — 60 days |
| AML.T0018 — Backdoor ML Model | TA-001 | 5 — Medium | Partial | Missing | P3 — 60 days |

---

*This threat model should be reviewed upon: any change to agent system prompts or workflow logic; any LLM model version update; any change to external data source integrations; publication of new MITRE ATLAS technique definitions; or any security incident affecting AI components. The attack scenarios in Section 4 should be used as the basis for tabletop exercises with the incident response team.*

*Next review: Q3 2025*
*Document owner: Security Engineering Lead*
*Threat model methodology: MITRE ATLAS v4.5 + STRIDE supplementary analysis*
