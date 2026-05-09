# Control Gap Analysis
## Multi-Agent AI Risk Analyst System

---

| Field | Detail |
|-------|--------|
| Document ID | CGA-MAARS-001 |
| Version | 1.0 |
| Classification | Confidential |
| Status | Draft — Pending Security Manager Review |
| Prepared by | Security Engineering |
| Review cycle | Quarterly or post-incident |

---

## Table of Contents

1. [Scope](#1-scope)
2. [OWASP LLM Top 10 Gap Analysis](#2-owasp-llm-top-10-gap-analysis)
3. [NIST AI RMF Gap Analysis](#3-nist-ai-rmf-gap-analysis)
4. [MITRE ATLAS Gap Analysis](#4-mitre-atlas-gap-analysis)
5. [Gap Summary Table](#5-gap-summary-table)
6. [Prioritized Remediation Roadmap](#6-prioritized-remediation-roadmap)

---

## 1. Scope

### 1.1 System Description

The Multi-Agent AI Risk Analyst System (MAARS) is a production AI pipeline that performs automated security risk assessments for enterprise IT environments. The system comprises six coordinated AI agents:

- **Orchestrator Agent** — coordinates workflow, dispatches tasks, holds the human approval gate
- **Asset Context Agent** — reads the CMDB to classify asset criticality
- **Vulnerability Agent** — fetches and scores CVEs against in-scope assets using NVD/CVSS data
- **Threat Intel Agent** — ingests threat intelligence feeds and maps adversary techniques to MITRE ATLAS
- **Control Mapping Agent** — identifies gaps against NIST RMF control families and the OWASP LLM Top 10
- **Report Generator Agent** — compiles findings into a risk register, executive summary, and CSV export

All agent outputs pass through a mandatory human approval gate before final report delivery. The system processes data classified at up to **Restricted** (internal asset inventory + correlated vulnerability data).

### 1.2 Frameworks Applied

| Framework | Version / Reference | Applicability |
|-----------|-------------------|---------------|
| OWASP LLM Top 10 | 2025 (v1.1) | Primary — direct LLM security risks |
| NIST AI Risk Management Framework | AI RMF 1.0 (NIST AI 100-1) | Governance and lifecycle controls |
| MITRE ATLAS | v4.5 | Adversarial ML threat modeling |
| NIST SP 800-53 | Rev 5 | Underlying control catalog (referenced in risk register) |
| NIST SP 800-37 | Rev 2 | Risk Management Framework process |

### 1.3 Assessment Methodology

Controls were assessed against three status levels:

| Status | Definition |
|--------|-----------|
| **Exists** | Control is fully implemented, documented, and verified through testing or evidence |
| **Partial** | Control is partially implemented or implemented but not consistently applied / tested |
| **Missing** | No control exists; the risk is unmitigated or mitigated only by compensating measures outside this system |

### 1.4 Assessment Boundaries

This gap analysis covers the MAARS system boundary including all six agents, their data stores, inter-agent communication channels, and the human approval gate. It does not cover:

- Underlying cloud infrastructure security (assessed separately under infrastructure compliance program)
- Physical security of data centers hosting the system
- Security of end-user devices used by the Security Manager for report approval

---

## 2. OWASP LLM Top 10 Gap Analysis

### LLM01 — Prompt Injection

**Status: Partial**

**Current controls:** Agent system prompts include refusal instructions. Orchestrator validates output schemas. Input data is processed inside isolated agent contexts.

**Gap:** No independent "judge" LLM validates agent outputs for injection artifacts before they propagate upstream. Input sanitization at ingestion points (particularly CVE description fields and TI feed narratives) is limited to schema validation — it does not detect embedded instruction syntax. Multi-turn prompt injection sequences targeting the Orchestrator are not specifically defended against, as the Orchestrator receives aggregated outputs from multiple agents and could be susceptible to indirect injection via corrupted agent results.

**Risk:** High. CVE descriptions and TI feed narratives are attacker-influenced content that is directly processed by LLM agents. This is the highest-likelihood injection vector in the system.

**Required control additions:**
- Secondary LLM judge evaluating every agent output for injection artifacts before upstream routing
- Regex/pattern-based pre-processing to flag instruction-syntax patterns in ingested external data
- Context-window scoping: each agent processes only its assigned task data, not accumulated conversation history

---

### LLM02 — Insecure Output Handling

**Status: Partial**

**Current controls:** Report Generator writes to a scoped staging area only. Report Generator hashes the draft report at creation time. Report format is a structured schema (risk register template, CSV).

**Gap:** The hash is computed and stored but the approval UI does not currently enforce hash verification by the Security Manager before sign-off — hash comparison is advisory rather than a blocking technical control. Additionally, structured output validation does not cover the executive summary (free-text section), which could contain hallucinated content presented as fact without a source citation requirement.

**Risk:** Medium. Structured outputs reduce injection surface significantly; the gap relates primarily to the integrity verification pathway and the free-text executive summary section.

**Required control additions:**
- Approval workflow should technically block sign-off unless the Security Manager has confirmed hash match (UI enforcement, not just display)
- Executive summary section should require inline citations linking claims back to source agent outputs

---

### LLM03 — Training Data Poisoning

**Status: Partial**

**Current controls:** TI feeds sourced from vetted commercial providers with contractual SLAs. CVE data sourced from NVD (authoritative source). Supplier risk assessments conducted annually.

**Gap:** The system relies on a single commercial TI feed as its primary source without automated cross-validation against a second independent source. There is no anomaly detection on feed content patterns (e.g., sudden spike or drop in IOC volume, introduction of novel unrecognized ATLAS technique IDs). CMDB data is treated as ground truth with no integrity verification — a compromised CMDB record could cause the Asset Context Agent to misclassify asset criticality, propagating errors through the entire risk assessment.

**Risk:** High. Single-source TI dependency creates a critical supply chain risk. CMDB integrity is foundational to the assessment; its compromise would invalidate all downstream outputs.

**Required control additions:**
- Minimum two independent TI feeds with consensus validation before TTP acceptance
- Feed anomaly detection monitoring (volume, TTP novelty, source attribution patterns)
- CMDB integrity baseline with periodic hash comparison against last-known-good snapshot

---

### LLM04 — Model Denial of Service

**Status: Missing**

**Current controls:** No specific DoS protections implemented at the LLM inference layer. General infrastructure rate limiting applies.

**Gap:** No per-agent rate limiting, token budget enforcement, or query complexity limits are in place at the application layer. A malicious actor with access to submit a risk assessment request (e.g., a large-scope CMDB query with thousands of assets) could cause excessive LLM inference costs, pipeline stalls, or timeouts that disrupt legitimate assessments. There is no circuit-breaker pattern for runaway agent loops.

**Risk:** Medium. The system is not externally accessible (internal use only), which reduces the threat surface. However, an insider or compromised internal system could trigger resource exhaustion.

**Required control additions:**
- Per-agent token budget limits enforced at the inference layer
- Maximum asset scope per assessment request (configurable ceiling)
- Circuit-breaker pattern: pipeline auto-terminates after configurable timeout per agent task
- Alerting on anomalous inference cost or duration

---

### LLM05 — Supply Chain Vulnerabilities

**Status: Partial**

**Current controls:** LLM model provider is a vetted enterprise provider. TI feed providers are annually assessed. NVD data sourced directly from NIST.

**Gap:** No software composition analysis (SCA) or SBOM is maintained for the agent orchestration framework, LLM inference libraries, or third-party integrations. Model versioning is not pinned — the underlying LLM could be updated by the provider without notification, potentially altering agent behavior. There is no process for verifying the integrity of model artifacts (e.g., checksum verification of model weights if self-hosted components are introduced in future).

**Risk:** Medium. Current reliance on a managed LLM service reduces immediate risk, but the absence of SBOM and model version pinning creates uncontrolled change risk.

**Required control additions:**
- SBOM for all framework dependencies; automated SCA scanning in CI/CD pipeline
- Model version pinning with explicit approval workflow for model updates
- Regression test suite for agent behavior run on every model version change

---

### LLM06 — Sensitive Information Disclosure

**Status: Partial**

**Current controls:** Agent access scoped to minimum required fields. CMDB token is session-scoped and stored in secrets manager. Inter-agent communication is internal only. Logs are access-controlled.

**Gap:** Agent logs may inadvertently capture full data payloads including asset names, CVE correlation details, and TI-sourced IOC details. No log scrubbing layer exists at agent output. Agents retain context window contents for the duration of their task — if an agent crashes or is restarted mid-task, context window contents could be exposed in crash dumps or error logs. Model inversion attacks have no specific defenses beyond access control.

**Risk:** High. The combination of Restricted-classified CMDB data with vulnerability information creates high-value intelligence if disclosed. Log exposure is a commonly overlooked secondary exfiltration path.

**Required control additions:**
- Log scrubbing layer at agent output: asset names, IP ranges, and CVE-asset correlations redacted before log write
- Context window cleared on task completion and agent shutdown; crash dump sanitization
- Query rate limiting on all agent APIs to slow inference/inversion attacks
- Field-level log classification: Restricted fields written to encrypted log tier only

---

### LLM07 — Insecure Plugin Design

**Status: Partial**

**Current controls:** Agent tool sets are hardcoded allowlists. Orchestrator cannot spawn unapproved sub-agents. Tool access is scoped per agent role.

**Gap:** The tool allowlists are currently enforced at the prompt/system-instruction layer rather than at the infrastructure layer. A sufficiently capable jailbreak could cause an agent to attempt tool calls outside its allowlist — the current defense relies on the LLM respecting its instructions, which is a soft control. There is no independent policy enforcement layer (e.g., OPA/Rego) that intercepts and validates tool calls before execution at the infrastructure level.

**Risk:** High. Prompt-layer enforcement is necessary but not sufficient; infrastructure-layer enforcement is required to make tool restrictions robust against jailbreak attacks.

**Required control additions:**
- Infrastructure-layer tool call interception: every tool call validated against agent's registered allowlist before execution, independent of LLM instruction compliance
- OPA/Rego policy enforcement sidecar for all agent API calls
- Alerting on any tool call attempt outside the registered allowlist (attempted bypass signal)

---

### LLM08 — Excessive Agency

**Status: Partial**

**Current controls:** Orchestrator WRITE access restricted to workflow state. Human approval gate required before report delivery. Most agents are READ-only. Orchestrator cannot make external network calls.

**Gap:** The human approval gate is currently enforced as a workflow step in the pipeline orchestration system — it is a process control, not a cryptographic technical control. A misconfiguration or pipeline logic error could theoretically allow a report to bypass the gate. There is no separation of duties between the person who configures the pipeline and the person who approves reports. The Orchestrator has no hard limit on the number of sub-tasks it can dispatch (a runaway loop risk).

**Risk:** High. The human approval gate is the single most important safety control in the system. Its implementation as a workflow step rather than a cryptographic requirement is the most significant agency-related gap.

**Required control additions:**
- Cryptographic signing requirement: report cannot be decrypted/delivered without Security Manager's private key signature — technical enforcement, not workflow enforcement
- Separation of duties: pipeline configuration access and report approval access must be held by different accounts
- Maximum task dispatch limit on Orchestrator with auto-halt on breach

---

### LLM09 — Misinformation / Overreliance

**Status: Partial**

**Current controls:** Vulnerability Agent instructed to cite source CVE IDs. Human approval gate provides a review checkpoint. Agents are instructed to flag low-confidence outputs.

**Gap:** There is no automated cross-check comparing agent-generated CVSS scores against NVD API scores for the same CVE ID. Hallucinated vulnerability assessments could pass through the pipeline if the cited CVE ID exists but the CVSS score is fabricated. Confidence scores are a prompted instruction, not a validated output field — agents could omit them without triggering a validation failure. The Control Mapping Agent's NIST RMF references are not verified against the official NIST control catalog; a hallucinated control reference (e.g., a plausible but non-existent control ID) would not be caught.

**Risk:** High. Undetected hallucinations in the vulnerability scoring or control mapping outputs directly corrupt the risk register — the primary deliverable of the system.

**Required control additions:**
- Automated CVSS score cross-check: agent-generated scores compared against NVD API for same CVE ID; discrepancies above threshold held for human review
- Confidence score as a required, validated output schema field (pipeline rejects outputs missing it)
- NIST control ID validation: Control Mapping Agent outputs validated against machine-readable NIST SP 800-53 Rev 5 control catalog

---

### LLM10 — Unbounded Consumption

**Status: Missing**

**Current controls:** General infrastructure resource limits apply. No application-layer controls.

**Gap:** No per-assessment resource budgets (token limits, processing time limits, cost ceilings) are enforced at the application layer. No alerting exists on anomalous resource consumption that could indicate a prompt injection attack inflating an agent's context window. The system has no mechanism to detect and terminate an assessment that is consuming disproportionate resources compared to its defined scope.

**Risk:** Medium. Primarily an availability and cost risk. Could mask injection attacks that use resource exhaustion as a distraction or disruption tactic.

**Required control additions:**
- Per-assessment resource budget (tokens, wall-clock time, estimated cost) enforced at orchestration layer
- Real-time resource consumption monitoring with auto-halt on budget breach
- Anomaly alerting: assessments consuming >2× the baseline resource budget flagged for review

---

## 3. NIST AI RMF Gap Analysis

The NIST AI Risk Management Framework organizes AI governance across four functions: **Govern**, **Map**, **Measure**, and **Manage**.

---

### 3.1 Govern

The Govern function establishes organizational accountability, policies, and culture for responsible AI development and deployment.

**Gaps identified:**

| Sub-function | Status | Gap Description |
|-------------|--------|----------------|
| GOVERN 1.1 — AI risk policies | Partial | An AI risk policy exists for the organization but does not specifically address multi-agent systems or the risks unique to AI pipelines operating on Restricted-classified data |
| GOVERN 1.2 — AI risk accountability | Partial | The Security Manager role is identified as the human approver but no formal AI system owner is designated with accountability for MAARS specifically |
| GOVERN 1.4 — Organizational risk tolerance | Missing | No formal AI risk tolerance statement has been defined for this system; risk acceptance decisions are made ad-hoc |
| GOVERN 2.2 — AI risk culture | Partial | Security team receives general AI security training; no specific training on multi-agent system risks, prompt injection, or adversarial ML |
| GOVERN 4.1 — Organizational teams | Partial | No formal AI safety review board or red team function; security reviews are conducted by the same team that builds the system |
| GOVERN 5.1 — Organizational risk policies for third parties | Partial | TI feed vendors are assessed but assessment criteria do not include AI-specific supply chain risks |
| GOVERN 6.1 — AI policies for deployment | Missing | No formal deployment readiness checklist or go/no-go criteria specific to AI systems in production |

**Priority gap:** The absence of a formal AI risk tolerance statement (GOVERN 1.4) means there is no agreed organizational baseline for acceptable residual risk. This makes risk acceptance decisions inconsistent and undocumented.

---

### 3.2 Map

The Map function identifies and categorizes AI risks in context — understanding what the system does, who is affected, and what could go wrong.

**Gaps identified:**

| Sub-function | Status | Gap Description |
|-------------|--------|----------------|
| MAP 1.1 — AI system categorization | Exists | System is categorized and documented; data classification applied |
| MAP 1.5 — Organizational risk context | Partial | Business context documented but threat landscape not formally updated more than annually |
| MAP 2.1 — Scientific and technical understanding | Partial | Team understands the LLM technology but has limited expertise in adversarial ML attacks specific to agentic systems |
| MAP 2.2 — AI risk identification | Partial | Risk register exists (this document) but is not derived from a formal threat modeling exercise updated at each model version change |
| MAP 3.1 — AI lifecycle risks | Partial | Development and deployment risks are considered; decommissioning and model replacement risks are not formally addressed |
| MAP 3.5 — Likelihood and impact | Exists | Risk register includes likelihood/impact scores |
| MAP 5.1 — Approaches to AI risk | Partial | Risk treatment decisions are made but not formally documented as accepted/transferred/mitigated with owner sign-off |

**Priority gap:** MAP 2.1 — the team lacks adversarial ML expertise specific to agentic pipelines. This creates a structural blind spot: risks that are not understood are not mapped.

---

### 3.3 Measure

The Measure function tests and evaluates AI systems to characterize their risks and validate that controls work.

**Gaps identified:**

| Sub-function | Status | Gap Description |
|-------------|--------|----------------|
| MEASURE 1.1 — AI risk evaluation approaches | Partial | Manual security review conducted; no automated continuous testing |
| MEASURE 2.1 — Evaluation approaches | Missing | No adversarial red-teaming (AI-specific) has been conducted against the system |
| MEASURE 2.2 — Evaluation with human input | Partial | Human approval gate provides one checkpoint; no structured usability or reliability evaluation of the gate itself |
| MEASURE 2.3 — AI system testing | Partial | Functional testing exists; no injection testing, jailbreak testing, or hallucination rate measurement |
| MEASURE 2.5 — Evaluation of AI output quality | Partial | No automated ground-truth comparison for CVSS scores or control mappings; human reviewer provides sole quality check |
| MEASURE 2.6 — Evaluation for bias | Missing | No evaluation of whether the system produces systematically biased risk scores for certain asset types or vulnerability categories |
| MEASURE 2.9 — Evaluation of explainability | Partial | Agent outputs include source citations but no structured explainability report linking each risk score to its evidence chain |
| MEASURE 3.1 — Incident identification | Missing | No AI-specific incident classification schema; AI failures are tracked in the general IT incident management system without AI-specific severity criteria |
| MEASURE 4.1 — Deployment monitoring | Partial | Infrastructure monitoring exists; no AI-specific behavioral monitoring (output drift, confidence score trends, hallucination rate) |

**Priority gap:** MEASURE 2.1 — the complete absence of adversarial red-teaming means the system's actual resilience against prompt injection, jailbreak, and data poisoning attacks is unknown. Controls exist on paper but their effectiveness is unvalidated.

---

### 3.4 Manage

The Manage function implements risk treatments and maintains ongoing operations and incident response.

**Gaps identified:**

| Sub-function | Status | Gap Description |
|-------------|--------|----------------|
| MANAGE 1.1 — AI risk treatment | Partial | Risk treatments defined in this document; formal treatment plan with owners and deadlines not yet established |
| MANAGE 1.3 — Prioritized risk treatment | Partial | Severity ratings applied; formal prioritization with budget allocation not yet completed |
| MANAGE 2.2 — Mechanisms for feedback | Partial | Security Manager can reject reports; no structured feedback mechanism for recording why rejections occurred or tracking rejection rate over time |
| MANAGE 2.4 — AI risk incidents | Missing | No AI-specific incident response playbook; general IR procedures do not cover scenarios such as prompt injection attacks, data poisoning, or hallucination-induced false risk assessments being approved |
| MANAGE 3.1 — AI risk treatment plans | Missing | No formal risk treatment plan document with assigned owners, target dates, and budget |
| MANAGE 3.2 — Treatment plans monitored | Missing | No tracking mechanism for remediation progress against this gap analysis |
| MANAGE 4.1 — Residual risk | Partial | Residual risk estimated in risk register; not formally accepted/signed off by designated risk owner |
| MANAGE 4.2 — Risk treatment effectiveness | Missing | No mechanism for measuring whether implemented controls actually reduce incident rates or risk scores over time |

**Priority gap:** MANAGE 2.4 — the absence of an AI-specific incident response playbook means that if a prompt injection attack succeeds, or a poisoned TI feed corrupts an assessment, the response team will have no pre-defined procedures to follow. Response time and effectiveness will be severely degraded.

---

## 4. MITRE ATLAS Gap Analysis

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) documents attack techniques specific to AI/ML systems. The following assessment identifies which ATLAS techniques are not adequately mitigated.

### 4.1 Coverage Assessment by Tactic

| ATLAS Tactic | Techniques Covered | Techniques Not Mitigated |
|-------------|-------------------|------------------------|
| Reconnaissance | AML.T0000 (Search for Victim's AI artifacts) | **Not mitigated** — no honeypot or deception layer; model architecture and agent prompts discoverable by authorized insiders |
| Resource Development | AML.T0017 (Acquire ML artifacts) | **Partially mitigated** — LLM from vetted provider; no artifact signing verification |
| Initial Access | AML.T0010 (ML Supply Chain Compromise) | **Partially mitigated** — supplier assessments exist; no SBOM or artifact integrity verification |
| Execution | AML.T0051 (LLM Prompt Injection) | **Partially mitigated** — system prompt defenses; no infrastructure-layer enforcement |
| | AML.T0054 (LLM Jailbreak) | **Partially mitigated** — refusal instructions; no red-team validation |
| | AML.T0056 (LLM Meta Prompt Extraction) | **Not mitigated** — system prompts not protected from extraction; no detection capability |
| Persistence | AML.T0019 (Backdoor ML Model) | **Partially mitigated** — managed model provider; no model integrity verification |
| Defense Evasion | AML.T0015 (Evade ML Model) | **Not mitigated** — no adversarial input detection at ingestion points |
| Discovery | AML.T0037 (Discover ML Artifacts) | **Not mitigated** — no monitoring for systematic probing of agent capabilities |
| Collection | AML.T0035 (ML Artifact Collection) | **Not mitigated** — no detection for systematic agent output harvesting |
| Exfiltration | AML.T0024 (Exfil via ML Inference API) | **Partially mitigated** — rate limiting not implemented; API access controlled but not monitored for exfil patterns |
| Impact | AML.T0020 (Poison Training Data) | **Partially mitigated** — single TI feed; no cross-validation |
| | AML.T0048 (Erode ML Model Integrity) | **Partially mitigated** — no behavioral drift monitoring |
| | AML.T0043 (Craft Adversarial Data) | **Partially mitigated** — schema validation only; no semantic adversarial input detection |

### 4.2 Unmitigated Technique Detail

**AML.T0056 — LLM Meta Prompt Extraction**
An adversary with query access could systematically probe agents to reconstruct their system prompts. Once extracted, the system prompts reveal the internal workflow structure, data sources, and security constraints — enabling more targeted attacks. No detection capability exists for this technique. Mitigation requires prompt confidentiality enforcement and monitoring for extraction-pattern queries.

**AML.T0015 — Evade ML Model**
Adversarial inputs crafted to evade detection by the Vulnerability Agent or Threat Intel Agent could cause them to miss genuine vulnerabilities or threat indicators. No adversarial input detection (e.g., input perturbation detection, anomaly scoring on inputs) is implemented at any ingestion point.

**AML.T0037 — Discover ML Artifacts**
An adversary conducting internal reconnaissance could probe agents with systematically varied inputs to map their capabilities, knowledge boundaries, and failure modes. No query pattern monitoring is implemented to detect this reconnaissance behavior.

**AML.T0035 — ML Artifact Collection**
Related to model inversion — an adversary could harvest agent outputs over time to reconstruct internal data (asset inventory patterns, vulnerability prioritization logic). No monitoring for systematic output collection exists.

---

## 5. Gap Summary Table

| Gap ID | Framework | Control Area | Gap Description | Severity | Recommended Remediation |
|--------|-----------|-------------|----------------|----------|------------------------|
| GAP-001 | OWASP LLM01 | Prompt injection defense | No infrastructure-layer injection defense; prompt-layer controls only | High | Deploy secondary LLM judge; implement regex pre-processing on ingested external data |
| GAP-002 | OWASP LLM03 | TI feed integrity | Single TI feed source; no cross-validation | High | Subscribe to second independent TI feed; implement consensus validation |
| GAP-003 | OWASP LLM07 | Tool call enforcement | Tool allowlists enforced at prompt layer only | High | Deploy OPA/Rego policy sidecar for infrastructure-layer tool call interception |
| GAP-004 | OWASP LLM08 | Human approval gate | Gate is a workflow step, not a cryptographic technical control | High | Implement cryptographic signing requirement for report delivery |
| GAP-005 | OWASP LLM09 | Hallucination detection | No automated CVSS or control ID cross-validation | High | Implement NVD API cross-check for CVSS scores; NIST catalog validation for control IDs |
| GAP-006 | OWASP LLM06 | Log data exposure | Agent logs may capture Restricted data payloads | High | Implement log scrubbing layer; field-level log classification |
| GAP-007 | NIST RMF MEASURE 2.1 | Red-team testing | No adversarial red-teaming of AI agents has been conducted | High | Commission external adversarial ML red-team exercise |
| GAP-008 | NIST RMF MANAGE 2.4 | Incident response | No AI-specific incident response playbook | High | Develop and tabletop-test AI IR playbook covering injection, poisoning, and hallucination scenarios |
| GAP-009 | ATLAS AML.T0056 | Prompt extraction | No protection or detection for system prompt extraction | High | Implement prompt confidentiality controls; monitor for extraction-pattern queries |
| GAP-010 | NIST AI RMF GOVERN 1.4 | Risk tolerance | No formal AI risk tolerance statement | Medium | Define and board-approve AI risk tolerance statement; integrate into risk acceptance workflow |
| GAP-011 | OWASP LLM04 / LLM10 | Resource limits | No per-agent token budgets or assessment resource ceilings | Medium | Implement per-assessment resource budgets at orchestration layer; circuit-breaker pattern |
| GAP-012 | OWASP LLM05 | Supply chain | No SBOM; model version not pinned | Medium | Establish SBOM for all framework dependencies; pin model version with change approval workflow |
| GAP-013 | ATLAS AML.T0015 | Adversarial input detection | No adversarial input detection at ingestion points | Medium | Implement anomaly scoring on ingested CVE and TI data; flag statistical outliers for review |
| GAP-014 | NIST AI RMF MEASURE 4.1 | Behavioral monitoring | No AI-specific output drift or hallucination rate monitoring | Medium | Implement behavioral monitoring dashboard: confidence score trends, CVSS discrepancy rate, rejection rate |
| GAP-015 | OWASP LLM03 | CMDB integrity | No integrity baseline for CMDB data | Medium | Implement CMDB hash baseline; periodic integrity comparison |
| GAP-016 | ATLAS AML.T0037 | Reconnaissance detection | No monitoring for systematic agent probing | Medium | Implement query pattern monitoring; alert on probing-pattern behavior |
| GAP-017 | NIST AI RMF GOVERN 2.2 | AI security training | No adversarial ML training for security team | Medium | Deliver adversarial ML training program; include agentic system attack simulation |
| GAP-018 | NIST AI RMF MANAGE 3.1 | Risk treatment plan | No formal risk treatment plan with owners and dates | Medium | Produce formal risk treatment plan from this gap analysis; assign owners; track in GRC tool |
| GAP-019 | OWASP LLM02 | Output integrity verification | Hash displayed but not technically enforced at approval | Low | Enforce hash verification as blocking step in approval UI |
| GAP-020 | NIST AI RMF MEASURE 2.6 | Bias evaluation | No evaluation for systematic bias in risk scoring | Low | Design and run bias evaluation study across asset types and vulnerability categories |

---

## 6. Prioritized Remediation Roadmap

Remediation actions are organized into three 30-day sprints. Priority is determined by: (1) severity of gap, (2) blast radius if exploited, and (3) implementation effort relative to risk reduction.

---

### 6.1 Days 1–30 — Critical Controls (Stop the Bleeding)

**Objective:** Close the highest-severity gaps that represent active, unmitigated risks to system integrity and report trustworthiness.

| Action | Gap(s) Addressed | Owner | Effort | Success Criterion |
|--------|-----------------|-------|--------|-------------------|
| Implement cryptographic signing for report delivery — replace workflow gate with technical signing requirement | GAP-004 | Security Engineering | Medium | Report delivery pipeline fails unless Security Manager's private key signature is present |
| Deploy OPA/Rego policy sidecar for tool call interception | GAP-003 | Platform Engineering | Medium | All tool calls validated at infrastructure layer; attempted out-of-allowlist calls generate alerts |
| Implement log scrubbing layer — redact Restricted fields before log write | GAP-006 | Security Engineering | Low | Asset names, IP ranges, CVE-asset correlations absent from standard log tier; confirmed by log audit |
| Subscribe to second independent TI feed; implement consensus validation for TTP acceptance | GAP-002 | Threat Intel Team | Low | No single-source TTP accepted without cross-validation; feed cross-check operational |
| Draft and tabletop-test AI-specific incident response playbook | GAP-008 | Security Operations | Low | Playbook covering prompt injection, data poisoning, and hallucination-induced false approval documented and tabletop-exercised |
| Add secondary LLM judge to agent output pipeline | GAP-001 | AI Engineering | High | Secondary judge evaluates all agent outputs before upstream routing; injection artifacts trigger alert and pipeline halt |

**30-day milestone:** All High-severity gaps with Low or Medium implementation effort are closed. Technical report signing is operational. AI IR playbook is tested.

---

### 6.2 Days 31–60 — Control Strengthening (Build the Foundation)

**Objective:** Implement monitoring and validation infrastructure that makes existing controls measurable and detectable gaps auditable.

| Action | Gap(s) Addressed | Owner | Effort | Success Criterion |
|--------|-----------------|-------|--------|-------------------|
| Implement NVD API cross-check for agent-generated CVSS scores | GAP-005 | AI Engineering | Medium | All CVSS scores automatically verified against NVD API; discrepancies >0.5 held for human review |
| Validate NIST control IDs against machine-readable SP 800-53 Rev 5 catalog | GAP-005 | AI Engineering | Low | Control Mapping Agent outputs with non-existent control IDs rejected by pipeline |
| Implement per-assessment resource budgets and circuit-breaker | GAP-011 | Platform Engineering | Medium | Assessments auto-halt at defined token/time ceiling; budget breach generates alert |
| Establish SBOM for all framework dependencies; pin LLM model version | GAP-012 | DevSecOps | Medium | SBOM committed to repository; model version change requires documented approval |
| Implement CMDB integrity baseline with periodic comparison | GAP-015 | Asset Management / Security Engineering | Medium | CMDB baseline hash established; daily comparison automated; drift generates alert within 4 hours |
| Deploy behavioral monitoring dashboard | GAP-014 | Security Operations | Medium | Dashboard tracking: agent confidence score trends, CVSS discrepancy rate, report rejection rate, pipeline anomalies |
| Implement query pattern monitoring for agent probing detection | GAP-016 | Security Operations | Low | Alerts generated on systematic probing patterns (>N similar queries with slight variations within time window) |
| Define formal AI risk tolerance statement | GAP-010 | CISO / Risk Management | Low | Risk tolerance statement approved by CISO; integrated into risk acceptance documentation |

**60-day milestone:** Hallucination detection is automated. Behavioral monitoring is live. Resource limits are enforced. SBOM exists. Risk tolerance is formally documented.

---

### 6.3 Days 61–90 — Resilience and Assurance (Validate and Sustain)

**Objective:** Validate that implemented controls actually work through adversarial testing; build the governance structures that sustain security posture over time.

| Action | Gap(s) Addressed | Owner | Effort | Success Criterion |
|--------|-----------------|-------|--------|-------------------|
| Commission external adversarial ML red-team exercise | GAP-007 | Security Engineering (sponsor) | High | Red team conducts prompt injection, jailbreak, data poisoning, and model inversion attacks; findings documented; all critical findings remediated |
| Implement system prompt confidentiality controls and extraction detection | GAP-009 | AI Engineering | Medium | System prompts not returnable in agent outputs; extraction-pattern queries generate alerts; tested by red team |
| Deliver adversarial ML security training to security team | GAP-017 | Security Training | Medium | All security team members complete training; knowledge assessment ≥80% pass rate |
| Implement adversarial input anomaly scoring at CVE and TI ingestion points | GAP-013 | AI Engineering | High | Statistical outlier inputs flagged with anomaly score; score threshold triggers human review before processing |
| Produce formal risk treatment plan with assigned owners and GRC tracking | GAP-018 | Risk Management | Low | All gaps from this document entered in GRC tool with owner, target date, and budget; reviewed monthly |
| Enforce hash verification as blocking step in approval UI | GAP-019 | Product Engineering | Low | Approval UI blocks sign-off until hash confirmation step is completed; confirmed by QA test |
| Design and run bias evaluation study | GAP-020 | AI Engineering / Security | High | Bias evaluation methodology documented; study completed across representative asset and vulnerability categories; findings reviewed |

**90-day milestone:** Red-team exercise complete with critical findings remediated. All gaps addressed or have formal risk treatment plan with owner. System is measurably more resilient than at baseline.

---

## Appendix A — Control Status Summary

| Framework | Total Controls Assessed | Exists | Partial | Missing |
|-----------|------------------------|--------|---------|---------|
| OWASP LLM Top 10 | 10 | 0 | 8 | 2 (LLM04, LLM10) |
| NIST AI RMF — Govern | 7 | 0 | 4 | 3 |
| NIST AI RMF — Map | 7 | 2 | 5 | 0 |
| NIST AI RMF — Measure | 9 | 0 | 5 | 4 |
| NIST AI RMF — Manage | 8 | 0 | 3 | 5 |
| MITRE ATLAS (key techniques) | 14 | 0 | 7 | 7 |
| **Total** | **55** | **2 (4%)** | **32 (58%)** | **21 (38%)** |

The 4% "Exists" rate reflects that this is a newly deployed system at initial production readiness. The 58% "Partial" rate is expected at this stage — basic controls are in place but have not been hardened, validated, or made technically enforcing. The 38% "Missing" rate, particularly concentrated in NIST AI RMF Manage and ATLAS reconnaissance/evasion techniques, represents the primary remediation priority.

---

## Appendix B — Definitions

| Term | Definition |
|------|-----------|
| ATLAS | Adversarial Threat Landscape for Artificial-Intelligence Systems (MITRE) |
| CVSS | Common Vulnerability Scoring System |
| GRC | Governance, Risk, and Compliance |
| IR | Incident Response |
| NVD | National Vulnerability Database (NIST) |
| OPA | Open Policy Agent — policy enforcement engine |
| SBOM | Software Bill of Materials |
| TTP | Tactics, Techniques, and Procedures |

---

*This document should be reviewed quarterly, or immediately following: (1) any model version update, (2) any security incident affecting the system, (3) publication of a new OWASP LLM Top 10 or ATLAS version, or (4) any significant change to the system architecture.*

*Next scheduled review: Q3 2025*
*Document owner: Security Engineering Lead*
*Approval required from: CISO or designated deputy*
