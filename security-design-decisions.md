# Security Design Decisions
## Multi-Agent AI Risk Analyst System (MAARS)
### Architecture Decision Records

---

| Field | Detail |
|-------|--------|
| Document ID | SDD-MAARS-001 |
| Version | 1.0 |
| Classification | Internal |
| Document Type | Architecture Decision Record (ADR) Collection |
| Prepared by | Security Engineering |
| Status | Approved |
| Review Cycle | Upon architecture change or annually |

---

## Purpose of This Document

Architecture Decision Records (ADRs) document the reasoning behind significant design choices. They answer a question that documentation rarely captures: not just *what* was built, but *why it was built that way* — and what alternatives were seriously considered and rejected.

For AI systems, this reasoning is especially important. The security properties of an AI pipeline emerge from hundreds of individual design decisions, many of which trade off convenience against safety, speed against auditability, or automation against human control. Without explicit documentation of these choices, future engineers may unknowingly reverse safety-critical decisions, or auditors may question whether controls were designed intentionally.

This document records eight foundational security design decisions for MAARS. Each record follows a consistent structure:

| Field | Content |
|-------|---------|
| **Decision** | The choice that was made |
| **Option chosen** | The selected approach |
| **Alternative considered** | The main alternative that was evaluated and rejected |
| **Context** | The problem being solved and constraints in play |
| **Rationale** | Why the chosen option is preferable |
| **Trade-offs accepted** | What the chosen option costs or makes harder |
| **Security benefit gained** | The specific security properties this decision provides |
| **References** | Related documents, frameworks, and standards |

---

## ADR Index

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](#adr-001--read-only-access-for-specialist-agents) | Read-only access for specialist agents | Approved |
| [ADR-002](#adr-002--human-approval-gate-over-automated-delivery) | Human approval gate over automated delivery | Approved |
| [ADR-003](#adr-003--separate-specialist-agents-over-monolithic-llm) | Separate specialist agents over monolithic LLM | Approved |
| [ADR-004](#adr-004--three-framework-coverage-over-single-framework) | Three-framework coverage over single framework | Approved |
| [ADR-005](#adr-005--dedicated-orchestrator-agent-over-distributed-orchestration) | Dedicated Orchestrator agent over distributed orchestration | Approved |
| [ADR-006](#adr-006--structured-output-formats-over-free-form-llm-text) | Structured output formats over free-form LLM text | Approved |
| [ADR-007](#adr-007--explicit-classification-labels-at-every-data-boundary) | Explicit classification labels at every data boundary | Approved |
| [ADR-008](#adr-008--agent-specific-logging-over-centralised-log-only) | Agent-specific logging over centralised log-only | Approved |

---

## ADR-001 — Read-Only Access for Specialist Agents

### Decision

The Asset Context, Vulnerability, Threat Intel, and Control Mapping agents are granted read-only access to their respective data sources. None of these agents can write to, modify, or delete any data in any system they access.

---

**Option chosen:** Read-only access for all specialist agents. Write access restricted to the Report Generator (report staging area only) and the Orchestrator (workflow state log only).

**Alternative considered:** Read-write access for agents that might need to update systems during assessment — for example, allowing the Asset Context Agent to annotate CMDB records with criticality classifications, or allowing the Vulnerability Agent to write scan results back to a vulnerability management database.

---

### Context

MAARS agents are LLM-based components that process external, attacker-influenced data. The Vulnerability Agent reads CVE descriptions written by third parties. The Threat Intel Agent reads feeds from commercial providers who could be compromised. Any of these agents could, in theory, be manipulated through prompt injection or adversarial data to take actions beyond their intended scope.

The question of access design therefore cannot be answered solely by asking "what does the agent need to do its job?" It must also account for: "what is the worst-case outcome if this agent is compromised or manipulated?"

---

### Rationale

**Blast radius containment is the primary justification.** If an agent with read-write access is compromised — through prompt injection, a jailbreak, or a supply chain attack on its underlying model — the attacker gains the ability to modify or destroy data in every system that agent can write to. The scope of damage is bounded by the access scope of the compromised agent.

Read-only access makes this class of attack structurally impossible for specialist agents. A successfully injected Vulnerability Agent cannot write false vulnerability data back to NVD. A successfully jailbroken Threat Intel Agent cannot modify the TI feed it is reading. The attacker's leverage is limited to what they can cause the agent to *report*, not what they can cause it to *do*.

This mirrors a well-established principle from traditional access control: the principle of least privilege applied specifically to the write dimension. An analyst who needs to read a database to produce a report does not need to modify that database to do their job. The same logic applies directly to AI agents.

**The write capability adds no functional value for analytical agents.** The Asset Context Agent's job is to read CMDB records and classify assets. It does not need to write its classifications back to the CMDB to perform this function — it returns classifications to the Orchestrator, which routes them to the Report Generator. The workflow does not require any specialist agent to persist data outside its response payload.

**Auditability is simplified.** When an investigation asks "how did this CMDB record get modified?", the answer cannot involve any specialist agent — they have no write access. The investigation space is immediately narrowed.

---

### Trade-offs Accepted

- **Workflow efficiency:** In some deployment scenarios, having agents annotate source systems directly would reduce the need to run the full assessment pipeline to update records. This convenience is sacrificed.
- **State persistence:** Agents cannot store intermediate results in shared data stores, requiring all state to flow through the Orchestrator. This adds architectural complexity to the orchestration layer.
- **Future capability:** Some advanced risk management workflows would benefit from agents that can update ticketing systems or vulnerability management platforms. These use cases cannot be supported without a formal access escalation process and additional controls.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Blast radius reduction | Compromise of any specialist agent cannot result in data modification in any source system |
| Prompt injection containment | Injected instructions cannot cause agents to execute write operations even if they override system prompt instructions |
| Integrity protection | Source data (CMDB, CVE DB, TI feeds) is protected from AI-layer corruption regardless of agent behavior |
| Audit simplification | Write operations to source systems can only originate from human operators or non-agent processes, narrowing the investigation space for data integrity incidents |

**References:** NIST SP 800-53 AC-6 (Least Privilege), OWASP LLM08 (Excessive Agency), MAARS Risk Register RR-003

---

## ADR-002 — Human Approval Gate Over Automated Report Delivery

### Decision

Every risk assessment report produced by MAARS must be reviewed and explicitly approved by a designated Security Manager before it is delivered to any stakeholder. This requirement is architectural — the pipeline does not have a pathway to deliver a report without a human approval action.

---

**Option chosen:** Mandatory human approval gate: Security Manager reviews every report, verifies the hash, and signs off before delivery. Target state: cryptographic signing requirement (report technically undeliverable without Security Manager's private key signature).

**Alternative considered:** Fully automated delivery: once the pipeline completes and the Report Generator produces a validated output, the report is automatically distributed to defined stakeholders. Human review becomes optional or advisory rather than mandatory.

---

### Context

MAARS processes data from external, attacker-influenced sources and uses LLM components that can hallucinate, be manipulated, or produce confidently wrong outputs. The outputs of the pipeline — risk registers, executive summaries, vulnerability-to-asset correlations — inform real security decisions: which vulnerabilities to patch first, which systems to prioritize in incident response, what to report to the board.

A risk report that contains false information is not merely a technical failure. It is a security incident. An organization acting on a manipulated or hallucinated risk assessment may leave critical vulnerabilities unaddressed, waste remediation budget on non-existent risks, or present false assurance to the board that their environment is more secure than it is.

The question is: should a human always stand between the AI's analysis and the decisions it informs?

---

### Rationale

**Accountability requires a decision-maker.** Automated systems do not have accountability. When a risk assessment informs a decision that turns out to be wrong, the organization needs to be able to explain who was responsible for that assessment. A human approval gate creates a named, authenticated decision-maker who has reviewed the output and taken responsibility for its distribution. Automation has no equivalent accountability property.

**Error correction before consequences.** AI systems make errors. LLMs hallucinate. Data sources can be poisoned. A human reviewer who knows the environment can catch errors that automated validation cannot — a CVSS score that is technically within the valid range but is inconsistent with the reviewer's knowledge of the vulnerability, a TTP attribution that does not match the current threat landscape, an asset misclassification that contradicts a recent infrastructure change. The value of human review is not that it catches every error; it is that it provides a final layer of defense against the errors that automated validation is structurally unable to detect.

**The cost of a missed error is asymmetric.** The cost of requiring human review is measured in hours of a Security Manager's time per assessment cycle. The cost of distributing a manipulated or incorrect risk report to board-level stakeholders — and having leadership make security investment decisions based on false data — is measured in organizational risk exposure, potential regulatory consequence, and erosion of trust in the security function. The asymmetry strongly favors human review.

**Automation is appropriate for the pipeline; humans are appropriate for the output.** MAARS automates the data collection, correlation, and report compilation that would otherwise take analysts weeks. This automation is valuable and appropriate — it handles the volume and consistency problem. The human approval gate does not negate the automation; it adds a quality and accountability checkpoint at the single moment where the AI's output becomes the organization's decision basis.

---

### Trade-offs Accepted

- **Throughput constraint:** The pipeline cannot produce approved reports faster than the Security Manager can review them. In organizations with high assessment volume, this creates a bottleneck. Mitigation: the review process is scoped to validation, not reconstruction — the Security Manager reviews a structured output, not raw data.
- **Availability dependency:** If the Security Manager is unavailable, reports cannot be approved. A formal delegation process (named alternate approver) is required to prevent this from blocking operations.
- **Human error:** Human reviewers make mistakes. A Security Manager who rubber-stamps reports without genuine review provides the appearance of oversight without the substance. Process controls (review checklists, minimum review time, dual approval for Critical-rated reports) mitigate but cannot eliminate this risk.
- **Latency:** Automated delivery would be faster. The approval gate adds hours to the time from assessment completion to stakeholder delivery.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Accountability | Named, authenticated human is responsible for every report that reaches stakeholders |
| Error interception | Human review provides a detection layer for hallucinations, manipulations, and data quality issues that automated validation cannot catch |
| Integrity assurance | Hash verification at approval confirms the report has not been tampered with between generation and review |
| Regulatory defensibility | Human sign-off creates an audit trail demonstrating due diligence in the risk assessment process |
| Safety net for AI failure modes | The gate is effective against every AI failure mode that produces a report — prompt injection, hallucination, data poisoning — because the output must pass human review regardless of how it was produced |

**References:** NIST AI RMF GOVERN 1.2 (Accountability), NIST SP 800-53 AC-5 (Separation of Duties), OWASP LLM08 (Excessive Agency), MAARS Risk Register RR-008

---

## ADR-003 — Separate Specialist Agents Over Monolithic LLM

### Decision

MAARS uses six separate, functionally distinct agents — each with a specific task, a specific data access scope, and a specific output format — rather than a single large LLM that is prompted to perform the entire risk assessment end-to-end.

---

**Option chosen:** Six specialist agents (Asset Context, Vulnerability, Threat Intel, Control Mapping, Report Generator, Orchestrator), each with scoped access, scoped prompts, and scoped output responsibility.

**Alternative considered:** A single monolithic LLM instance prompted with the full assessment task: "You are a security analyst. Here is the CMDB, here are the CVEs, here is the threat intelligence, here is the NIST framework. Produce a complete risk assessment."

---

### Context

Modern frontier LLMs are capable of performing multi-step analytical tasks in a single prompt. It would be technically feasible to build MAARS as a single model invocation with a very large context window containing all source data. This would be simpler to implement and deploy. The question is whether simplicity is the right optimization for a security-critical system.

---

### Rationale

**Least privilege is structurally enforced, not instructed.** In a monolithic architecture, all data is in the context window simultaneously. The model that reads CMDB records is the same model that reads CVE descriptions written by third parties — creating a direct prompt injection pathway where adversarial content in CVE descriptions can influence the model's interpretation of CMDB data. In the specialist agent architecture, these are separate agents with separate context windows. The Vulnerability Agent never sees CMDB content; the Asset Context Agent never sees raw CVE descriptions. Least privilege is a structural property, not an instruction in a system prompt that can be overridden.

**The blast radius of any single compromise is bounded.** If the Threat Intel Agent is successfully jailbroken, the attacker gains control of that agent's output — TTP mappings. They do not gain access to the CMDB data that the Asset Context Agent holds, or the vulnerability scoring that the Vulnerability Agent produced, or the Orchestrator's coordination logic. In a monolithic system, compromising the model compromises the entire assessment.

**Auditability becomes tractable.** When an investigation asks "how did this incorrect risk score appear in the report?", the specialist architecture narrows the answer to a specific agent's output, a specific data source, and a specific processing step. In a monolithic system, the answer is "somewhere in the context window of a single large model call" — which provides no actionable forensic information.

**Failure modes are isolated.** If the Vulnerability Agent's LLM component produces an anomalous output — an unusually high number of high-severity findings, outputs that fail schema validation, a confidence score distribution far from baseline — the pipeline can halt that agent specifically, flag the output for human review, and continue the assessment with degraded capability (marking vulnerability findings as unverified) rather than failing the entire assessment. A monolithic system either succeeds or fails as a whole.

**Each agent's system prompt is smaller, more auditable, and harder to override.** A monolithic system prompt for a full risk assessment would be thousands of tokens long, covering every sub-task, every data source, every output format. Maintaining, auditing, and testing such a prompt is extremely difficult. Each specialist agent has a focused system prompt covering only its specific task, making it far easier to audit for security properties, test for robustness, and red-team for jailbreak vulnerabilities.

---

### Trade-offs Accepted

- **Infrastructure complexity:** Six agents require six deployment environments, six sets of credentials, six monitoring configurations, and six system prompts to maintain.
- **Orchestration overhead:** The Orchestrator adds a coordination layer that introduces potential failure points and requires careful design.
- **Latency:** Sequential agent processing adds wall-clock time compared to a single large model call. (Partially mitigated by parallel execution of independent agents.)
- **Context limitations:** Agents cannot access information held by other agents without going through the Orchestrator, which can limit contextual reasoning across data types. Mitigation: the Report Generator receives all agent outputs simultaneously.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Structural least privilege | Each agent's data access scope is determined by its service account, not its system prompt — scope cannot be overridden by prompt injection |
| Blast radius containment | Compromise of any single agent is bounded to that agent's output scope |
| Auditability | Every processing step is attributable to a specific agent, a specific input, and a specific output |
| Failure isolation | Anomalies in one agent can be handled without invalidating the entire assessment |
| Prompt auditability | Each agent's instructions are small enough to be meaningfully reviewed and red-teamed |

**References:** NIST SP 800-53 AC-6 (Least Privilege), NIST SP 800-53 AU-12 (Audit Record Generation), OWASP LLM01 (Prompt Injection), MAARS Risk Register RR-001

---

## ADR-004 — Three-Framework Coverage Over Single Framework

### Decision

MAARS is assessed against three complementary security frameworks — OWASP LLM Top 10, NIST AI RMF, and MITRE ATLAS — rather than selecting a single authoritative framework.

---

**Option chosen:** All three frameworks applied in combination: OWASP LLM Top 10 for technical LLM-specific risks, NIST AI RMF for organizational governance, and MITRE ATLAS for adversarial threat modeling.

**Alternative considered (A):** NIST AI RMF alone, as the most comprehensive and regulatory-aligned governance framework.

**Alternative considered (B):** OWASP LLM Top 10 alone, as the most practically focused and widely adopted framework for LLM applications.

---

### Context

No single security framework provides complete coverage of the risk landscape for an AI system. Frameworks are built for different purposes, by different communities, with different threat models in mind. Selecting only one framework creates systematic blind spots — entire categories of risk that the selected framework does not address and that will therefore go unassessed.

The question is whether multi-framework complexity is worth the coverage improvement, or whether one well-applied framework is sufficient.

---

### Rationale

**The frameworks address genuinely different risk dimensions.** This is not redundancy — it is coverage complementarity.

OWASP LLM Top 10 answers: *What technical vulnerabilities exist in the LLM components of this system?* It provides the practitioner-level, attack-surface-focused catalog needed to assess whether individual agents are hardened against the most common LLM attack vectors. It does not address organizational governance, incident response maturity, or adversary-specific threat scenarios.

NIST AI RMF answers: *Does the organization have the governance structures to manage AI risk sustainably over time?* It addresses the lifecycle risks that exist outside the system itself — whether risk decisions are accountable, whether testing is systematic, whether incident response exists, whether the organization can sustain the controls it has implemented. It does not provide a TTP catalog or a technical vulnerability checklist.

MITRE ATLAS answers: *How would a real adversary actually attack this system, and with what sequence of techniques?* It provides the adversary-perspective modeling that neither OWASP nor NIST provides — enabling threat narratives, TTP chaining, and detection engineering that is grounded in how real AI attacks have occurred, not just what categories of risk theoretically exist. It does not provide governance guidance or a ranked list of common vulnerabilities.

**A single framework produces false completeness.** An organization that assesses only against NIST AI RMF will have excellent governance documentation and no assessment of whether the Vulnerability Agent is vulnerable to prompt injection. An organization that assesses only against OWASP LLM Top 10 will have a hardened application and no AI-specific incident response playbook. An organization that assesses only against MITRE ATLAS will have a sophisticated threat model and no awareness that their single TI feed is a governance failure. Each single-framework approach provides genuine value; none provides adequate coverage.

**Multi-framework analysis produces cross-validation.** When all three frameworks identify the same gap — for example, the absence of adversarial testing appears in OWASP LLM evaluation, in NIST AI RMF MEASURE 2.1, and in ATLAS reconnaissance mitigations — that convergence provides high confidence that the gap is real and significant, not an artifact of one framework's perspective.

---

### Trade-offs Accepted

- **Assessment scope and effort:** Three frameworks require more time and expertise to apply thoroughly than one. The control gap analysis covers 55 control points; a single-framework assessment might cover 20.
- **Stakeholder communication complexity:** Explaining three frameworks to a non-technical audience requires more translation work. Mitigation: the executive summary presents findings in plain language without framework references.
- **Potential for conflicting guidance:** Rarely, frameworks suggest different mitigations for the same risk. These conflicts are resolved by defaulting to the more conservative control. No irreconcilable conflicts were identified in this assessment.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Complete risk coverage | No major risk category is missed due to framework scope limitations |
| Cross-validation | Gaps identified by multiple frameworks carry higher confidence |
| Regulatory defensibility | Alignment with NIST AI RMF satisfies emerging regulatory expectations; OWASP alignment satisfies security community expectations |
| Adversary realism | ATLAS integration ensures the threat model reflects how real attackers operate, not just theoretical risk categories |
| Sustained governance | NIST AI RMF ensures controls are institutionalized, not just documented at a point in time |

**References:** NIST AI 100-1 (AI RMF), OWASP LLM Top 10 2025, MITRE ATLAS v4.5, MAARS Control Gap Analysis CGA-MAARS-001

---

## ADR-005 — Dedicated Orchestrator Agent Over Distributed Orchestration

### Decision

MAARS uses a dedicated Orchestrator agent as a single coordination point for the pipeline. Specialist agents do not coordinate with each other directly — all inter-agent communication flows through the Orchestrator.

---

**Option chosen:** Single dedicated Orchestrator agent that dispatches tasks, receives results, validates outputs, and manages pipeline state. Specialist agents are consumers of task dispatches and producers of results — they have no awareness of each other or the broader pipeline.

**Alternative considered:** Distributed orchestration where each agent is responsible for triggering the next step — the Asset Context Agent, having completed its task, directly passes its output to the Vulnerability Agent, which passes its output to the Threat Intel Agent, and so on in a chain.

---

### Context

In a multi-agent system, workflow coordination can be implemented in multiple ways. The simplest is a chain: each agent knows which agent comes next and triggers it directly. This is easier to implement and requires no central coordinator. The alternative — a hub-and-spoke model with a dedicated orchestrator — adds a component but centralizes control.

For a security-critical pipeline, the choice between these models has significant security implications beyond implementation convenience.

---

### Rationale

**Separation of concerns is a foundational security principle.** In the distributed model, every specialist agent carries two responsibilities: performing its analytical task and managing workflow coordination. This conflation means that a vulnerability in the workflow coordination logic of the Threat Intel Agent (for example) could be exploited to manipulate the pipeline — not just the TI analysis. The dedicated Orchestrator separates these concerns cleanly: specialist agents are responsible only for their analytical task; the Orchestrator is responsible only for coordination. Each component can be designed, audited, and tested for its single responsibility.

**Policy enforcement has a single implementation point.** In the distributed model, pipeline policy — which agents run, in what order, what happens when an agent fails, what constitutes an acceptable output — is distributed across all agents. Enforcing a new policy requires updating every agent. In the Orchestrator model, pipeline policy lives in one place. Adding a new validation rule (for example, requiring all agent outputs to include a confidence score) requires changing the Orchestrator once, not modifying every downstream agent.

**The human approval gate has a natural owner.** The Orchestrator is the component that decides whether the pipeline proceeds to report generation. It is the natural and correct owner of the human approval gate check — verifying that approval has been granted before routing to the Report Generator. In a distributed model, this check would need to be implemented in whichever agent triggers the Report Generator, creating an architectural dependency between a specialist agent and a governance requirement.

**Anomaly detection is centralized.** The Orchestrator observes every agent's output before it is passed downstream. This makes it the natural point for cross-agent anomaly detection — identifying, for example, that the Vulnerability Agent is reporting an unusually high number of critical findings on assets that the Asset Context Agent classified as low-criticality. Neither agent individually has visibility into this anomaly; the Orchestrator, receiving both outputs, does.

**The blast radius of Orchestrator compromise is bounded differently.** One objection to the hub model is that the Orchestrator becomes a high-value target — compromise it and you influence the entire pipeline. This is true, and it motivates the strict access controls applied to the Orchestrator (Restricted trust zone, no external data source access, no write access to source systems). The counter-argument is that in the distributed model, every agent is effectively an Orchestrator for the next step in the chain — there is no reduction in attack surface, only a distribution of it across components that have less security investment.

---

### Trade-offs Accepted

- **Single point of failure:** If the Orchestrator fails, the entire pipeline halts. Mitigation: the Orchestrator is the highest-availability component; it processes coordination logic only, not analytical tasks, keeping it simple and reliable.
- **Orchestrator as high-value target:** Concentrating coordination logic in one component makes that component a high-value target for attackers seeking to manipulate the pipeline. Mitigation: the Orchestrator is placed in the Restricted trust zone with the most stringent access controls in the system.
- **Latency:** All inter-agent communication passes through the Orchestrator, adding a hop. In practice, the coordination overhead is negligible compared to agent inference time.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Separation of concerns | Analytical agents are responsible only for analysis; workflow policy is owned entirely by the Orchestrator |
| Centralized policy enforcement | Pipeline security policies (output validation, approval gate, anomaly detection) have a single implementation point |
| Cross-agent anomaly detection | The Orchestrator can detect inconsistencies across agent outputs that no individual agent could observe |
| Audit clarity | Every pipeline decision — which agent ran, when, with what result — is recorded by a single component |
| Blast radius management | Specialist agent compromise cannot propagate to pipeline control; that capability is reserved to the Orchestrator |

**References:** NIST SP 800-53 CM-7 (Least Functionality), NIST SP 800-53 AU-12 (Audit Record Generation), OWASP LLM08 (Excessive Agency), MAARS Architecture Diagram

---

## ADR-006 — Structured Output Formats Over Free-Form LLM Text

### Decision

All agent outputs in MAARS are produced in defined, validated schemas — risk register entries follow a fixed field structure, vulnerability outputs follow a CVSS-aligned schema, TTP mappings follow the ATLAS technique ID format. Agents are not permitted to produce free-form narrative text as their primary output (with the exception of the executive summary section of the final report, which has its own validation requirements).

---

**Option chosen:** Structured, schema-validated output formats for all agent outputs. Free-form narrative is restricted to explicitly designated sections of the final report and requires additional validation (source citations).

**Alternative considered:** Free-form LLM text output for all agents, relying on the human reviewer to assess quality and extract structured information at the approval gate. Alternatively, structured output for the final report only, with free-form outputs in inter-agent communication.

---

### Context

LLMs produce text. Their natural output mode is narrative prose. Requiring structured output imposes constraints on the model and requires additional validation infrastructure. The question is whether this constraint is worth the implementation complexity.

---

### Rationale

**Downstream reliability requires structural predictability.** The Report Generator receives outputs from four specialist agents and compiles them into a risk register. If any agent produces output in an unexpected format — fields in the wrong order, a CVSS score expressed as a string rather than a float, an ATLAS technique ID in a non-standard format — the Report Generator either fails to process it (a reliability problem) or silently misinterprets it (a correctness problem that may not be detected). Structured schemas with machine validation make both of these failure modes detectable and handleable.

**Schema validation is a prompt injection detection mechanism.** A successfully injected agent output will often violate the expected schema — it will contain instructions, narrative text, or unusual field values rather than the expected structured data. Schema validation at the Orchestrator layer acts as a first-pass injection detector: outputs that cannot be parsed against the schema are quarantined before they propagate. A free-form output has no equivalent detection mechanism — injected content is indistinguishable from legitimate narrative.

**Hallucination is bounded and detectable.** An LLM producing a free-form risk assessment can hallucinate any content anywhere in its output. An LLM producing a structured output with a CVSS score field can only hallucinate within the constraints of that field — and the resulting value can be automatically cross-checked against the NVD API. Structured outputs transform hallucination from an unbounded problem (any claim, anywhere, in any form) to a bounded problem (specific field values that can be validated against authoritative sources).

**Auditability requires traceability.** For each finding in the final risk register, it must be possible to trace back to: which agent produced it, from which data source, at what confidence level. Free-form prose does not support this tracing mechanically. Structured outputs with source citation fields and agent attribution fields make this tracing automatic rather than dependent on manual reconstruction.

**The human reviewer's cognitive load is reduced.** A Security Manager reviewing a structured risk register can evaluate specific field values against their knowledge and judgment. A Security Manager reviewing free-form narrative from multiple agents must first extract the structured information from the prose, then evaluate it — a significantly higher cognitive burden that increases the likelihood of review errors.

---

### Trade-offs Accepted

- **Expressiveness limitation:** Some nuances of risk assessment are difficult to capture in structured fields. The executive summary section exists precisely because board communication requires narrative that a schema cannot fully capture.
- **Prompt engineering complexity:** Getting LLMs to reliably produce valid structured output requires careful prompt design and may require retry logic when the model produces invalid JSON or misses required fields.
- **Schema maintenance:** As the risk assessment methodology evolves, schemas must be updated. Schema versioning and migration must be managed.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Injection detection | Schema validation at Orchestrator layer provides first-pass detection of injection-corrupted outputs |
| Hallucination bounding | Structured fields constrain hallucination scope and enable automated cross-validation against authoritative sources |
| Downstream reliability | Pipeline components receive predictable, parseable inputs; silent misinterpretation is eliminated |
| Audit traceability | Source attribution fields in structured outputs enable mechanical traceability from final report to source data |
| Review efficiency | Human reviewer evaluates specific field values rather than reconstructing structure from narrative |

**References:** OWASP LLM02 (Insecure Output Handling), OWASP LLM09 (Misinformation), NIST AI RMF MEASURE 2.5, MAARS Risk Register RR-005

---

## ADR-007 — Explicit Classification Labels at Every Data Boundary

### Decision

Every data flow in MAARS carries an explicit classification label (Public, Internal, Confidential, or Restricted) at every boundary where data crosses between components or between trust zones. Classification is re-evaluated at combination points — where data from multiple sources is merged — and escalates if the combination creates a higher-sensitivity output than either input.

---

**Option chosen:** Explicit classification labels on all data flows; automatic escalation at combination points; access controls enforced per classification level at every receiving component.

**Alternative considered:** Implicit trust — classify data at its source (CMDB data is Restricted, CVE data is Public) and apply controls at the source systems only, trusting that data handled within the system boundary maintains its original classification without re-evaluation.

---

### Context

Data classification is commonly applied at the point of origin: a database record is classified, an API is classified, a document is classified. Less commonly, classification is re-evaluated as data flows through a pipeline and combines with other data. The question for MAARS is whether source-level classification is sufficient, or whether flow-level classification is necessary.

---

### Rationale

**Combination creates sensitivity that neither input possesses alone.** CVE data from NVD is Public — it is freely available to anyone. CMDB asset data is Restricted. But the output of the Vulnerability Agent — a list of CVE IDs mapped to specific named assets — is more sensitive than either input. An attacker who has access to NVD data knows that CVE-2024-XXXX is a critical vulnerability. An attacker who also has the asset list knows that CVE-2024-XXXX affects the organization's core banking system. The correlation is what creates weaponizable intelligence.

If classification is only applied at the source (CVE data = Public; CMDB data = Restricted), the combined output might be handled with Public-level controls because the CVE component is Public. Explicit flow-level classification prevents this underprotection by requiring re-evaluation at every combination point.

**Zero-trust alignment requires not assuming trust based on origin.** Zero-trust architecture does not assume that data is safe because it came from a trusted source. Applying this principle to data flows means that every component receiving data must evaluate whether it is appropriate for that component to receive that data at that classification level — not whether the sender was a trusted component. Explicit classification labels enable this evaluation mechanically rather than requiring each component to reason about the provenance of every piece of data it receives.

**Classification drives the access control matrix.** The agent access matrix specifies which agents can access which data at which classification levels. This matrix is only enforceable if the classification of data is explicit and consistent as it flows through the pipeline. Implicit classification — where each component must infer the sensitivity of data from its content or origin — creates inconsistency and provides attackers with opportunities to exploit classification ambiguity.

**Audit and incident response require classification visibility.** When an incident investigation asks "did Restricted data leave the system boundary?", the answer requires knowing the classification of every data element that flowed through the pipeline. Explicit classification labels make this query answerable from the audit log. Implicit classification makes it unanswerable without reconstructing the classification of every data element from first principles.

---

### Trade-offs Accepted

- **Implementation overhead:** Every data flow must carry classification metadata, and every combination point must implement escalation logic. This adds complexity to the data model and the pipeline implementation.
- **Schema complexity:** Classification labels add fields to every inter-agent message format, increasing schema size and parsing complexity.
- **False precision:** Classification is ultimately a judgment. Labeling a data element as "Confidential" rather than "Internal" involves a decision that reasonable people might make differently. The classification scheme must be clearly defined and consistently applied.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Combination sensitivity detection | Classification escalation at merge points prevents underprotection of correlated data |
| Zero-trust alignment | Access controls are applied based on data classification, not assumed based on data origin |
| Access control enforceability | The agent access matrix can be mechanically enforced only if data classification is explicit |
| Incident response capability | Classification visibility in audit logs enables precise answers to "what data was exposed" questions |
| Regulatory compliance | Explicit classification supports data handling requirements under most regulatory frameworks |

**References:** NIST SP 800-53 AC-4 (Information Flow Enforcement), NIST SP 800-53 SC-28 (Protection of Information at Rest), Zero Trust Architecture (NIST SP 800-207), MAARS DFD Classification Legend

---

## ADR-008 — Agent-Specific Logging Over Centralised Log-Only

### Decision

MAARS implements two complementary logging tiers: agent-specific logs that capture the inputs, outputs, confidence scores, and tool call attempts of each individual agent; and a centralised audit log (append-only) that records pipeline-level events including task dispatch, approval actions, and report delivery. Both tiers are required — centralised logging alone is insufficient.

---

**Option chosen:** Agent-specific logs (per-agent, captures agent-level detail) plus centralised append-only audit log (pipeline-level, captures workflow decisions and approval events). Log scrubbing applied at agent output to prevent Restricted data from appearing in standard log tiers.

**Alternative considered:** Centralised logging only — all system events flow into a single logging infrastructure. Agent-level details are captured only to the extent that the centralised log receives them, without a dedicated per-agent logging layer.

---

### Context

Centralised logging is standard practice. Security operations teams are equipped to analyse centralised logs, SIEM tools are built to consume them, and retention policies are applied to them. The question is whether centralised logging alone provides the forensic capability that a security-critical AI pipeline requires, or whether agent-specific logging adds meaningful value.

---

### Rationale

**Forensic investigation of AI system incidents requires agent-level granularity.** When a risk report is found to contain a hallucinated finding, the investigation must answer: which agent produced the hallucination, what input data was it processing, what was the confidence score, was a flag raised at the time? A centralised log that records "Report Generator produced output at 14:32" does not answer these questions. Agent-specific logs that record the full input context, the output produced, the confidence score, and any schema validation failures for each agent invocation do answer them.

**Prompt injection attacks leave traces that are only visible at the agent level.** An injected agent output will show specific anomalies: an output that fails schema validation but is retried with the same input; a tool call attempt to an endpoint not in the agent's allowlist; a confidence score near zero on a finding that the agent reports with high specificity. These signals exist at the agent's local event stream. In a centralised-only model, these signals may never reach the centralised log, or may be aggregated in a way that loses the diagnostic detail.

**The centralised log provides pipeline integrity; agent logs provide analytical integrity.** These are different things. The centralised audit log answers: "did the pipeline proceed correctly? Was the approval gate enforced? When was the report delivered and to whom?" This is essential for accountability and compliance. Agent-specific logs answer: "did each agent process its inputs correctly? Were there anomalies in the outputs? Did any agent attempt actions outside its scope?" Both sets of questions are necessary for complete incident investigation.

**The append-only property of the centralised log is a specific security requirement.** The Scenario 2 attack narrative in the threat model demonstrates how an insider with configuration access can modify a workflow log to conceal a pipeline manipulation. An append-only centralised log makes this concealment impossible — entries can be added but not modified or deleted. Agent-specific logs need not be append-only (they may rotate and archive normally) because their primary purpose is diagnostic, not non-repudiation. The centralised audit log's primary purpose is non-repudiation, making append-only enforcement essential for that tier specifically.

**Log scrubbing prevents a secondary exfiltration pathway.** Agent-specific logs capture inputs and outputs that may include Restricted-classified data — asset names, CVE-to-asset correlations, vulnerability scores. Without log scrubbing, the logging infrastructure becomes a secondary data store containing the same Restricted data as the primary systems, but potentially with less stringent access controls. Log scrubbing at the agent output layer, before log write, ensures that standard log tiers contain only the metadata needed for diagnostics (timing, schema validation results, confidence scores, error codes) without capturing the sensitive data payloads.

---

### Trade-offs Accepted

- **Storage cost:** Two logging tiers require more storage than one. Agent-specific logs can be large if they capture full input/output payloads. Log scrubbing, retention policies, and tiered storage (hot/warm/cold) manage this cost.
- **Implementation complexity:** Implementing per-agent logging requires changes to every agent's output pipeline. Each agent must emit a structured log event in addition to its response payload.
- **Log management overhead:** Two separate logging infrastructures require two sets of retention policies, access controls, and monitoring configurations.
- **Alert fatigue risk:** More log sources produce more events, increasing the potential for alert fatigue if correlation rules are not carefully designed. Mitigation: agent-specific logs are primarily for forensic use; only a defined set of agent events are forwarded to the SIEM for real-time alerting.

---

### Security Benefit Gained

| Property | Description |
|----------|-------------|
| Forensic granularity | Agent-level input/output capture enables precise reconstruction of any finding's provenance |
| Injection signal detection | Agent-level anomalies (schema failures, out-of-scope tool call attempts, confidence score anomalies) are captured before they reach the centralised log |
| Non-repudiation | Append-only centralised audit log creates an immutable record of pipeline decisions and approval events |
| Exfiltration pathway elimination | Log scrubbing prevents logging infrastructure from becoming a secondary Restricted data store |
| Separation of concerns | Diagnostic logs (agent-specific) and accountability logs (centralised audit) serve different purposes and are governed differently |

**References:** NIST SP 800-53 AU-3 (Content of Audit Records), NIST SP 800-53 AU-9 (Protection of Audit Information), NIST SP 800-53 AU-10 (Non-Repudiation), OWASP LLM06 (Sensitive Information Disclosure), MAARS Threat Model Scenario 2, MAARS Risk Register RR-012

---

## Decision Dependency Map

The eight ADRs in this document are not independent — several decisions reinforce or depend on each other. Understanding these dependencies helps explain why reversing any single decision without considering its dependencies can undermine the security architecture.

```
ADR-001 (Read-only agents)
    └── enables → ADR-006 (Structured outputs are the only write surface)
    └── supports → ADR-008 (Agent logs have bounded scope because agents have bounded actions)

ADR-003 (Separate specialist agents)
    └── requires → ADR-005 (Separation necessitates a dedicated Orchestrator)
    └── enables → ADR-001 (Per-agent access control is only meaningful with separate agents)
    └── enables → ADR-008 (Agent-specific logging is meaningful because agents have distinct identities)

ADR-005 (Dedicated Orchestrator)
    └── enables → ADR-002 (Human gate has a natural enforcement point in the Orchestrator)
    └── enables → ADR-007 (Classification labels can be enforced at a single coordination point)

ADR-007 (Classification at every boundary)
    └── requires → ADR-003 (Boundaries only exist because agents are separate)
    └── enables → ADR-008 (Log classification tiers are meaningful because data classification is explicit)

ADR-002 (Human approval gate)
    └── depends on → ADR-006 (Structured outputs make the review task tractable for a human reviewer)
    └── depends on → ADR-005 (The gate is owned by the Orchestrator; without a dedicated Orchestrator, gate ownership is ambiguous)
```

**The implication of these dependencies:** If a future engineering team decides to simplify the architecture by merging agents (reversing ADR-003) or granting agents write access (reversing ADR-001), they should be aware that these changes do not affect only the decisions in question — they propagate through the dependency graph and may undermine the security properties of multiple other decisions.

---

## Change History

| Version | Date | Change | Author |
|---------|------|--------|--------|
| 1.0 | 2025 | Initial document — all eight ADRs | Security Engineering |

---

*This document should be reviewed and updated whenever a significant architectural change is proposed. Any change that affects a decision documented here requires a new ADR or an explicit revision of the affected ADR, with sign-off from the Security Engineering Lead and the system owner.*

*For questions or proposed changes, open an issue in the project repository.*
