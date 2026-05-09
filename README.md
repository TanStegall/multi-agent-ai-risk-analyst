# 🛡️ Multi-Agent AI Risk Analyst System (MAARS)

> A fully documented architecture for a production-ready multi-agent AI system that performs automated security risk assessments — with comprehensive security controls, human oversight, and executive reporting.

---

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)
![NIST AI RMF](https://img.shields.io/badge/Framework-NIST%20AI%20RMF-blue.svg)
![OWASP LLM Top 10](https://img.shields.io/badge/Framework-OWASP%20LLM%20Top%2010-red.svg)
![MITRE ATLAS](https://img.shields.io/badge/Framework-MITRE%20ATLAS-purple.svg)

---

## 📋 Table of Contents

1. [System Overview](#-system-overview)
2. [Repository Structure](#-repository-structure)
3. [Deliverables Checklist](#-deliverables-checklist)
4. [Frameworks Used and Why](#-frameworks-used-and-why)
5. [Human Oversight Design](#-human-oversight-design)
6. [Security Design Principles](#-security-design-principles)
7. [How to Review This Documentation](#-how-to-review-this-documentation)
8. [Author and Course Context](#-author-and-course-context)
9. [License](#-license)

---

## 🏗️ System Overview

MAARS is a multi-agent AI pipeline that automates enterprise security risk assessments. Six coordinated AI agents ingest data from internal systems and external security databases, correlate findings across frameworks, and produce a structured risk report — which a human security manager must review and approve before it reaches any stakeholder.

The system was designed as a portfolio capstone demonstrating end-to-end AI security engineering: threat modeling an AI system, applying least-privilege access controls to AI agents, mapping risks across multiple frameworks, and building human oversight into the architecture by design rather than as an afterthought.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   ORCHESTRATOR AGENT                     │
│        Coordinates workflow · delegates to specialists   │
│        Human Gate: final report approval required        │
└────────────────────┬─────────────────────────────────────┘
        ┌────────────┼─────────────┐
┌───────▼──────┐ ┌───▼──────────┐ ┌▼─────────────────┐
│ ASSET        │ │ VULNERABILITY │ │ THREAT INTEL     │
│ CONTEXT      │ │ AGENT         │ │ AGENT            │
│              │ │               │ │                  │
│ Reads: CMDB  │ │ Reads: CVE DB │ │ Reads: TI feeds  │
│ Classifies:  │ │ CVSS scores   │ │ Maps: ATLAS TTPs │
│ Criticality  │ │               │ │                  │
│ Access: READ │ │ Access: READ  │ │ Access: READ     │
└──────────────┘ └───────────────┘ └──────────────────┘
                        │
             ┌──────────┴──────────┐
  ┌──────────▼──────┐  ┌───────────▼────────┐
  │ CONTROL MAPPING │  │ REPORT GENERATOR   │
  │ AGENT           │  │ AGENT              │
  │ Maps: NIST RMF  │  │ Outputs: Risk Reg, │
  │ OWASP LLM gaps  │  │ Exec Summary, CSV  │
  │ Access: READ    │  │ Access: WRITE rpt  │
  └─────────────────┘  └────────────────────┘
                                 │
                       ┌─────────▼──────────┐
                       │   HUMAN APPROVAL   │
                       │       GATE         │
                       │  Security Manager  │
                       │  Reviews & Signs   │
                       └────────────────────┘
```

See [`architecture/`](./architecture/) for the full interactive architecture diagram and [`data-flow-diagram/`](./data-flow-diagram/) for DFD Level 1 with data classification labels at every boundary.

### System Components

| Agent | Role | Access Level | Data Sources |
|-------|------|-------------|-------------|
| Orchestrator | Coordinates workflow; dispatches tasks; manages approval gate | READ + WRITE (workflow state only) | Agent results, audit log |
| Asset Context | Classifies asset criticality from CMDB | READ | CMDB (scoped fields only) |
| Vulnerability | Fetches and scores CVEs against in-scope assets | READ | NVD / CVE DB, CVSS API |
| Threat Intel | Maps adversary techniques to MITRE ATLAS | READ | Approved TI feeds, ATLAS DB |
| Control Mapping | Identifies NIST RMF and OWASP LLM control gaps | READ | NIST docs, OWASP LLM Top 10 |
| Report Generator | Compiles risk register, executive summary, CSV | READ + WRITE (report staging only) | All agent outputs, report templates |

---

## 📁 Repository Structure

```
maars/
│
├── README.md                        # This file — project overview and navigation guide
│
├── architecture/
│   ├── architecture-diagram.svg     # Full system architecture with trust boundaries,
│   │                                # agent roles, data flows, and access levels
│   └── architecture-notes.md        # Design rationale for structural decisions
│
├── data-flow-diagram/
│   ├── dfd-level1-ingestion.svg     # DFD Layer 1: external sources → specialist agents
│   │                                # → Orchestrator, with classification labels
│   └── dfd-level1-synthesis.svg     # DFD Layer 2: Orchestrator → Report Generator
│                                    # → Human Gate → delivery, with classification labels
│
├── agent-access-matrix.md           # Complete access control matrix for all 6 agents:
│                                    # data sources, access levels (READ/WRITE/NONE),
│                                    # permitted actions, explicit denials, trust zones,
│                                    # and least-privilege rationale per agent
│
├── risk-register.md                 # Risk register with 12 risks mapped across
│                                    # OWASP LLM Top 10, MITRE ATLAS, and NIST RMF.
│                                    # Includes likelihood, impact, risk scores,
│                                    # current controls, and recommended mitigations
│
├── control-gap-analysis.md          # Full gap analysis across all three frameworks:
│                                    # control status (Exists/Partial/Missing),
│                                    # gap descriptions, severity ratings, and a
│                                    # prioritized 30/60/90-day remediation roadmap
│
├── threat-model.md                  # MITRE ATLAS threat model: 4 threat actor profiles,
│                                    # 10 ATLAS technique mappings with risk scores,
│                                    # 2 realistic attack scenario narratives (TTP chains),
│                                    # and detection opportunity analysis
│
├── exec-summary.md                  # 1–2 page executive summary for CISO and board:
│                                    # system purpose, overall risk rating (HIGH),
│                                    # top findings in plain language, control highlights,
│                                    # critical gaps, and recommended actions with effort
│
├── security-design-decisions.md     # Architecture Decision Records (ADRs) documenting
│                                    # "Why X over Y" for 8 major security design choices:
│                                    # human gate design, agent separation, framework
│                                    # selection, access controls, and output integrity
│
└── LICENSE                          # MIT License
```

---

## ✅ Deliverables Checklist

### Core Deliverables

- [x] **Architecture diagram** — full system architecture with agents, data flows, trust boundaries, and access level annotations
- [x] **Agent access matrix** — complete READ/WRITE/NONE matrix for all 6 agents with least-privilege rationale
- [x] **Data flow diagram** — DFD Level 1 with data classification labels (Public / Internal / Confidential / Restricted) at every boundary
- [x] **Risk register** — 12 risks mapped across OWASP LLM Top 10, MITRE ATLAS, and NIST RMF with likelihood/impact scoring
- [x] **Control gap analysis** — 55 controls assessed across all three frameworks; 30/60/90-day remediation roadmap
- [x] **Executive summary** — 1–2 page board-level summary with overall HIGH risk rating and prioritized actions
- [x] **Threat model** — MITRE ATLAS threat model with 4 actor profiles, 10 TTP mappings, 2 attack narratives, detection analysis
- [x] **GitHub repository** — this repository, with README and all documentation
- [x] **Security design decisions** — Architecture Decision Records for 8 major security design choices

### Framework Coverage

- [x] OWASP LLM Top 10 (2025) — all 10 categories assessed
- [x] MITRE ATLAS v4.5 — 10 techniques mapped; 4 threat actor profiles
- [x] NIST AI RMF 1.0 — all 4 functions assessed (Govern, Map, Measure, Manage)
- [x] NIST SP 800-53 Rev 5 — control families referenced in risk register
- [x] NIST SP 800-37 Rev 2 — RMF process applied to lifecycle assessment

---

## 📚 Frameworks Used and Why

### OWASP LLM Top 10 (2025)

**What it is:** The Open Worldwide Application Security Project's ranked list of the most critical security risks specific to Large Language Model applications, published and maintained by the security community.

**Why it was selected:** MAARS is fundamentally an LLM-based system. The OWASP LLM Top 10 provides the most directly applicable, practitioner-focused catalog of LLM-specific risks — covering prompt injection, insecure output handling, training data poisoning, excessive agency, and more. It translates directly to the attack surface of each agent in the pipeline. Using a well-known, publicly available framework also makes the risk register legible to any security professional without requiring specialist knowledge.

**How it is applied:** Every risk in the risk register is mapped to an OWASP LLM category. The control gap analysis assesses all 10 categories in sequence. The executive summary references OWASP findings in plain-language form for non-technical audiences.

---

### NIST AI Risk Management Framework (AI RMF 1.0)

**What it is:** The U.S. National Institute of Standards and Technology's framework for managing risks in AI systems across four functions: Govern, Map, Measure, and Manage. It is the leading organizational governance framework for responsible AI deployment.

**Why it was selected:** OWASP covers technical risks; NIST AI RMF covers the organizational and governance risks that determine whether technical controls are actually implemented and sustained over time. A system can have well-designed technical controls that are never tested, never updated, and never backed by formal accountability — NIST AI RMF identifies those governance gaps. It is also the framework most likely to be required by regulators and enterprise customers, making fluency with it a professional necessity.

**How it is applied:** The control gap analysis assesses MAARS against all four RMF functions with individual sub-function gap assessments. The 30/60/90-day remediation roadmap maps directly to RMF Manage function requirements. The agent access matrix reflects RMF Map function documentation requirements.

---

### MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) v4.5

**What it is:** MITRE's knowledge base of adversary tactics, techniques, and procedures (TTPs) targeting AI and machine learning systems, structured as a companion to MITRE ATT&CK. It documents real-world attacks against AI systems observed by security researchers.

**Why it was selected:** Neither OWASP nor NIST AI RMF provides adversary-focused threat modeling. ATLAS fills this gap by providing a TTP taxonomy that mirrors how actual threat actors attack AI systems — enabling threat modeling that goes beyond "what could go wrong" to "how would a specific adversary actually do this." The attack scenario narratives in the threat model are only possible because ATLAS provides the TTP vocabulary to describe chained adversarial actions realistically.

**How it is applied:** The threat model maps 10 ATLAS techniques with likelihood/impact scoring. Every risk in the risk register includes an ATLAS technique ID. The two attack narratives chain multiple ATLAS TTPs into realistic operational scenarios. The detection opportunity analysis identifies where each ATLAS TTP could be detected in the pipeline.

---

### Why All Three Frameworks Together

No single framework provides complete coverage:

| Dimension | OWASP LLM Top 10 | NIST AI RMF | MITRE ATLAS |
|-----------|:---:|:---:|:---:|
| LLM-specific technical risks | ✅ Primary | Partial | Partial |
| Organizational governance | ❌ | ✅ Primary | ❌ |
| Adversary TTP modeling | Partial | ❌ | ✅ Primary |
| Risk quantification | Partial | ✅ | Partial |
| Detection engineering | ❌ | Partial | ✅ |
| Regulatory / compliance alignment | Partial | ✅ | Partial |

Using all three creates a defense-in-depth coverage model: OWASP ensures the LLM components are hardened, NIST AI RMF ensures the organization can sustain that hardening over time, and ATLAS ensures the threat model reflects how real adversaries would actually attack the system.

---

## 👤 Human Oversight Design

### The Approval Gate

MAARS is designed around a fundamental principle: **AI systems that inform high-stakes decisions must have a human in the loop before those decisions are acted upon.**

The human approval gate is the most important security control in the system. Every risk report — regardless of how well the AI agents performed — must be reviewed and explicitly approved by a designated Security Manager before it reaches any stakeholder. This is not a courtesy review; it is an architectural requirement.

### Why the Gate Exists

AI agents in MAARS process real vulnerability data, real asset inventories, and real threat intelligence. An error in any agent's output — whether caused by a bug, a hallucination, or a malicious manipulation — could result in:

- A critical vulnerability being classified as low priority and left unpatched
- A non-existent vulnerability being escalated, wasting remediation resources
- Sensitive asset data being included in a report distributed to unauthorized recipients
- An adversary-manipulated assessment being presented to leadership as accurate

The human approval gate provides a checkpoint where a trained security professional can catch these errors before they have consequences.

### What the Security Manager Reviews

| Review Item | What the Reviewer Checks |
|------------|------------------------|
| Risk score plausibility | Do the likelihood/impact scores reflect the actual environment? Are any scores surprisingly high or low? |
| Source citations | Does each finding reference a real CVE ID, a real ATLAS technique, a real NIST control? |
| Asset scope accuracy | Are the assessed assets the ones that were in scope for this assessment cycle? |
| Report integrity hash | Does the hash displayed match the report content? (Verifies the report has not been tampered with between generation and review) |
| Overall coherence | Does the risk landscape described match the reviewer's knowledge of current threats? |

### Current Implementation vs. Target State

The approval gate is currently implemented as a **workflow step** — the pipeline requires a human action before proceeding. The target state, identified as the highest-priority remediation in the control gap analysis, is a **cryptographic signing requirement**: the report cannot be decrypted or delivered without the Security Manager's private key signature, making bypass technically impossible rather than merely procedurally disallowed.

This distinction — between a control that relies on correct process execution and a control that makes incorrect execution technically impossible — is a core principle of security engineering and is documented in detail in [`security-design-decisions.md`](./security-design-decisions.md).

---

## 🔐 Security Design Principles

The following principles guided every architectural decision in MAARS. Full rationale for each is documented in [`security-design-decisions.md`](./security-design-decisions.md).

### 1. Least Privilege by Default

Every agent has access only to the specific data and actions required for its assigned task. The Vulnerability Agent cannot access the CMDB. The Threat Intel Agent cannot read the risk register draft. The Orchestrator cannot write to any data source other than the workflow state log. Access is scoped at the credential level — each agent has a distinct service account with a distinct permission set — not just at the prompt/instruction level.

### 2. Read-Only Where Possible

Five of the six agents are read-only. The only agent with write access is the Report Generator, and its write scope is limited to the report staging area. This design means that even if an agent is compromised, the attacker cannot use that agent to modify source systems, corrupt input data, or tamper with other agents' outputs directly.

### 3. Human Oversight is Non-Negotiable

The system is designed so that the human approval gate cannot be bypassed by normal pipeline operation. Reports do not flow to stakeholders; they flow to a human reviewer, and only to stakeholders after the reviewer acts. This is not a configurable option — it is a structural property of the architecture.

### 4. Classification at Every Boundary

Every data flow in the system carries an explicit classification label (Public, Internal, Confidential, Restricted). Classification escalates as data is combined — CMDB asset data (Restricted) combined with vulnerability data (Public) produces a correlated risk assessment (Restricted), reflecting the higher sensitivity of the combination. This drives access control and handling decisions throughout the pipeline.

### 5. Defense in Depth for AI-Specific Threats

The system applies multiple overlapping controls for the highest-risk AI attack vectors. Prompt injection, for example, is defended against at three levels: system prompt refusal instructions (soft control), output schema validation (structural control), and a secondary LLM judge (independent control). No single control is relied upon exclusively for any critical protection.

### 6. Auditability and Non-Repudiation

Every agent action, every approval decision, and every report delivery is logged to an append-only audit store. Reports are cryptographically hashed at generation time. The combination means that for any report, it is possible to prove: what data went in, which agents processed it, what outputs were produced, who approved it, and when. This supports incident investigation, regulatory compliance, and accountability.

### 7. Fail-Safe Defaults

When the pipeline encounters an anomaly — an agent output that fails schema validation, a confidence score below threshold, an unexpected tool call attempt — the default behavior is to halt and alert, not to proceed with degraded output. The system is designed to surface uncertainty rather than paper over it.

### 8. Separation of Duties

The agent that produces a report (Report Generator) is architecturally separate from the agent that coordinates the workflow (Orchestrator), which is separate from the human who approves the report (Security Manager). No single agent or individual can both produce and approve a risk assessment. This mirrors a core internal controls principle applied to AI system design.

---

## 📖 How to Review This Documentation

This repository documents a security architecture, not a deployed codebase. The documents are designed to be read in a specific order depending on your role and purpose.

### Recommended Reading Order

#### For a Security Assessment Review

Start with the executive summary for the overall risk picture, then move to the risk register for specific findings, then the control gap analysis for remediation priorities. The threat model provides the adversary perspective if you want to understand attack scenarios.

```
exec-summary.md  →  risk-register.md  →  control-gap-analysis.md  →  threat-model.md
```

#### For an Architecture Review

Start with the architecture diagram for the structural picture, then the data flow diagram to understand how data moves and is classified, then the agent access matrix to evaluate access controls, then the security design decisions document for the rationale behind key choices.

```
architecture/  →  data-flow-diagram/  →  agent-access-matrix.md  →  security-design-decisions.md
```

#### For a Framework Compliance Review

The control gap analysis is structured by framework (OWASP LLM, NIST AI RMF, MITRE ATLAS) and is the primary compliance reference document. The risk register provides the detailed finding-level mappings.

```
control-gap-analysis.md  →  risk-register.md
```

### Document Relationships

All documents in this repository are internally consistent — risk IDs, control references, and ATLAS technique IDs are the same across all documents. If you find a discrepancy, please open an issue.

| If you want to know... | Read... |
|----------------------|---------|
| What the system does and why | `README.md` → System Overview |
| What the overall risk level is | `exec-summary.md` |
| What specific risks exist and their scores | `risk-register.md` |
| What controls are missing and how to fix them | `control-gap-analysis.md` |
| How an attacker would actually compromise the system | `threat-model.md` → Attack Scenarios |
| Who can access what | `agent-access-matrix.md` |
| Why the architecture was designed this way | `security-design-decisions.md` |
| How data flows and is classified | `data-flow-diagram/` |
| How agents are connected | `architecture/` |

### Terminology Reference

| Term | Plain-language meaning |
|------|----------------------|
| Agent | An AI component with a specific job — like the "Vulnerability Agent" which finds and scores security flaws |
| Orchestrator | The AI component that manages the other agents and coordinates the workflow |
| CMDB | Configuration Management Database — the organization's inventory of all IT systems |
| TTP | Tactic, Technique, and Procedure — how attackers operate |
| ATLAS | MITRE's catalog of attack techniques specifically targeting AI systems |
| Least privilege | Giving each component only the minimum access it needs to do its job — nothing more |
| Human approval gate | The mandatory step where a real person reviews and signs off on the AI's output before it is distributed |
| Risk register | A structured list of identified risks with scores, controls, and mitigations |

---

## 👩‍💻 Author and Course Context

This repository is the capstone deliverable for a 22-module AI Security Engineering course. It represents the portfolio centrepiece of the curriculum — demonstrating end-to-end competency in AI security architecture across threat modeling, access control design, multi-framework risk assessment, and executive communication.

### Course Modules Applied

This deliverable draws on skills and knowledge from across the full curriculum, including:

- **AI system architecture** — multi-agent design patterns, trust boundaries, data flow design
- **Threat modeling** — MITRE ATLAS, adversary profiling, TTP chaining, attack narrative development
- **Risk assessment** — OWASP LLM Top 10, NIST AI RMF, likelihood/impact scoring, risk register construction
- **Access control design** — least privilege principles, agent access matrices, separation of duties
- **Human oversight engineering** — approval gate design, cryptographic integrity controls, accountability mechanisms
- **Security documentation** — executive communication, ADR writing, compliance mapping, gap analysis

### Portfolio Context

The documents in this repository are designed to demonstrate security engineering competency at a production level — the kind of documentation that would be expected for a real enterprise AI system undergoing a security review. The risk register, threat model, control gap analysis, and security design decisions documents are all written to the standard that would be expected in a professional security engagement.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**Multi-Agent AI Risk Analyst System**

*Designed with security by design. Human oversight by architecture. Transparency by documentation.*

</div>
