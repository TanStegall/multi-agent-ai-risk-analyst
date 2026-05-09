# Agent Access Matrix
## Multi-Agent AI Risk Analyst System (MAARS)

---

| Field | Detail |
|-------|--------|
| Document ID | AAM-MAARS-001 |
| Version | 1.0 |
| Classification | Internal |
| Prepared by | Security Engineering |

---

## Access Level Definitions

| Level | Symbol | Definition |
|-------|--------|-----------|
| Read | READ | Query and retrieve data only. No modification, deletion, or creation of records. |
| Write | WRITE | Create or modify data within a strictly scoped staging area. Cannot write to source systems. |
| None | NONE | No access of any kind. Explicitly denied at the infrastructure layer. |

## Trust Zone Definitions

| Zone | Definition |
|------|-----------|
| Restricted | Highest sensitivity. Elevated audit logging. Authenticated access only. Contains data that would be weaponizable if disclosed (CMDB asset inventory, approved reports). |
| Internal | Standard internal trust. mTLS required for inter-agent communication. Not accessible from outside the system boundary. |
| External access | Agent makes outbound calls to data sources outside the system boundary (NVD, TI feeds). Tightest egress controls applied. |

---

## Matrix

### Orchestrator Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | Restricted |
| **Access level** | READ + WRITE (workflow state and task dispatch only) |
| **Human approval required** | Yes — required before final report delivery |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| Agent result payloads | READ | Receives structured outputs from all specialist agents |
| Workflow state log | WRITE | Records pipeline progress, task dispatch events, and completion status |
| Audit log | WRITE | Appends pipeline-level events; append-only, cannot modify existing entries |

**Permitted actions:**
- Dispatch tasks to specialist agents
- Receive and validate agent output schemas
- Route validated results to Report Generator
- Write workflow state and audit events
- Halt pipeline on anomaly detection or schema validation failure
- Verify human approval status before authorising report delivery

**Explicitly denied:**
- Direct access to CMDB, CVE DB, TI feeds, or NIST/OWASP documents
- Modifying any source data or agent outputs after receipt
- Delivering reports without a confirmed human approval signature
- Spawning agents or sub-processes not in its registered tool allowlist
- External network calls outside the internal system boundary

**Least privilege rationale:**
The Orchestrator coordinates the entire pipeline but touches no source data directly. Its WRITE scope is limited to workflow state — not to any data system. This ensures that a compromised Orchestrator cannot exfiltrate asset data or corrupt source records; it can only disrupt pipeline coordination, which is detectable and recoverable.

---

### Asset Context Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | Restricted |
| **Access level** | READ |
| **Human approval required** | No |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| CMDB | READ | Scoped to criticality classification fields only: asset name, tier, business owner. Network topology, credentials, and configuration details are out of scope. |
| Asset classification schema | READ | Internal reference document defining criticality tiers |

**Permitted actions:**
- Query CMDB for assets within the defined assessment scope
- Classify each asset as High, Medium, or Low criticality
- Map assets to business owners and system tiers
- Return structured asset inventory payload to Orchestrator

**Explicitly denied:**
- Writing to or modifying any CMDB record
- Querying assets outside the defined assessment scope
- Bulk export of the full CMDB asset inventory
- Accessing network topology, configuration details, or credentials
- Retaining asset data between assessment sessions
- Passing raw CMDB data to any agent other than the Orchestrator

**Least privilege rationale:**
The Asset Context Agent handles the most sensitive data in the system — the organisation's complete asset inventory. Its CMDB access is scoped to only the fields needed for criticality classification. Even if compromised via prompt injection, it cannot export full network topology or system configurations. Context windows are cleared after each session, preventing accumulation of a profilable asset database.

---

### Vulnerability Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | External access |
| **Access level** | READ |
| **Human approval required** | No |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| NVD / CVE DB | READ | Public National Vulnerability Database. Read-only queries for specific CVE IDs. |
| CVSS scoring API | READ | Retrieves base scores for CVE IDs. Cross-validation against agent-generated scores. |
| Asset list (from Orchestrator) | READ | Receives in-scope asset identifiers from the Orchestrator — does not query CMDB directly |

**Permitted actions:**
- Fetch CVE records for assets within the defined assessment scope
- Retrieve and validate CVSS base scores from NVD
- Correlate CVE IDs to affected assets using the asset list provided by the Orchestrator
- Flag CVEs with unverifiable or low-confidence scores for human review
- Return scored vulnerability list to Orchestrator in validated schema format

**Explicitly denied:**
- Writing to CVE DB, NVD, or any external data source
- Accepting CVE records without a traceable, citable CVE ID
- Direct access to the CMDB or internal asset systems
- Caching raw CVE payloads beyond the scope of the current task
- Overriding CVSS scores without flagging the discrepancy
- Querying vulnerability data for assets outside the defined assessment scope

**Least privilege rationale:**
The Vulnerability Agent receives only the asset identifiers it needs from the Orchestrator — it never queries the CMDB directly. This means it holds the asset list only for the duration of its task and only in the form needed to match CVEs. It never holds the full CMDB record (owner, network details, configuration) that would make a disclosure significantly more damaging.

---

### Threat Intel Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | External access |
| **Access level** | READ |
| **Human approval required** | No |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| TI feeds (approved allowlist) | READ | Commercial and open-source feeds. Only feeds on the approved provider allowlist are accepted. |
| MITRE ATLAS DB | READ | Public ATLAS technique catalog for TTP attribution and validation |
| IOC repositories | READ | Indicator of Compromise repositories for cross-validation |

**Permitted actions:**
- Ingest threat intelligence from feeds on the approved provider allowlist only
- Map adversary tactics, techniques, and procedures to MITRE ATLAS technique IDs
- Cross-validate TTP attributions across a minimum of two independent feed sources
- Flag single-source TTPs as unverified and hold for human review
- Return validated TTP mapping payload to Orchestrator

**Explicitly denied:**
- Accessing TI feed providers not on the approved allowlist
- Accepting TTP attributions from a single feed source without cross-validation
- Writing back to any TI feed provider or IOC repository
- Accessing CMDB, CVE DB, or any internal asset system
- Storing raw feed content persistently beyond the current session
- Accepting novel, unrecognised ATLAS technique IDs without human review flag

**Least privilege rationale:**
The Threat Intel Agent is the most exposed to external, attacker-influenced content — TI feeds are written by third parties and could be compromised. The approved provider allowlist enforced at the infrastructure layer (not just the system prompt) prevents feed substitution attacks. The cross-validation requirement means no single compromised feed can corrupt the TTP output undetected.

---

### Control Mapping Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | Internal |
| **Access level** | READ |
| **Human approval required** | No |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| NIST RMF control catalog | READ | NIST SP 800-53 Rev 5 machine-readable control catalog |
| OWASP LLM Top 10 (2025) | READ | Reference document for LLM-specific control gap identification |
| Draft risk register | READ | Receives the draft risk register from the Orchestrator for annotation |

**Permitted actions:**
- Map identified risks to NIST RMF control families (AC, AU, SI, SC, etc.)
- Identify gaps against OWASP LLM Top 10 categories
- Annotate the draft risk register with control references and gap descriptions
- Validate NIST control IDs against the machine-readable SP 800-53 catalog
- Return annotated gap analysis payload to Orchestrator

**Explicitly denied:**
- Writing directly to the risk register (annotations returned as a payload, not written in place)
- Accessing CMDB, CVE DB, TI feeds, or any external data source
- Overriding risk scores set by other agents
- External network calls of any kind
- Modifying NIST or OWASP reference documents
- Accepting control IDs not present in the official NIST SP 800-53 Rev 5 catalog

**Least privilege rationale:**
The Control Mapping Agent reads the draft risk register but cannot write to it. This enforces a separation of concerns: the agents that produce risk findings (Vulnerability, Threat Intel) are structurally separate from the agent that assesses control coverage. No single agent can both identify a risk and declare it mitigated — a key separation of duties control.

---

### Report Generator Agent

| Field | Detail |
|-------|--------|
| **Trust zone** | Internal |
| **Access level** | READ + WRITE (report staging area only) |
| **Human approval required** | Yes — report cannot be delivered without Security Manager approval |

**Data sources accessible:**

| Source | Access | Notes |
|--------|--------|-------|
| All agent output payloads | READ | Receives compiled results from the Orchestrator |
| Report staging area | WRITE | Sole write destination. Scoped exclusively to this staging area. |
| Report templates | READ | Internal formatting templates for risk register, executive summary, and CSV export |

**Permitted actions:**
- Compile risk register from all agent output payloads
- Generate executive summary (markdown/PDF format)
- Export CSV risk data to the report staging area
- Compute SHA-256 hash of the draft report immediately upon creation
- Record hash in the append-only audit log
- Submit report to the human approval queue

**Explicitly denied:**
- Delivering any report without a confirmed Security Manager approval signature
- Accessing CMDB, CVE DB, TI feeds, or any source data system directly
- Modifying a report after its hash has been recorded in the audit log
- Sending reports to external recipients
- Overwriting previously approved reports
- Writing to any system other than the report staging area

**Least privilege rationale:**
The Report Generator is the only agent with meaningful write access, and that access is scoped exclusively to the report staging area — not to any source system. The cryptographic hash requirement at generation time, combined with the human approval gate, means the Report Generator cannot complete its function autonomously: technical delivery requires a human signature. Even a fully compromised Report Generator cannot distribute a report without the Security Manager's private key.

---

## Summary Table

| Agent | Trust Zone | Read Access | Write Access | Human Approval | External Calls |
|-------|-----------|-------------|-------------|---------------|----------------|
| Orchestrator | Restricted | Agent payloads, workflow state | Workflow state, audit log | Required (final report) | No |
| Asset Context | Restricted | CMDB (scoped) | None | Not required | No |
| Vulnerability | External access | NVD/CVE DB, CVSS API | None | Not required | Yes (NVD, CVSS) |
| Threat Intel | External access | TI feeds (allowlisted), ATLAS DB | None | Not required | Yes (feeds, ATLAS) |
| Control Mapping | Internal | NIST catalog, OWASP docs, draft risk register | None | Not required | No |
| Report Generator | Internal | All agent outputs, report templates | Report staging area only | Required (before delivery) | No |

---

## Principle of Least Privilege — System-Level Summary

Five of six agents are read-only. The only write access in the system flows through two narrow channels: the Orchestrator writes workflow state (not data), and the Report Generator writes to a scoped staging area (not source systems). This design means that even a worst-case compromise of all six agents simultaneously cannot result in modification of any source system — CMDB, CVE DB, TI feeds, or NIST reference documents remain intact regardless of agent behavior.

The write surface of the entire system is:

```
Orchestrator    →  workflow state log (internal)
Report Generator →  report staging area (internal, Restricted)
```

Everything else is read-only by architecture, not by instruction.

---

*For the full security rationale behind these access decisions, see `security-design-decisions.md` ADR-001.*
*For the risk register entries associated with access control failures, see `risk-register.md` RR-003, RR-006.*
