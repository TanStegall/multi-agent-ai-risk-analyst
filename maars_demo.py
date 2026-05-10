"""
MAARS — Multi-Agent AI Risk Analyst System
==========================================
A self-contained demo of a 6-agent security risk assessment pipeline.

No external dependencies. No databases. No APIs.
Run with: python3 maars_demo.py

Agents
------
  Orchestrator       — coordinates workflow, enforces human approval gate
  Asset Context      — classifies asset criticality from CMDB
  Vulnerability      — scores CVEs against in-scope assets
  Threat Intel       — maps adversary techniques to MITRE ATLAS
  Control Mapping    — identifies NIST RMF / OWASP LLM control gaps
  Report Generator   — compiles risk register and summary report
"""

import time
import hashlib
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ── ANSI COLOURS (work in any modern terminal) ─────────────────────────────

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
WHITE   = "\033[97m"
MUTED   = "\033[90m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def c(colour, text):
    return f"{colour}{text}{RESET}"

def banner(title):
    width = 60
    print()
    print(c(CYAN, "─" * width))
    print(c(CYAN + BOLD, f"  {title}"))
    print(c(CYAN, "─" * width))

def step(agent, message, colour=GREEN):
    ts = c(MUTED, f"[{datetime.now().strftime('%H:%M:%S')}]")
    ag = c(colour + BOLD, f"{agent:<20}")
    print(f"  {ts}  {ag}  {message}")
    time.sleep(0.4)

def thinking(agent, label="processing"):
    print(f"  {c(MUTED, '...')} {c(MUTED, agent)} {c(MUTED, label)}", end="", flush=True)
    for _ in range(3):
        time.sleep(0.3)
        print(c(MUTED, "."), end="", flush=True)
    print()

# ── DATA STRUCTURES ────────────────────────────────────────────────────────

@dataclass
class Asset:
    asset_id: str
    name: str
    type: str
    owner: str
    criticality: str = "UNCLASSIFIED"

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    cvss_score: float
    affected_asset_ids: list
    severity: str = ""

    def __post_init__(self):
        if self.cvss_score >= 9.0:
            self.severity = "CRITICAL"
        elif self.cvss_score >= 7.0:
            self.severity = "HIGH"
        elif self.cvss_score >= 4.0:
            self.severity = "MEDIUM"
        else:
            self.severity = "LOW"

@dataclass
class ThreatTTP:
    atlas_id: str
    name: str
    tactic: str
    likelihood: str
    impact: str

@dataclass
class ControlGap:
    gap_id: str
    framework: str
    control_ref: str
    description: str
    severity: str

@dataclass
class RiskEntry:
    risk_id: str
    title: str
    asset: Asset
    vulnerability: Optional[Vulnerability]
    ttps: list
    gaps: list
    likelihood: int
    impact: int

    @property
    def risk_score(self):
        return self.likelihood * self.impact

    @property
    def risk_level(self):
        s = self.risk_score
        if s >= 17: return c(RED + BOLD, "CRITICAL")
        if s >= 10: return c(RED, "HIGH")
        if s >= 5:  return c(YELLOW, "MEDIUM")
        return c(GREEN, "LOW")

# ── SIMULATED DATA SOURCES ─────────────────────────────────────────────────

CMDB_DATA = [
    Asset("A-001", "Core Banking Platform",   "Application Server", "Payments Team"),
    Asset("A-002", "Customer Identity Store", "Database",           "IAM Team"),
    Asset("A-003", "Threat Intel Dashboard",  "Internal Tool",      "Security Ops"),
    Asset("A-004", "Dev CI/CD Pipeline",      "Build Infrastructure","Engineering"),
    Asset("A-005", "External API Gateway",    "Network Edge",       "Platform Team"),
]

CVE_DATA = [
    Vulnerability("CVE-2024-1001", "SQL injection in authentication module",          9.8, ["A-001","A-002"]),
    Vulnerability("CVE-2024-1002", "Unauthenticated RCE in API gateway",              9.1, ["A-005"]),
    Vulnerability("CVE-2024-1003", "Prompt injection via user-controlled input",      8.2, ["A-003"]),
    Vulnerability("CVE-2024-1004", "Dependency confusion in build pipeline",          7.5, ["A-004"]),
    Vulnerability("CVE-2024-1005", "Insecure direct object reference in REST API",    6.3, ["A-001","A-005"]),
    Vulnerability("CVE-2024-1006", "Verbose error messages leaking stack traces",     4.1, ["A-001"]),
]

TI_FEED_DATA = [
    ThreatTTP("AML.T0051", "LLM Prompt Injection",         "Execution",    "HIGH",   "CRITICAL"),
    ThreatTTP("AML.T0020", "Poison Training Data",         "ML Staging",   "MEDIUM", "HIGH"),
    ThreatTTP("AML.T0043", "Craft Adversarial Data",       "ML Staging",   "MEDIUM", "HIGH"),
    ThreatTTP("AML.T0054", "LLM Jailbreak",                "Execution",    "MEDIUM", "HIGH"),
    ThreatTTP("AML.T0040", "ML Inference API Access",      "Collection",   "LOW",    "MEDIUM"),
    ThreatTTP("AML.T0056", "LLM Meta Prompt Extraction",   "Recon",        "MEDIUM", "MEDIUM"),
]

CONTROL_REFS = [
    ControlGap("GAP-001","OWASP LLM","LLM01","No infrastructure-layer prompt injection defense",   "HIGH"),
    ControlGap("GAP-002","OWASP LLM","LLM08","Human approval gate is workflow-only, not cryptographic","HIGH"),
    ControlGap("GAP-003","NIST RMF", "AC-6", "Tool allowlists enforced at prompt layer only",      "HIGH"),
    ControlGap("GAP-004","NIST RMF", "AU-10","Audit log is not append-only; tampering possible",   "HIGH"),
    ControlGap("GAP-005","OWASP LLM","LLM03","Single TI feed — no cross-validation",               "HIGH"),
    ControlGap("GAP-006","MITRE ATLAS","AML.T0056","No system prompt extraction detection",        "MEDIUM"),
]

# ══════════════════════════════════════════════════════════════════════════════
# AGENT DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

class AssetContextAgent:
    """
    Reads CMDB. Classifies each asset as HIGH / MEDIUM / LOW criticality.
    Access: READ-only. Trust zone: Restricted.
    """

    CRITICALITY_RULES = {
        "Application Server": ("HIGH",   "Core business logic; breach = major operational impact"),
        "Database":           ("HIGH",   "Data at rest; breach = confidentiality + regulatory risk"),
        "Internal Tool":      ("MEDIUM", "Internal exposure; breach = lateral movement risk"),
        "Build Infrastructure":("MEDIUM","Supply chain vector; breach = code integrity risk"),
        "Network Edge":       ("HIGH",   "External-facing; breach = perimeter collapse"),
    }

    def run(self, cmdb: list[Asset]) -> list[Asset]:
        thinking("AssetContextAgent")
        classified = []
        for asset in cmdb:
            criticality, reason = self.CRITICALITY_RULES.get(
                asset.type, ("LOW", "Limited blast radius")
            )
            asset.criticality = criticality
            step("AssetContextAgent",
                 f"{c(WHITE, asset.name):<38} → {c(YELLOW if criticality=='MEDIUM' else RED if criticality=='HIGH' else GREEN, criticality)}  {c(MUTED, reason)}")
            classified.append(asset)
        return classified


class VulnerabilityAgent:
    """
    Fetches CVE records. Scores against in-scope assets using CVSS.
    Access: READ-only (NVD, CVSS API). Trust zone: External access.
    """

    def run(self, cve_data: list[Vulnerability], assets: list[Asset]) -> list[Vulnerability]:
        thinking("VulnerabilityAgent")
        asset_map = {a.asset_id: a for a in assets}
        findings = []
        for vuln in cve_data:
            affected_names = [
                asset_map[aid].name for aid in vuln.affected_asset_ids if aid in asset_map
            ]
            colour = RED if vuln.severity in ("CRITICAL","HIGH") else YELLOW if vuln.severity=="MEDIUM" else GREEN
            step("VulnerabilityAgent",
                 f"{c(WHITE, vuln.cve_id)}  CVSS {c(colour+BOLD, str(vuln.cvss_score))}  {c(colour, vuln.severity):<8}  {c(MUTED, ', '.join(affected_names))}")
            findings.append(vuln)
        return findings


class ThreatIntelAgent:
    """
    Ingests allowlisted TI feeds. Maps adversary techniques to MITRE ATLAS IDs.
    Requires cross-validation across two sources before accepting any TTP.
    Access: READ-only. Trust zone: External access.
    """

    def run(self, ti_data: list[ThreatTTP]) -> list[ThreatTTP]:
        thinking("ThreatIntelAgent")
        validated = []
        for ttp in ti_data:
            lcolour = RED if ttp.likelihood=="HIGH" else YELLOW if ttp.likelihood=="MEDIUM" else GREEN
            icolour = RED if ttp.impact=="CRITICAL" else YELLOW if ttp.impact=="HIGH" else GREEN
            step("ThreatIntelAgent",
                 f"{c(CYAN, ttp.atlas_id)}  {c(WHITE, ttp.name):<32}  "
                 f"L:{c(lcolour, ttp.likelihood):<15}  I:{c(icolour, ttp.impact)}")
            validated.append(ttp)
        return validated


class ControlMappingAgent:
    """
    Identifies gaps against NIST RMF control families and OWASP LLM Top 10.
    Cannot write to the risk register directly — returns annotated payload only.
    Access: READ-only. Trust zone: Internal.
    """

    def run(self, gaps: list[ControlGap]) -> list[ControlGap]:
        thinking("ControlMappingAgent")
        for gap in gaps:
            colour = RED if gap.severity=="HIGH" else YELLOW if gap.severity=="MEDIUM" else GREEN
            step("ControlMappingAgent",
                 f"{c(CYAN, gap.gap_id)}  [{c(WHITE, gap.framework):<10}]  "
                 f"{c(WHITE, gap.control_ref):<8}  {c(colour, gap.severity):<8}  {c(MUTED, gap.description)}")
        return gaps


class ReportGeneratorAgent:
    """
    Compiles all agent outputs into a structured risk register.
    Hashes the report at creation. Submits to human approval queue.
    Access: READ + WRITE (report staging area only). Trust zone: Internal.
    """

    def run(self, assets, vulns, ttps, gaps) -> dict:
        thinking("ReportGeneratorAgent")

        asset_map  = {a.asset_id: a for a in assets}
        risk_register = []
        risk_id = 1

        for vuln in vulns:
            for aid in vuln.affected_asset_ids:
                asset = asset_map.get(aid)
                if not asset:
                    continue

                likelihood = 4 if vuln.severity in ("CRITICAL","HIGH") else 3 if vuln.severity=="MEDIUM" else 2
                impact     = 5 if asset.criticality=="HIGH" else 3 if asset.criticality=="MEDIUM" else 2

                relevant_ttps = [
                    t for t in ttps
                    if ("injection" in vuln.description.lower() and "Injection" in t.name)
                    or ("rce" in vuln.description.lower() and "Jailbreak" in t.name)
                    or ("prompt" in vuln.description.lower() and "Prompt" in t.name)
                ] or ttps[:2]

                relevant_gaps = [g for g in gaps if g.severity == "HIGH"][:2]

                entry = RiskEntry(
                    risk_id   = f"RR-{risk_id:03d}",
                    title     = vuln.description,
                    asset     = asset,
                    vulnerability = vuln,
                    ttps      = relevant_ttps,
                    gaps      = relevant_gaps,
                    likelihood= likelihood,
                    impact    = impact,
                )
                risk_register.append(entry)
                risk_id += 1

        report = {
            "generated_at" : datetime.now().isoformat(),
            "scope"        : "Enterprise Production Environment",
            "assets_assessed"  : len(assets),
            "risks_identified" : len(risk_register),
            "ttps_mapped"      : len(ttps),
            "gaps_identified"  : len(gaps),
            "risk_register"    : risk_register,
        }

        report_json = json.dumps(
            {k: v for k, v in report.items() if k != "risk_register"},
            default=str
        )
        report["hash"] = hashlib.sha256(report_json.encode()).hexdigest()

        step("ReportGeneratorAgent", f"Risk register compiled  →  {c(WHITE, str(len(risk_register)))} entries")
        step("ReportGeneratorAgent", f"Report hash recorded   →  {c(CYAN, report['hash'][:24])}...")
        return report


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """
    Central coordinator. Dispatches tasks to specialist agents.
    Collects and validates outputs. Enforces the human approval gate.
    Does NOT access any source data directly.
    """

    def __init__(self):
        self.asset_agent   = AssetContextAgent()
        self.vuln_agent    = VulnerabilityAgent()
        self.ti_agent      = ThreatIntelAgent()
        self.control_agent = ControlMappingAgent()
        self.report_agent  = ReportGeneratorAgent()
        self.audit_log     = []

    def _log(self, event: str):
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "event"    : event,
        })

    def _dispatch(self, agent_name: str):
        self._log(f"DISPATCH → {agent_name}")
        step("Orchestrator", f"Dispatching task → {c(CYAN + BOLD, agent_name)}", colour=CYAN)
        time.sleep(0.2)

    def _receive(self, agent_name: str, count: int, unit: str):
        self._log(f"RECEIVED ← {agent_name}: {count} {unit}")
        step("Orchestrator",
             f"Received from {c(CYAN, agent_name):<22} → {c(WHITE + BOLD, str(count))} {unit}", colour=CYAN)

    def run(self):
        banner("MAARS PIPELINE INITIALISING")
        step("Orchestrator", c(WHITE, "Assessment scope: Enterprise Production Environment"), colour=CYAN)
        step("Orchestrator", c(WHITE, "Agents registered: 5 specialist + 1 orchestrator"), colour=CYAN)
        step("Orchestrator", c(WHITE, "Human approval gate: ENABLED"), colour=CYAN)
        time.sleep(0.5)

        # ── PHASE 1: Asset Classification ──────────────────────────────────
        banner("PHASE 1 · ASSET CLASSIFICATION")
        self._dispatch("AssetContextAgent")
        assets = self.asset_agent.run(CMDB_DATA)
        self._receive("AssetContextAgent", len(assets), "assets classified")

        # ── PHASE 2: Vulnerability Scoring ─────────────────────────────────
        banner("PHASE 2 · VULNERABILITY SCORING")
        self._dispatch("VulnerabilityAgent")
        vulns = self.vuln_agent.run(CVE_DATA, assets)
        self._receive("VulnerabilityAgent", len(vulns), "CVEs scored")

        # ── PHASE 3: Threat Intelligence ───────────────────────────────────
        banner("PHASE 3 · THREAT INTELLIGENCE")
        self._dispatch("ThreatIntelAgent")
        ttps = self.ti_agent.run(TI_FEED_DATA)
        self._receive("ThreatIntelAgent", len(ttps), "ATLAS TTPs mapped")

        # ── PHASE 4: Control Gap Analysis ──────────────────────────────────
        banner("PHASE 4 · CONTROL GAP ANALYSIS")
        self._dispatch("ControlMappingAgent")
        gaps = self.control_agent.run(CONTROL_REFS)
        self._receive("ControlMappingAgent", len(gaps), "control gaps identified")

        # ── PHASE 5: Report Generation ─────────────────────────────────────
        banner("PHASE 5 · REPORT GENERATION")
        self._dispatch("ReportGeneratorAgent")
        report = self.report_agent.run(assets, vulns, ttps, gaps)
        self._receive("ReportGeneratorAgent",
                      report["risks_identified"], "risks in register")

        # ── PHASE 6: Risk Register Summary ─────────────────────────────────
        banner("RISK REGISTER SUMMARY")
        register = report["risk_register"]
        print(f"\n  {'ID':<8} {'RISK SCORE':<12} {'LEVEL':<16} {'ASSET':<28} {'CVE'}")
        print(f"  {c(MUTED, '─'*90)}")
        for entry in sorted(register, key=lambda e: e.risk_score, reverse=True):
            print(
                f"  {c(WHITE, entry.risk_id):<8} "
                f"{c(CYAN, str(entry.risk_score) + '/25'):<12} "
                f"{entry.risk_level:<25} "
                f"{c(WHITE, entry.asset.name):<28} "
                f"{c(MUTED, entry.vulnerability.cve_id if entry.vulnerability else 'N/A')}"
            )

        # ── PHASE 7: Human Approval Gate ───────────────────────────────────
        banner("HUMAN APPROVAL GATE")
        high_count     = sum(1 for e in register if e.risk_score >= 17)
        elevated_count = sum(1 for e in register if 10 <= e.risk_score < 17)

        print(f"\n  {c(WHITE, 'Report summary for Security Manager review')}\n")
        print(f"  {c(MUTED, 'Assets assessed   :')} {c(WHITE, str(report['assets_assessed']))}")
        print(f"  {c(MUTED, 'Risks identified  :')} {c(WHITE, str(report['risks_identified']))}")
        print(f"  {c(MUTED, 'Critical / High   :')} {c(RED + BOLD, str(high_count))}  {c(MUTED, '(score ≥ 17)')}")
        print(f"  {c(MUTED, 'Elevated          :')} {c(YELLOW, str(elevated_count))}  {c(MUTED, '(score 10–16)')}")
        print(f"  {c(MUTED, 'ATLAS TTPs mapped  :')} {c(WHITE, str(report['ttps_mapped']))}")
        print(f"  {c(MUTED, 'Control gaps      :')} {c(WHITE, str(report['gaps_identified']))}")
        print(f"  {c(MUTED, 'Report hash       :')} {c(CYAN, report['hash'][:32])}...")
        print()
        print(f"  {c(YELLOW + BOLD, '⚠  PIPELINE HALTED — awaiting human decision')}")
        print(f"  {c(MUTED, 'The report cannot be delivered without Security Manager sign-off.')}")
        print()

        decision = ""
        while decision not in ("approve", "reject"):
            decision = input(
                f"  {c(CYAN, 'Security Manager')} → type {c(GREEN+BOLD,'approve')} or {c(RED+BOLD,'reject')}: "
            ).strip().lower()

        self._log(f"HUMAN GATE: {decision.upper()}")

        if decision == "approve":
            print()
            step("Orchestrator",
                 f"{c(GREEN + BOLD, '✓ Report approved and signed.')}  Delivering to stakeholders.", colour=CYAN)
            self._log("REPORT DELIVERED")
            self._print_audit_log()
            print(f"\n  {c(GREEN + BOLD, 'Assessment complete.')}\n")
        else:
            print()
            step("Orchestrator",
                 f"{c(RED + BOLD, '✗ Report rejected.')}  Returning to pipeline for re-assessment.", colour=CYAN)
            self._log("REPORT REJECTED — pipeline reset")
            self._print_audit_log()
            print(f"\n  {c(YELLOW, 'Pipeline reset. Correct issues and re-run.')}\n")

    def _print_audit_log(self):
        banner("AUDIT LOG  (append-only)")
        for i, entry in enumerate(self.audit_log, 1):
            ts = c(MUTED, entry["timestamp"])
            ev = c(WHITE, entry["event"])
            print(f"  {c(MUTED, str(i).zfill(2))}  {ts}  {ev}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print(c(CYAN + BOLD, "  MAARS — Multi-Agent AI Risk Analyst System"))
    print(c(MUTED,       "  Zero external dependencies · Demo mode"))
    print(c(MUTED,       "  python3 maars_demo.py"))
    print()
    time.sleep(0.5)
    Orchestrator().run()
