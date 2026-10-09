# ARCHITECTURE SPECIFICATION (TARGET POC)

## 1. Executive Summary

The **Agentic Vulnerability Remediation Proof of Concept (POC)** is a controlled, file-based, local system operating inside Visual Studio Code using **GitHub Copilot agents**.

It enables developer-guided, auditable remediation of security vulnerabilities discovered from local CSV files, establishing empirical test baselines before requiring explicit human approval to apply minimal, targeted code fixes.

---

## 2. Target POC Architectural Flow

```
Local CSV (vulnerability/*.csv)
      ↓
GitHub Copilot inside VS Code
      ↓
Bounded Agent Workflow (7 Agents + 1 Governance Gate)
      ↓
Local Repository
      ↓
Shared Vulnerability Markdown (output/<sanitized_title>_<vulnerability_id>.md)
      ↓
Controlled Selected-Row CSV Update
```

---

## 3. Logical Architecture vs Current Runtime Workflow

The original logical architecture defines key conceptual capabilities. The runtime POC implements these capabilities cleanly without unnecessary external components:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       LOGICAL POC CAPABILITIES                             │
├──────────────────────────┬──────────────────────────────────────────────────┤
│ Logical Capability       │ Runtime Implementation Mapping                   │
├──────────────────────────┼──────────────────────────────────────────────────┤
│ Classification & Mapping │ Internal capability: Vulnerability Orchestrator  │
│                          │ & Code Analysis / RCA Agent (RouteDerivation)    │
│ Code Analysis & RCA      │ Code Analysis / RCA Agent (Read-Only)            │
│ Baseline Unit Testing    │ Unit Test Agent (Local CLI dotnet/mvn test)      │
│ Human Approval           │ Human Approval Gate (GOVERNANCE GATE, not AI)    │
│ Remediation              │ Remediation Agent (DotNet, Dependency, Config)   │
│ Regression Testing       │ Regression Agent (Local test suite verification) │
│ Final Validation         │ Final Validation Agent (Independent Audit)       │
│ Documentation & Sync     │ Documentation Agent (Shared Markdown & CSV Sync) │
└──────────────────────────┴──────────────────────────────────────────────────┘
```

---

## 4. Bounded Agent Inventory & Governance Gate

| # | Agent / Gate | Role & Scope | Modifies Code? | Modifies CSV? |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Vulnerability Orchestrator** | Discovers CSVs, prompts category & single finding selection, initializes Shared Markdown, coordinates pipeline. | ❌ NO | ❌ NO |
| 2 | **Code Analysis / RCA Agent** | Analyzes code, traces data & call flow, identifies root cause and security impact, proposes fix. | ❌ NO | ❌ NO |
| 3 | **Unit Test Agent** | Authors security tests, runs baseline against UNFIXED code, records baseline evidence. | ❌ NO | ❌ NO |
| — | **Human Approval Gate** | **MANDATORY GOVERNANCE GATE (Not an AI Agent)**. Developer inspects RCA and baseline; authorizes or rejects fix. | — | — |
| 4 | **Remediation Agent** | Applies minimal secure code fix addressing root cause using internal strategies (.NET, Dependency, Config, Java). Runs post-fix tests. | ✅ YES | ❌ NO |
| 5 | **Regression Agent** | Runs full build and existing test suite; distinguishes pre-existing failures from regressions. | ❌ NO | ❌ NO |
| 6 | **Final Validation Agent** | Skeptical independent verification; checks diff, tests, secrets, bypasses; assigns PASS/FAIL/PARTIAL and score (0-100). | ❌ NO | ❌ NO |
| 7 | **Documentation Agent** | Consolidates report in Shared Markdown; **SOLE WRITER** for updating the selected row in local CSV. | ❌ NO | ✅ YES (Selected row only) |

---

## 5. Shared State & Evidence Model

Instead of multi-file packages (`changes.patch`, `agent-execution-trace.log`, `remediation-report.md`), the POC maintains **ONE** persistent Shared Markdown artifact per run:

`output/<sanitized_vulnerability_title>_<vulnerability_id>.md`

### Section Lifecycle
1. `# Vulnerability Remediation Report — <ID>`
2. `## Vulnerability Information` (Metadata from CSV)
3. `## Code Analysis / RCA Agent` (Dataflow, root cause, proposed fix)
4. `## Unit Test Agent` (Baseline test command, exit code, outputs)
5. `## Human Approval Gate` (Governance decision, reviewer name, notes)
6. `## Remediation Agent` (Fix rationale, Git diff, post-fix tests)
7. `## Regression Agent` (Regression command, results, analysis)
8. `## Final Validation Agent` (Status: PASS/FAIL/PARTIAL, Confidence: 0-100, verification checks)
9. `## Documentation Agent` (Final status, CSV update record)
10. `## Final Status`
11. `## Agent Execution Summary` (Execution trace and agent matrix)

---

## 6. Strict Environmental Guardrails

- **NO MCP**: No Model Context Protocol servers or tools.
- **NO SharePoint / Graph / Azure**: No external network or cloud platform calls.
- **NO External Database**: No SQLite persistence; state resides in CSV + Markdown + Git.
- **NO Automatic PR / Push**: No remote Git pushes or Pull Request creation; changes remain on approved local branch.
- **NO Batching**: Exactly one vulnerability processed per remediation run.
