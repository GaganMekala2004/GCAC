# GCAC / Prototype_GCAS — Agentic Vulnerability Remediation (Local POC)

[![.NET 9.0](https://img.shields.io/badge/.NET-9.0-purple.svg)](https://dotnet.microsoft.com/)
[![Tests](https://img.shields.io/badge/Tests-37%20Passed-brightgreen.svg)]()
[![Environment](https://img.shields.io/badge/Environment-Local%20VS%20Code-blue.svg)]()
[![Governance](https://img.shields.io/badge/Governance-Human%20Approval%20Gate-orange.svg)]()

**GCAC (Prototype_GCAS)** is a local, bounded, human-governed **Agentic AI Vulnerability Remediation Proof of Concept (POC)** designed to execute within the developer's approved Visual Studio Code environment using **GitHub Copilot agents**.

---

## 1. Target POC Architecture

The solution operates purely on local repository state:

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

### Core Architecture Principles
- **Local Execution**: Executes entirely within the developer's local VS Code workspace.
- **Local CSV Input**: Vulnerabilities are discovered from local CSV files in `vulnerability/*.csv`.
- **Single-Vulnerability Focus**: Processes **EXACTLY ONE** selected vulnerability per run (no backlog batching).
- **Shared Markdown State**: Single auditable report at `output/<sanitized_title>_<id>.md` acts as the persistent workflow state.
- **Controlled CSV Update**: Only the Documentation Agent updates the local CSV, modifying only the selected row and preserving all original columns and rows.
- **Mandatory Human Approval**: Human Approval is an explicit **GOVERNANCE GATE** (not an AI agent) that blocks any production code modifications until the developer authorizes the fix.
- **Zero External Dependencies**:
  - NO Model Context Protocol (MCP)
  - NO Microsoft Graph or SharePoint integrations
  - NO Azure service APIs or third-party APIs
  - NO external or SQLite database for workflow state
  - NO automated Pull Request creation, remote push, or auto-merge
  - NO automatic disposable workspace clone or branch creation

---

## 2. Logical Architecture vs Runtime Workflow

| Capability | Logical POC Architecture | Current Runtime Implementation |
| :--- | :--- | :--- |
| **Ingestion & Discovery** | CSV-based input discovery & parsing | `CsvVulnerabilityService` (`vulnerability/*.csv`) |
| **Classification & Mapping** | Dynamic vulnerability classification & routing | Handled internally by **Vulnerability Orchestrator** & **Code Analysis / RCA Agent** |
| **Root Cause Analysis** | AST-level vulnerability tracing | **Code Analysis / RCA Agent** (Read-Only) |
| **Baseline Testing** | Establish unfixed empirical baseline | **Unit Test Agent** (local `dotnet test` / `mvn test`) |
| **Human Review Gate** | Mandatory developer authorization gate | **Human Approval Gate** (**GOVERNANCE GATE**, not an AI agent) |
| **Code Remediation** | Minimal targeted secure fix | **Remediation Agent** (internal .NET, Dependency, Config, Java strategies) |
| **Regression Testing** | Verification of existing test suites | **Regression Agent** (distinguishes pre-existing from fix regressions) |
| **Independent Verification** | Skeptical multi-dimensional review | **Final Validation Agent** (PASS/FAIL/PARTIAL, 0-100 score) |
| **Reporting & CSV Sync** | Consolidated audit report & CSV update | **Documentation Agent** (Shared Markdown & single-row CSV update) |

---

## 3. Exact 16-Step Workflow Lifecycle

```
STEP 1: Developer invokes /remediate-vulnerability (or @vulnerability-orchestrator)
STEP 2: Vulnerability Orchestrator discovers local CSV files in vulnerability/*.csv
STEP 3: Developer selects ONE vulnerability category/type
STEP 4: Orchestrator displays matching findings
STEP 5: Developer selects EXACTLY ONE vulnerability finding
STEP 6: Initialize Shared Markdown report: output/<sanitized_title>_<vulnerability_id>.md
STEP 7: Code Analysis / RCA Agent traces data/call flow and determines root cause (Read-Only)
STEP 8: Unit Test Agent inspects test framework and drafts security tests
STEP 9: Unit Test Agent executes baseline tests on UNFIXED code -> Appends to Shared Markdown
STEP 10: STOP at Human Approval Gate -> Developer inspects RCA and baseline; decides APPROVE/REQUEST CHANGES/REJECT
STEP 11: After approval only: Remediation Agent applies minimal secure code fix
STEP 12: Remediation Agent executes post-fix verification tests -> Appends to Shared Markdown
STEP 13: Regression Agent executes full regression test suite -> Appends to Shared Markdown
STEP 14: Final Validation Agent independently verifies code, diff, and tests -> Assigns PASS/FAIL/PARTIAL and score (0-100)
STEP 15: Documentation Agent consolidates evidence and finalizes report in Shared Markdown
STEP 16: Documentation Agent updates the selected vulnerability row in the local CSV
```

---

## 4. Repository Structure

```
GCAC/
├── .github/
│   ├── agents/
│   │   ├── vulnerability-orchestrator.agent.md
│   │   ├── code-analysis-rca.agent.md
│   │   ├── unit-test.agent.md
│   │   ├── remediation.agent.md
│   │   ├── regression.agent.md
│   │   ├── final-validation.agent.md
│   │   └── documentation.agent.md
│   ├── prompts/
│   │   └── remediate-vulnerability.prompt.md
│   └── copilot-instructions.md
├── vulnerability/
│   └── vulnerabilities.csv
├── output/
│   └── <sanitized_vulnerability_title>_<vulnerability_id>.md
├── src/
│   ├── VulnerabilityRemediation.Domain/
│   ├── VulnerabilityRemediation.Repository/
│   └── VulnerabilityRemediation.Cli/
├── tests/
│   └── VulnerabilityRemediation.Tests/
├── config/
│   └── repositories.json
├── sample-repos/
│   ├── gcas-agentic-e2e-test-repo/
│   ├── payments-api/
│   ├── customer-service/
│   ├── inventory-manager/
│   ├── identity-provider/
│   └── storefront-api/
└── docs/
```

---

## 5. Quick Start Guide

### Prerequisites
- **.NET 9.0 SDK** (`dotnet --version`)
- **Git 2.30+** (`git --version`)
- **Visual Studio Code** with GitHub Copilot Chat

### Build and Test Solution
```powershell
# Restore dependencies and build local solution
dotnet build VulnerabilityRemediation.sln

# Run all 37 unit, CSV, markdown, and workflow tests
dotnet test VulnerabilityRemediation.sln
```

### Local CLI Helper Commands
```powershell
# List findings from local CSV
dotnet run --project src/VulnerabilityRemediation.Cli -- list

# List available vulnerability categories/types in CSV
dotnet run --project src/VulnerabilityRemediation.Cli -- categories

# Show complete details for a single vulnerability
dotnet run --project src/VulnerabilityRemediation.Cli -- show VUL-POC-001

# Run the 16-step remediation workflow (stops at Human Approval Gate)
dotnet run --project src/VulnerabilityRemediation.Cli -- execute VUL-POC-001

# Authorize and complete remediation
dotnet run --project src/VulnerabilityRemediation.Cli -- execute VUL-POC-001 --approve

# View the generated Shared Markdown report
dotnet run --project src/VulnerabilityRemediation.Cli -- report VUL-POC-001

# View local Git diff
dotnet run --project src/VulnerabilityRemediation.Cli -- diff VUL-POC-001
```

---

## 6. GitHub Copilot Workflow in VS Code

1. Open GitHub Copilot Chat in VS Code.
2. Run prompt:
   ```
   /remediate-vulnerability
   ```
   or invoke the orchestrator directly:
   ```
   @vulnerability-orchestrator Remediate VUL-POC-001
   ```
3. Select the vulnerability category and specific finding.
4. Review the generated Root Cause Analysis and Baseline Test results.
5. Grant explicit human approval (`APPROVE`) at the Human Approval Gate.
6. The agents apply the targeted fix, run regression tests, conduct independent validation, finalize the Shared Markdown report in `output/`, and update the CSV record.

---

## 7. Documentation Index

- [Architecture Specification](docs/ARCHITECTURE.md)
- [Agent Workflow & Roles](docs/AGENT_WORKFLOW.md)
- [Human-in-the-Loop Governance Gate](docs/HUMAN_REVIEW.md)
- [Security Guardrails](docs/SECURITY_GUARDRAILS.md)
- [Acceptance Criteria Verification Matrix](docs/ACCEPTANCE_CRITERIA.md)
- [Environment Setup & Installation](docs/SETUP.md)
- [Demo Runbook](docs/DEMO_RUNBOOK.md)
