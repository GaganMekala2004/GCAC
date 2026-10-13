# Prototype_GCAS — Agentic AI Vulnerability Remediation Platform

[![.NET 9.0](https://img.shields.io/badge/.NET-9.0-purple.svg)](https://dotnet.microsoft.com/)
[![Tests](https://img.shields.io/badge/Tests-41%20Passed-brightgreen.svg)]()
[![MCP Server](https://img.shields.io/badge/MCP-Protocol%202024--11--05-blue.svg)](https://modelcontextprotocol.io/)
[![Security Guardrails](https://img.shields.io/badge/Guardrails-HITL%20Enforced-orange.svg)]()

**Prototype_GCAS** is an enterprise-grade, deterministic, agentic AI platform designed to autonomously ingest, validate, classify, remediate, test, and audit security vulnerabilities across enterprise software repositories with strict **Human-in-the-Loop (HITL)** approval gates.

---

## Architecture Overview

```
                                  ┌─────────────────────────────────────────┐
                                  │      AI Model & Agent Orchestration     │
                                  │  • GitHub Copilot Chat (VS Code)        │
                                  │  • Antigravity Agent & Skills           │
                                  └────────────────────┬────────────────────┘
                                                       │ JSON-RPC 2.0 (STDIO)
                                                       ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                           VulnerabilityDataMcp (MCP Server)                               │
│  • Context Retrieval  • Workspace Preparation  • Remediation Engine  • Security Audit     │
└──────────────────────────────────────────────┬────────────────────────────────────────────┘
                                               │
┌──────────────────────────────────────────────┴────────────────────────────────────────────┐
│                              Core GCAS Services & Agents                                  │
├──────────────────────────┬─────────────────────────────┬──────────────────────────────────┤
│ Ingestion & Validation   │ Repository Workspace Mgr    │ Deterministic Fix Agents         │
│ • ExcelIngestionService  │ • RepositoryRegistry        │ • DotNetFixAgent                 │
│ • DomainValidator        │ • SampleRepositoriesSeeder  │ • JavaFixAgent                   │
│ • VulnerabilityDbContext │ • Git Workspace Preparation │ • DependencyFixAgent             │
│ • SQLite Database Store  │   (workspaces/<VULN_ID>/)   │ • LargeRefactorAgent             │
├──────────────────────────┼─────────────────────────────┼──────────────────────────────────┤
│ Testing & Validation     │ Independent Security Audit  │ Evidence & Publishing            │
│ • TestValidationAgent    │ • SecurityReviewAgent       │ • EvidenceGeneratorService       │
│ • dotnet test / mvn test │ • AST & Diff Inspection     │ • PrPublisherService             │
│ • Real Execution Logs    │ • Secret / Bypass Detection │ • AWAITING_HUMAN_REVIEW (Gate)   │
└──────────────────────────┴─────────────────────────────┴──────────────────────────────────┘
```

---

## Key Features

1. **Deterministic Repository Resolution**:
   - Maps `ApplicationNumber` to source repositories via `config/repositories.json` without guessing or hallucinating paths.
   - Auto-seeds baseline repositories (`sample-repos/`) on `main` branch with clean git state.

2. **Autonomous End-to-End Execution**:
   - Retrieves vulnerability context, creates isolated branch `remediation/<vuln-id>`, inspects AST, applies precise fix, executes real test suites (`dotnet test`, `mvn test`), and conducts security audit.

3. **Dynamic Batching Engine**:
   - Groups findings by application and blast radius:
     - **Large Batches**: Identical 3PP dependency and package upgrades across applications.
     - **Medium Batches**: Related controller/service-level vulnerabilities.
     - **Small/Individual**: Complex source code refactors and architectural changes.

4. **Independent Security Review & Audit Evidence**:
   - Performs independent security review on git diffs before requesting human review.
   - Generates full evidence package in `remediation-output/<VULN_ID>/`:
     - `changes.patch` (Git unified diff)
     - `remediation-report.md` (Markdown audit report)
     - `agent-execution-trace.log` (Full execution trace)

5. **Immutable Human-in-the-Loop Review Gate**:
   - Automated remediation strictly stops at status `AWAITING_HUMAN_REVIEW`.
   - Never auto-pushes to remote git repositories or opens Pull Requests without explicit human confirmation (`approve-pr` / `isApproved: true`).

---

## Supported Applications & Repositories

| Application | Name | Technology | Repository Path | Target Vulnerabilities |
| :--- | :--- | :--- | :--- | :--- |
| **`APP-E2E-001`** | GCAS Agentic E2E Test API | .NET 9 | `sample-repos/gcas-agentic-e2e-test-repo` | `GCAS-E2E-001` (SQLi), `GCAS-E2E-002` (Cmd Injection), `GCAS-E2E-003` (Path Traversal), `GCAS-E2E-004` (Reflected XSS), `GCAS-E2E-005` (Hardcoded Secret), `GCAS-E2E-006` (Newtonsoft.Json) |
| **`APP-1001`** | Payments API | .NET 9 | `sample-repos/payments-api` | `VUL-POC-001` (SQLi), `VUL-POC-005` (DES Refactor), `VUL-POC-006` (Cmd Injection), `VUL-POC-007` (API Secret) |
| **`APP-1002`** | Customer Service | Java Spring | `sample-repos/customer-service` | `VUL-POC-002` (Auth Bypass), `VUL-POC-008` (Spring Boot 3.1.2), `VUL-POC-009` (Path Traversal) |
| **`APP-1003`** | Inventory Manager | .NET 9 | `sample-repos/inventory-manager` | `VUL-POC-003` (Newtonsoft.Json), `VUL-POC-010` (Encodings.Web) |
| **`APP-1004`** | Identity Provider | Infra / VM | `sample-repos/identity-provider` | `VUL-POC-004` (Ivanti Server Buffer Overflow — No Code Fix) |
| **`APP-1005`** | Storefront Web API | .NET 9 | `sample-repos/storefront-api` | `VUL-POC-011` (Reflected XSS) |

---

## Quick Start Guide

### Prerequisites
- **.NET 9.0 SDK** (`dotnet --version`)
- **Git 2.30+** (`git --version`)
- **Visual Studio Code** or **Antigravity IDE**

### Build and Run Tests
```powershell
# Restore dependencies and build solution
dotnet build

# Run all 41 unit and integration tests
dotnet test
```

---

## Control CLI Commands Reference

The CLI is located in `src/VulnerabilityRemediation.Cli`:

```powershell
# List all ingested vulnerabilities
dotnet run --project src/VulnerabilityRemediation.Cli -- list

# Show details of a specific vulnerability
dotnet run --project src/VulnerabilityRemediation.Cli -- show VUL-POC-002

# Validate database integrity against domain business rules
dotnet run --project src/VulnerabilityRemediation.Cli -- validate

# Generate dynamic remediation batch plan
dotnet run --project src/VulnerabilityRemediation.Cli -- batch-plan

# Prepare workspace & local remediation branch
dotnet run --project src/VulnerabilityRemediation.Cli -- prepare VUL-POC-002

# Execute autonomous remediation, real tests, security audit, and evidence generation
dotnet run --project src/VulnerabilityRemediation.Cli -- execute VUL-POC-002

# Execute remediation for an entire batch
dotnet run --project src/VulnerabilityRemediation.Cli -- batch-execute BATCH-APP-1003-DEP-02

# View git diff patch evidence
dotnet run --project src/VulnerabilityRemediation.Cli -- diff VUL-POC-002

# View markdown audit report
dotnet run --project src/VulnerabilityRemediation.Cli -- evidence VUL-POC-002

# Check lifecycle and human review status
dotnet run --project src/VulnerabilityRemediation.Cli -- status VUL-POC-002

# Approve remediation and publish Pull Request (HITL Gate)
dotnet run --project src/VulnerabilityRemediation.Cli -- publish VUL-POC-002 --approve
dotnet run --project src/VulnerabilityRemediation.Cli -- approve-pr VUL-POC-002
```

---

## Model Context Protocol (MCP) Server

The MCP server is located in `mcp/VulnerabilityDataMcp` and communicates over STDIO JSON-RPC 2.0.

### Configuration
- **VS Code**: `.vscode/mcp.json`
- **Antigravity**: `.agents/mcp_config.json`

### Key MCP Tools
- `get_vulnerability_context(vulnerabilityId)`: Returns structured context, repository mapping, and route.
- `prepare_workspace(vulnerabilityId)`: Clones repository to workspace and checks out local remediation branch.
- `execute_remediation(vulnerabilityId)`: Executes complete fix, test runner, security audit, and evidence generation.
- `run_validation_tests(vulnerabilityId)`: Runs real build and test suites and returns execution metrics.
- `run_security_review(vulnerabilityId)`: Conducts AST security audit on git diff.
- `generate_evidence(vulnerabilityId)`: Collects patch, report, and execution trace.
- `get_vulnerability_diff(vulnerabilityId)`: Retrieves unified git diff.
- `get_evidence_report(vulnerabilityId)`: Retrieves markdown audit report.
- `get_batch_plan()`: Generates dynamic batch plan grouped by application and blast radius.
- `approve_pr(vulnerabilityId)`: Publishes approved branch and opens GitHub Pull Request upon explicit human approval.

---

## AI Agent Integrations

### GitHub Copilot Chat (VS Code)
1. Open GitHub Copilot Chat in VS Code.
2. Enter:
   ```
   remediate VUL-POC-002
   ```
   or with custom agent:
   ```
   @remediation-orchestrator Remediate GCAS-E2E-005
   ```
3. Copilot autonomously executes the remediation pipeline and provides the complete finalized report with git diff, test results, security audit rating, and stops at `AWAITING_HUMAN_REVIEW`.

### Antigravity AI
1. Skill defined in `.agents/skills/gcas-remediation/SKILL.md`.
2. Antigravity connects to `vulnerability-data` MCP server via `.agents/mcp_config.json`.
3. Enter:
   ```
   remediate VUL-POC-002
   ```

---

## Documentation Index

- [Architecture Specification](docs/ARCHITECTURE.md)
- [Model Context Protocol (MCP) Guide](docs/MCP.md)
- [Agent Workflow & Delegation Matrix](docs/AGENT_WORKFLOW.md)
- [Demonstration & Real-Time Runbook](docs/DEMO_RUNBOOK.md)
- [Human-in-the-Loop Review Gate](docs/HUMAN_REVIEW.md)
- [Security Guardrails](docs/SECURITY_GUARDRAILS.md)
- [Acceptance Criteria Verification Matrix](docs/ACCEPTANCE_CRITERIA.md)
- [Environment Setup & Installation](docs/SETUP.md)
- [Model Routing Strategy](docs/MODEL_ROUTING.md)
