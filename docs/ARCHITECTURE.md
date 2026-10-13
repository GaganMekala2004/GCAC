# ARCHITECTURE SPECIFICATION

## Executive Overview

The **Agentic AI Vulnerability Remediation Platform (Prototype_GCAS)** is an enterprise-grade, auditable, modular security remediation system. It bridges structured vulnerability reporting with AI agent runtimes (Visual Studio Code GitHub Copilot and Antigravity IDE) while enforcing absolute developer oversight via deterministic software boundaries.

---

## 1. Architectural Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                      DETERMINISTIC SOFTWARE LAYER                      │
│                                                                        │
│  - Excel Ingestion (ClosedXML + Untrusted Input Sanitizer)             │
│  - Domain Normalization & Business Rules (DomainValidator)             │
│  - SQLite Database Store (data/vulnerabilities.db)                     │
│  - App -> Repo Registry (config/repositories.json)                     │
│  - Sample Repositories Seeder (SampleRepositoriesSeeder.cs)            │
│  - Repository Workspace Manager (workspaces/<VULN_ID>/repository)      │
│  - Deterministic Fix Agents (DotNetFix, JavaFix, DependencyFix, etc.) │
│  - Build & Test Runner (TestValidationAgent: dotnet test / mvn test)   │
│  - Independent AST Security Reviewer (SecurityReviewAgent)             │
│  - Dynamic Batching Engine (VulnerabilityBatchingService)              │
│  - Vulnerability Data MCP Server (mcp/VulnerabilityDataMcp)            │
│  - Remediation Audit Evidence Engine (remediation-output/<VULN_ID>/)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼ (.vscode/mcp.json & .agents/mcp_config.json)
┌────────────────────────────────────────────────────────────────────────┐
│                     AI AGENTIC ORCHESTRATION LAYER                     │
│                                                                        │
│  - GitHub Copilot Chat Agent (@remediation-orchestrator)               │
│  - Antigravity Remediation Skill (.agents/skills/gcas-remediation/)    │
│  - Copilot Instructions & Strict Behavioral Guardrails                 │
│  - Autonomous Context Retrieval, Workspace Prep & Fix Execution        │
│  - Direct In-Chat Review Delivery with Unified Git Diff                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     HUMAN CONTROL / DEVELOPER GATE                     │
│                                                                        │
│  - Status = AWAITING_HUMAN_REVIEW (STOP)                               │
│  - Developer Audits Git Diff, Test Logs & Evidence Report              │
│  - Explicit Human Authorization Required:                              │
│    "APPROVE PR <VULNERABILITY_ID>" or "publish <id> --approve"         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     GITHUB INTEGRATION & PR PUBLISH                    │
│                                                                        │
│  - PR Publisher Service (PrPublisherService.cs)                        │
│  - Git Push Remote Branch -> Create GitHub Pull Request                │
│  - NO Auto-Merge | NO Auto-Deploy                                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Projects & Modules

1. **`VulnerabilityRemediation.Domain`**:
   - `VulnerabilityFinding`: Canonical domain model preserving immutable `SourceClassification` alongside technical `DerivedRemediationRoute`.
   - Result Models: `RepositoryInspectionResult`, `FixExecutionResult`, `TestExecutionResult`, `SecurityReviewResult`, `RemediationEvidencePackage`.
   - `DomainValidator`: Validates business rules (CVE format, severity bounds, application number mapping).
   - `ClassificationAgent`: Deterministically derives remediation route.

2. **`VulnerabilityRemediation.Excel`**:
   - `ExcelIngestionService`: ClosedXML parser with security sanitizer stripping Excel formula triggers (`=`, `+`, `-`, `@`), truncating oversized cells, and normalizing headers.

3. **`VulnerabilityRemediation.Persistence`**:
   - `VulnerabilityDbContext`: SQLite database store (`data/vulnerabilities.db`) with parameterized queries and indexed fields.
   - `VulnerabilityRepository`: CRUD and filtered queries (by app, severity, classification, SLA status, internet-facing).

4. **`VulnerabilityRemediation.Repository`**:
   - `RepositoryRegistry`: Deterministic `ApplicationNumber` $\rightarrow$ `RepositoryMapping` resolver (`config/repositories.json`).
   - `SampleRepositoriesSeeder`: Automatically initializes and seeds baseline sample git repositories (`sample-repos/`) on `main`.
   - `RepositoryWorkspaceManager`: Clones, isolates, and manages branches (`workspaces/<VULN_ID>/repository`).
   - `RepositoryContextAgent`: Inspects AST structure, project files (`.csproj`, `pom.xml`), and test runners.
   - Fix Agents: `DotNetFixAgent`, `JavaFixAgent`, `DependencyFixAgent`, `LargeRefactorAgent`.
   - `TestValidationAgent`: Executes real build and test suites (`dotnet test`, `mvn test`) with AST fallback.
   - `SecurityReviewAgent`: Independent AST security auditor validating root cause resolution and detecting security bypasses or secret leaks.
   - `EvidenceGeneratorService`: Persists unified diff `changes.patch`, markdown `remediation-report.md`, and `agent-execution-trace.log`.
   - `PrPublisherService`: Pushes branches and opens PRs upon explicit human authorization.
   - `RemediationOrchestratorEngine`: Orchestrates the complete 10-step remediation lifecycle.

5. **`VulnerabilityDataMcp`**:
   - C# STDIO MCP Server (JSON-RPC 2.0 / Protocol `2024-11-05`) exposing 22 tools and aliases to Copilot and Antigravity.

6. **`VulnerabilityRemediation.Cli`**:
   - Control CLI supporting `import`, `validate`, `show`, `list`, `prepare`, `execute`, `diff`, `evidence`, `status`, `batch-plan`, `batch-execute`, `publish`, `approve-pr`.

7. **`VulnerabilityRemediation.Tests`**:
   - 41 unit and integration tests covering domain validation, Excel ingestion, classification, workspace manager, MCP server protocol, CLI commands, and end-to-end multi-repository remediation workflows.

