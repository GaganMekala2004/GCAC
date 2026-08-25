---
name: gcas-remediation
description: Autonomous vulnerability remediation workflow for Prototype_GCAS using local MCP tools and deterministic remediation agents.
---

# GCAS Vulnerability Remediation Skill

This skill guides autonomous remediation of security findings across enterprise application repositories using the local GCAS infrastructure.

## Autonomous Remediation Workflow

When requested to remediate a vulnerability (e.g., `remediate VUL-POC-002` or `remediate GCAS-E2E-004`):

1. **Retrieve Vulnerability Context**:
   - Query MCP tool `get_vulnerability_context` (or `get_remediation_context`) with `vulnerabilityId`.
   - Extract `ApplicationNumber`, `DerivedRemediationRoute`, `Severity`, `LocationPath`, and repository mapping.
   - Do NOT ask the user for details or file paths.

2. **Prepare Workspace**:
   - Query MCP tool `prepare_workspace` (or run CLI `dotnet run --project src/VulnerabilityRemediation.Cli -- prepare <VULN_ID>`).
   - Clones target repo to `workspaces/<VULN_ID>/repository` and checks out `remediation/<vuln-id>`.

3. **Execute Remediation Pipeline**:
   - Query MCP tool `execute_remediation` with `vulnerabilityId` (or execute via `RemediationOrchestratorEngine`).
   - The engine selects the appropriate fix agent (e.g. `JavaFixAgent`, `DotNetDependencyFixAgent`, `TerraformFixAgent`), applies the precise fix, executes real test validation (`mvn test`, `dotnet test`), runs the security review audit, and generates audit evidence.

4. **Review Status and Evidence**:
   - Validate that tests passed and security review returned `PASS`.
   - Evidence is persisted to `remediation-output/<VULN_ID>/` (`changes.patch`, `remediation-report.md`, `agent-execution-trace.log`).

5. **Stop at Human Review Gate**:
   - Set status to `AWAITING_HUMAN_REVIEW`.
   - Never push to remote or open a PR until explicit human authorization is received.
