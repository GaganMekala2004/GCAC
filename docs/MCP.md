# MODEL CONTEXT PROTOCOL (MCP) ARCHITECTURE SPECIFICATION

## 1. Vulnerability Data MCP Server Overview

The **Vulnerability Data MCP Server** is a C# STDIO server (`mcp/VulnerabilityDataMcp/`) implementing Model Context Protocol (protocol version `2024-11-05` / JSON-RPC 2.0). It provides a comprehensive suite of tools enabling AI agents in GitHub Copilot Chat (VS Code) and Antigravity to query vulnerability findings, resolve repository mappings, prepare workspaces, execute autonomous remediation pipelines, run validation tests, conduct independent security reviews, collect evidence packages, and manage Pull Request publication upon human authorization.

---

## 2. Configuration & Client Connections

### Visual Studio Code (`.vscode/mcp.json`)
```json
{
  "mcpServers": {
    "vulnerability-data": {
      "command": "dotnet",
      "args": [
        "${workspaceFolder}/mcp/VulnerabilityDataMcp/bin/Debug/net9.0/VulnerabilityDataMcp.dll"
      ],
      "env": {
        "GCAS_WORKSPACE_ROOT": "${workspaceFolder}",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1"
      }
    }
  }
}
```

### Antigravity IDE (`.agents/mcp_config.json`)
```json
{
  "mcpServers": {
    "vulnerability-data": {
      "command": "dotnet",
      "args": [
        "c:/Users/NAGASATYAMEKALA/Desktop/Prototype_GCAS/mcp/VulnerabilityDataMcp/bin/Debug/net9.0/VulnerabilityDataMcp.dll"
      ],
      "env": {
        "GCAS_WORKSPACE_ROOT": "c:/Users/NAGASATYAMEKALA/Desktop/Prototype_GCAS",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1"
      }
    }
  }
}
```

---

## 3. Exposed Tool Suite

### Context & Query Tools
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_vulnerability` | `vulnerabilityId` | Retrieves structured finding details from `data/vulnerabilities.db`. |
| `get_vulnerability_context` | `vulnerabilityId` | Retrieves complete remediation context object (finding details, app metadata, repository mapping, and derived route). |
| `get_remediation_context` | `vulnerabilityId` | Alias for `get_vulnerability_context`. |
| `get_application_vulnerabilities` | `applicationNumber` | Retrieves all findings associated with an application (e.g. `APP-E2E-001`, `APP-1002`). |
| `get_vulnerabilities_by_classification` | `classification` | Filters findings by `SourceClassification` (`3PP`, `Ivanti`, `SpecializedAction`). |
| `get_vulnerabilities_by_severity` | `severity` | Filters findings by `Severity` (`Critical`, `High`, `Medium`, `Low`). |
| `get_out_of_sla_vulnerabilities` | *(none)* | Retrieves all findings marked Out of SLA. |
| `get_internet_facing_vulnerabilities` | *(none)* | Retrieves all findings marked Internet Facing. |
| `get_repository_mapping` | `applicationNumber` | Deterministically resolves Application Number to Repository URL from `config/repositories.json`. |
| `get_vulnerability_status` | `vulnerabilityId` | Returns current lifecycle state, SLA, branch, and review requirements. |
| `get_remediation_status` | `vulnerabilityId` | Alias for `get_vulnerability_status`. |
| `get_batch_plan` | *(none)* | Returns dynamic batch plan grouped by application and blast radius strategy. |

### Workspace & Execution Tools
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `prepare_workspace` | `vulnerabilityId` | Clones target repository to `workspaces/<vulnerabilityId>/repository` and checks out branch `remediation/<vuln-id>`. |
| `prepare_remediation_workspace` | `vulnerabilityId` | Alias for `prepare_workspace`. |
| `execute_remediation` | `vulnerabilityId` | Autonomously executes code fix, test validation, security review, and evidence generation; sets status to `AWAITING_HUMAN_REVIEW`. |
| `execute_batch_remediation` | `batchId` | Executes batch remediation pipeline across all findings in the specified batch. |

### Validation & Audit Tools
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `run_tests` | `vulnerabilityId` | Runs actual build and unit test commands against the workspace repository and returns metrics. |
| `run_validation_tests` | `vulnerabilityId` | Alias for `run_tests`. |
| `run_security_review` | `vulnerabilityId` | Performs independent AST security review on git diff and modified files. |
| `generate_evidence` | `vulnerabilityId` | Collects and returns evidence package (`changes.patch`, `remediation-report.md`, `agent-execution-trace.log`). |
| `get_vulnerability_diff` | `vulnerabilityId` | Returns git diff patch from `remediation-output/<vulnerabilityId>/changes.patch`. |
| `get_evidence_report` | `vulnerabilityId` | Returns markdown audit report from `remediation-output/<vulnerabilityId>/remediation-report.md`. |
| `get_execution_trace_log` | `vulnerabilityId` | Returns execution trace log from `remediation-output/<vulnerabilityId>/agent-execution-trace.log`. |

### Ingestion, Integrity & Publishing Tools
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `import_vulnerabilities` | `filePath` *(optional)* | Ingests vulnerability findings from an Excel workbook into SQLite database. |
| `validate_vulnerability` | `vulnerabilityId` *(optional)* | Validates specific vulnerability or whole database against domain integrity rules. |
| `validate_database` | *(none)* | Validates all persisted findings in database. |
| `publish_remediation_pr` | `vulnerabilityId`, `isApproved`, `approvalNotes` | Pushes approved branch to remote repository and opens Pull Request (Requires `isApproved: true`). |
| `approve_pr` | `vulnerabilityId`, `approvalNotes` *(optional)* | Explicit developer approval tool to publish remediation Pull Request. |

---

## 4. Human-in-the-Loop Security Gate

The MCP server enforces strict authorization guardrails:
- `execute_remediation` **ALWAYS** terminates with `status: "AWAITING_HUMAN_REVIEW"`.
- `publish_remediation_pr` refuses execution and returns `[HUMAN APPROVAL REQUIRED]` unless `isApproved` is explicitly passed as `true`.

