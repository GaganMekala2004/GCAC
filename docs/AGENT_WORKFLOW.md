# AGENT WORKFLOW & DELEGATION SPECIFICATION

## Multi-Agent Sequence Flow

```
[Developer] ──► Copilot Chat / Antigravity ──► Remediation Orchestrator Engine
                                                      │
                                                      ├─► 1. get_vulnerability_context (MCP / DB)
                                                      ├─► 2. ClassificationAgent (Derive Route)
                                                      ├─► 3. RepositoryWorkspaceManager (Prepare Workspace)
                                                      ├─► 4. RepositoryContextAgent (Inspect AST / Manifests)
                                                      ├─► 5. Specialist Fix Agent Delegation:
                                                      │      ├── DotNetFixAgent (C# / ASP.NET Core)
                                                      │      ├── JavaFixAgent (Java / Spring Boot)
                                                      │      ├── DependencyFixAgent (NuGet / Maven / Gradle)
                                                      │      └── LargeRefactorAgent (Architectural Refactor)
                                                      ├─► 6. TestValidationAgent (dotnet test / mvn test)
                                                      ├─► 7. SecurityReviewAgent (Independent AST Audit)
                                                      └─► 8. EvidenceGeneratorService (Write Evidence Package)
                                                                        │
                                                                        ▼ (STOP AT HUMAN REVIEW GATE)
[Developer] ◄── Complete Review Response (Diff + Tests + Security Audit) ──┘
      │
      ▼ (Developer Reviews Evidence in remediation-output/<VULN_ID>/)
[Developer] ──► "APPROVE PR <VULN_ID>"
                      │
                      ▼ (Explicit Human Authorization Required)
               PrPublisherService
                      │
                      ├─► Verify Human Authorization (isApproved == true)
                      ├─► git push origin remediation/<vuln-id>
                      └─► Open GitHub Pull Request
```

---

## Agent Delegation Matrix

| Step | Lifecycle Phase | Responsible Component / Agent | Execution Mode | Output Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Context Retrieval | `VulnerabilityDataMcp` / DB | MCP / CLI | Structured `VulnerabilityFinding` object |
| **2** | Route Classification | `ClassificationAgent` | Deterministic Rules | `DerivedRemediationRoute` enum |
| **3** | Workspace Preparation| `RepositoryWorkspaceManager` | Git Workspace Manager | `workspaces/<VULN_ID>/repository` (Branch: `remediation/<vuln-id>`) |
| **4** | Code Inspection | `RepositoryContextAgent` | AST / Manifest Parser | `RepositoryInspectionResult` (Target files, test runner) |
| **5** | Code Remediation | Specialist Fix Agents | Secure AST Rewriter | Modified repository files |
| **6** | Build & Test Run | `TestValidationAgent` | Process Execution | `TestExecutionResult` (`dotnet test`, `mvn test`) |
| **7** | Security Audit | `SecurityReviewAgent` | Independent Auditor | `SecurityReviewResult` (Rating: `PASS`, RootCauseResolved) |
| **8** | Evidence Packaging | `EvidenceGeneratorService` | Evidence Generator | `remediation-output/<VULN_ID>/changes.patch`<br>`remediation-output/<VULN_ID>/remediation-report.md`<br>`remediation-output/<VULN_ID>/agent-execution-trace.log` |
| **9** | **Human Review Gate**| **Developer** | **HITL Decision** | **Explicit Human Approval (`APPROVE PR <ID>`)** |
| **10**| Remote Publishing | `PrPublisherService` | Git Remote & GitHub API | Pushed remote branch & published Pull Request |

---

## Dual Execution Pathways

1. **Autonomous Tool-Calling Pathway**:
   - Used when Copilot Agent Mode or Antigravity executes tool calls via the `vulnerability-data` MCP server (`prepare_workspace`, `execute_remediation`, `run_tests`, `run_security_review`).

2. **Direct Autonomous Workspace Pathway**:
   - Used in standard chat turns where tools are not directly invoked by the interface. The agent natively references `config/repositories.json`, inspects the code in `workspaces/<VULN_ID>/repository`, applies the fix, and returns the complete review report with git diff, test metrics, and security audit rating without delegating intermediate commands to the user.
