# DEMONSTRATION & REAL-TIME TESTING RUNBOOK

Follow these steps to demonstrate and test the **Agentic AI Vulnerability Remediation System** inside Visual Studio Code, Antigravity, and via the Control CLI:

---

## 1. Setup & Ingestion

1. **Open Workspace**:
   ```powershell
   cd c:\Users\NAGASATYAMEKALA\Desktop\Prototype_GCAS
   ```
2. **Build and Test Suite**:
   ```powershell
   dotnet build
   dotnet test
   ```
3. **Inspect Persisted Findings & Database Integrity**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- list
   dotnet run --project src/VulnerabilityRemediation.Cli -- validate
   ```

---

## 2. Dynamic Batch Planning Demonstration

Generate and view dynamic remediation batches grouped by blast radius:
```powershell
dotnet run --project src/VulnerabilityRemediation.Cli -- batch-plan
```

Execute an entire batch of dependency updates:
```powershell
dotnet run --project src/VulnerabilityRemediation.Cli -- batch-execute BATCH-APP-1003-DEP-02
```

---

## 3. Interactive AI Remediation Demos

### A. Single Vulnerability Remediation in GitHub Copilot Chat
1. Open **GitHub Copilot Chat** in VS Code.
2. Enter:
   ```
   remediate VUL-POC-002
   ```
   or for E2E suite:
   ```
   remediate GCAS-E2E-005
   ```
3. **Autonomous Execution Flow**:
   - Queries `vulnerability-data` MCP server via `get_remediation_context`.
   - Prepares isolated workspace `workspaces/<VULN_ID>/repository` on branch `remediation/<vuln-id>`.
   - Selects correct fix agent (`JavaFixAgent`, `DotNetFixAgent`, etc.) and applies precise code fix.
   - Executes real test suite (`mvn test`, `dotnet test`) and records execution metrics.
   - Runs independent AST security review (`Rating = PASS`).
   - Generates evidence package in `remediation-output/<VULN_ID>/`.
   - **STOPS at status `AWAITING_HUMAN_REVIEW` (Zero remote pushes, Zero PRs)**.

### B. Antigravity Remediation Demo
1. In Antigravity chat, enter:
   ```
   remediate VUL-POC-002
   ```
2. Antigravity leverages `.agents/skills/gcas-remediation/SKILL.md` and MCP server to execute the pipeline and stop at `AWAITING_HUMAN_REVIEW`.

---

## 4. Human Review & PR Publishing Demo

1. **Developer Inspects Git Diff & Audit Evidence**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- diff VUL-POC-002
   dotnet run --project src/VulnerabilityRemediation.Cli -- evidence VUL-POC-002
   dotnet run --project src/VulnerabilityRemediation.Cli -- status VUL-POC-002
   ```
2. **Developer Issues Explicit Approval**:
   In Copilot Chat:
   ```
   APPROVE PR VUL-POC-002
   ```
   *Or via Control CLI:*
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- publish VUL-POC-002 --approve
   dotnet run --project src/VulnerabilityRemediation.Cli -- approve-pr VUL-POC-002
   ```
3. **Observe PR Publisher Execution**:
   - Validates human approval flag (`isApproved == true`).
   - Pushes branch `remediation/vul-poc-002` to remote repository.
   - Creates GitHub Pull Request with complete audit details.
   - Status transitions to `PrCreated`.

---

## 5. Complete Vulnerability Scenarios Matrix

| Vulnerability ID | Target App / Repository | Technology | Flaw & Scenario | Derived Route | Human Review Gate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`GCAS-E2E-001`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | SQL Injection in `ProductsController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`GCAS-E2E-002`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | Command Injection in `DiagnosticsController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`GCAS-E2E-003`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | Reflected XSS in `SearchController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`GCAS-E2E-004`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | Path Traversal in `FileController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`GCAS-E2E-005`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | Hardcoded Secret in `SecretService.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`GCAS-E2E-006`** | `sample-repos/gcas-agentic-e2e-test-repo` | .NET 9 Web API | Vulnerable `Newtonsoft.Json` in `.csproj` | `DependencyUpdate` | Dependency Update $\rightarrow$ PR on Approval |
| **`VUL-POC-001`** | `sample-repos/payments-api` | .NET 9 Web API | SQL Injection in `PaymentController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`VUL-POC-002`** | `sample-repos/customer-service` | Java Spring Boot | Auth Bypass in `SecurityConfig.java` | `JavaSpringSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`VUL-POC-003`** | `sample-repos/inventory-manager` | .NET 9 Service | Vulnerable `Newtonsoft.Json` in `.csproj` | `DependencyUpdate` | Dependency Update $\rightarrow$ PR on Approval |
| **`VUL-POC-004`** | `sample-repos/identity-provider` | Infrastructure / VM | Ivanti Server Buffer Overflow | `NoCodeRemediation` | Server Patch Report $\rightarrow$ STOP |
| **`VUL-POC-005`** | `sample-repos/payments-api` | .NET 9 Web API | DES Protocol Refactor in `LegacyCrypto.cs` | `LargeRefactor` | Architecture Plan $\rightarrow$ STOP |
| **`VUL-POC-006`** | `sample-repos/payments-api` | .NET 9 Web API | Command Injection in `ReceiptController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |
| **`VUL-POC-007`** | `sample-repos/payments-api` | .NET 9 Web API | Hardcoded API Secret in `appsettings.json` | `ConfigurationChange` | Local Config Fix $\rightarrow$ PR on Approval |
| **`VUL-POC-008`** | `sample-repos/customer-service` | Java Spring Boot | Vulnerable Spring Boot parent in `pom.xml` | `DependencyUpdate` | Dependency Update $\rightarrow$ PR on Approval |
| **`VUL-POC-009`** | `sample-repos/customer-service` | Java Spring Boot | Path Traversal in `DocumentDownloadController.java`| `JavaSpringSourceFix`| Local Code Fix $\rightarrow$ PR on Approval |
| **`VUL-POC-010`** | `sample-repos/inventory-manager` | .NET 9 Service | Vulnerable `System.Text.Encodings.Web` | `DependencyUpdate` | Dependency Update $\rightarrow$ PR on Approval |
| **`VUL-POC-011`** | `sample-repos/storefront-api` | .NET 9 Web API | Reflected XSS in `SearchController.cs` | `DotNetSourceFix` | Local Code Fix $\rightarrow$ PR on Approval |

