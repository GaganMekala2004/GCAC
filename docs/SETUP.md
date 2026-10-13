# ENVIRONMENT SETUP & PREREQUISITES GUIDE

## 1. System Requirements & Prerequisites

- **Operating System**: Windows 10/11, macOS, or Linux
- **Runtime**: [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- **Version Control**: Git 2.30+
- **AI Coding Assistants**:
  - Visual Studio Code with GitHub Copilot Chat extension, OR
  - Antigravity IDE

---

## 2. Step-by-Step Installation & Build

1. **Navigate to Repository Workspace**:
   ```powershell
   cd c:\Users\NAGASATYAMEKALA\Desktop\Prototype_GCAS
   ```

2. **Verify .NET 9 SDK**:
   ```powershell
   dotnet --version
   ```

3. **Restore Dependencies & Build Solution**:
   ```powershell
   dotnet build
   ```

4. **Execute Full Test Suite (41 Tests)**:
   ```powershell
   dotnet test
   ```

5. **Verify Database Findings**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- list
   dotnet run --project src/VulnerabilityRemediation.Cli -- validate
   ```

---

## 3. Sample Repositories Auto-Seeding

The platform includes a built-in repository seeder (`SampleRepositoriesSeeder.cs`). When any CLI command, MCP tool, or integration test executes, it automatically checks and initializes clean baseline Git repositories under `sample-repos/` on branch `main`:
- `sample-repos/gcas-agentic-e2e-test-repo` (APP-E2E-001)
- `sample-repos/payments-api` (APP-1001)
- `sample-repos/customer-service` (APP-1002)
- `sample-repos/inventory-manager` (APP-1003)
- `sample-repos/identity-provider` (APP-1004)
- `sample-repos/storefront-api` (APP-1005)

---

## 4. IDE & Agent Integrations

### A. Visual Studio Code Setup
1. Open the repository root in VS Code.
2. The `.vscode/settings.json` and `.vscode/mcp.json` automatically register the `vulnerability-data` MCP server.
3. Open **GitHub Copilot Chat** (`Ctrl+Alt+I` / `Cmd+Option+I`).
4. Type `remediate VUL-POC-002` or `@remediation-orchestrator Remediate GCAS-E2E-005` to trigger autonomous remediation.

### B. Antigravity Setup
1. The `.agents/mcp_config.json` configures the `vulnerability-data` MCP server.
2. The remediation skill is configured in `.agents/skills/gcas-remediation/SKILL.md`.
3. Type `remediate VUL-POC-002` to run the remediation workflow.

