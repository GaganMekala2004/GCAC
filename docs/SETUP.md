# ENVIRONMENT SETUP & PREREQUISITES GUIDE (TARGET POC)

## 1. System Requirements & Prerequisites

- **Operating System**: Windows 10/11, macOS, or Linux
- **Runtime**: [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- **Version Control**: Git 2.30+
- **AI Coding Assistant**:
  - Visual Studio Code with GitHub Copilot Chat extension, OR
  - Antigravity IDE

---

## 2. Step-by-Step Installation & Verification

1. **Clone/Open Repository Root**:
   ```powershell
   cd <repository-root>
   ```

2. **Verify .NET 9 SDK**:
   ```powershell
   dotnet --version
   ```

3. **Restore Dependencies & Build Solution**:
   ```powershell
   dotnet build VulnerabilityRemediation.sln
   ```

4. **Execute Full Test Suite**:
   ```powershell
   dotnet test VulnerabilityRemediation.sln
   ```

5. **Verify Local CSV Findings**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- list-csv
   ```

---

## 3. Directory Layout

The solution uses a clean, file-based architecture without external infrastructure:

```
GCAC/
├── .github/
│   ├── agents/                   # 7 bounded Copilot agent instructions
│   ├── prompts/                  # /remediate-vulnerability workflow prompt
│   └── copilot-instructions.md   # Shared governance & security rules
├── vulnerability/                # Input vulnerability CSV files
│   └── vulnerabilities.csv
├── output/                       # Output Shared Vulnerability Markdown reports
├── src/                          # Local .NET helper libraries (Domain, Repository, Cli)
├── tests/                        # Local unit and workflow tests
└── docs/                         # Architectural documentation & runbooks
```

---

## 4. Running the Remediation Workflow in VS Code

1. Open the repository root in **Visual Studio Code**.
2. Open **GitHub Copilot Chat** (`Ctrl+Alt+I` on Windows/Linux or `Cmd+Option+I` on macOS).
3. Enter:
   ```
   /remediate-vulnerability
   ```
4. Follow the interactive steps:
   - Select a vulnerability category.
   - Select exactly one vulnerability finding.
   - Review Code Analysis & RCA.
   - Review baseline test execution results.
   - Explicitly provide **Human Approval** (`APPROVE`, `REQUEST CHANGES`, `REJECT`).
   - Review post-fix remediation and regression test runs.
   - Review Final Validation verdict and finalized Markdown report.
   - Verify that the Documentation Agent updated the selected CSV row.
