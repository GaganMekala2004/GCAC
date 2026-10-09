# DEMONSTRATION & TESTING RUNBOOK (TARGET POC)

Follow these steps to demonstrate and test the **Agentic Vulnerability Remediation POC** inside Visual Studio Code using GitHub Copilot Chat, Antigravity, and the local helper CLI.

---

## 1. Environment Setup & Verification

1. **Open Workspace**:
   ```powershell
   cd <repository-root>
   ```

2. **Build and Test Suite**:
   ```powershell
   dotnet build
   dotnet test
   ```

3. **Inspect Local Vulnerability CSV**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- list-csv
   ```

---

## 2. Interactive AI Remediation Workflow in VS Code / GitHub Copilot

### Step-by-Step Interactive Run

1. Open **GitHub Copilot Chat** in VS Code (or Antigravity Chat).
2. Enter the workflow command:
   ```
   /remediate-vulnerability
   ```
3. **Stage 1 - Discovery & Selection**:
   - The **Vulnerability Orchestrator** scans `vulnerability/*.csv` and lists distinct vulnerability categories (e.g., *SQL Injection*, *Command Injection*, *Path Traversal*, *Dependency Vulnerability*, *Hardcoded Secret*).
   - Prompt response: Select ONE vulnerability type (e.g., `SQL Injection`).
   - The Orchestrator lists matching findings.
   - Prompt response: Select EXACTLY ONE vulnerability (e.g., `GCAS-E2E-001` or `VUL-POC-001`).

4. **Stage 2 - Shared Markdown Initialization**:
   - Creates `output/<sanitized_vulnerability_title>_<vulnerability_id>.md` (e.g., `output/sql_injection_in_weatherforecastcontroller_gcas_e2e_001.md`).
   - Records vulnerability metadata and initializes the single shared audit report.

5. **Stage 3 - Code Analysis & Root Cause Analysis (RCA)**:
   - **Code Analysis / RCA Agent** inspects the target code without modifying production code.
   - Traces source-to-sink data flow, call hierarchy, affected files/lines, and root cause.
   - Appends findings to the Shared Markdown report.

6. **Stage 4 - Unit Testing & Baseline Verification**:
   - **Unit Test Agent** inspects existing test conventions (`xUnit`, `NUnit`, `MSTest`).
   - Generates security-focused unit tests reproducing the vulnerability.
   - Executes baseline tests against the **unfixed code**.
   - Appends execution commands, baseline results, and failure logs to the Shared Markdown report.

7. **Stage 5 - MANDATORY HUMAN APPROVAL GATE**:
   - Workflow **STOPS completely**.
   - Displays selected vulnerability, root cause analysis, affected files, proposed remediation, and baseline test evidence.
   - Developer reviews the proposal and issues explicit decision:
     - `APPROVE` $\rightarrow$ Proceeds to production-code remediation.
     - `REQUEST CHANGES` $\rightarrow$ Re-runs analysis or test generation with feedback.
     - `REJECT` $\rightarrow$ Workflow terminates with audit log.
   - **NO PRODUCTION CODE MODIFICATION OCCURS BEFORE APPROVAL.**

8. **Stage 6 - Remediation**:
   - **Remediation Agent** applies the minimal, secure code fix.
   - No unrelated refactoring or formatting churn.
   - Executes post-fix security tests and appends before/after context and test outcomes to the Shared Markdown.

9. **Stage 7 - Regression Testing**:
   - **Regression Agent** inspects Git diff and runs existing project build and regression suites (`dotnet test`).
   - Confirms zero regressions; distinguishes pre-existing failures from remediation changes.
   - Appends results to the Shared Markdown.

10. **Stage 8 - Final Independent Validation**:
    - **Final Validation Agent** independently validates diffs, build results, test outcomes, and security rules.
    - Emits `PASS`, `FAIL`, or `PARTIAL` with a Confidence Score (0-100).
    - Appends validation verdict to the Shared Markdown.

11. **Stage 9 - Documentation & Controlled CSV Update**:
    - **Documentation Agent** finalizes the Shared Markdown report.
    - Performs an in-place update on **ONLY the selected vulnerability row** in `vulnerability/*.csv`.
    - Preserves all original rows and all original columns.

---

## 3. Local Helper CLI Verification (Optional Developer Utilities)

You can also inspect local CSVs, run workflow stages, view git diffs, and inspect Markdown reports via the local CLI:

1. **List all vulnerabilities in local CSV**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- list-csv
   ```

2. **Run remediation engine on a finding**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- run-remediation GCAS-E2E-001
   ```

3. **Inspect Git diff**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- show-diff
   ```

4. **View Shared Markdown report**:
   ```powershell
   dotnet run --project src/VulnerabilityRemediation.Cli -- show-report GCAS-E2E-001
   ```

---

## 4. Key Governance & POC Rules

| Guardrail | Enforcement Rule |
| :--- | :--- |
| **No Remote Git Push** | Changes remain exclusively on the local working branch for developer review. Zero automated push/merge. |
| **No Automated PRs** | Pull request publishing is out of scope for this POC. |
| **No SQLite / MCP / SharePoint** | All runtime state is maintained via `vulnerability/*.csv` and `output/*.md`. |
| **Single Vulnerability Per Run** | Exactly one vulnerability is selected and remediated per execution. |
| **Preservation of User Work** | Rollback and file tracking preserve unrelated developer modifications. |
