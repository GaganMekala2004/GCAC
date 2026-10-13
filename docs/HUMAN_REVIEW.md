# DEVELOPER HUMAN REVIEW GUIDE

## Developer Review Procedure

When the `remediation-orchestrator` agent completes its local workflow, it sets the status to `AWAITING_HUMAN_REVIEW` and halts execution. No remote branches or Pull Requests exist at this point.

### Step 1: Inspect Evidence Package
Review the generated audit report located at:
`remediation-output/<vulnerability-id>/remediation-report.md`

Verify:
- **Root Cause Summary**: Was the vulnerability accurately identified?
- **Remediation Summary**: Does the fix address the root cause cleanly without scanner rule suppression?
- **Files Changed**: Are changes strictly limited to relevant code files?
- **Validation Results**: Did `dotnet test` or `mvn test` pass cleanly?
- **Security Audit Rating**: Is the independent security review rating `PASS`?

### Step 2: Inspect Unified Git Diff
Run the CLI diff command or inspect Git changes in VS Code / Antigravity:
```powershell
dotnet run --project src/VulnerabilityRemediation.Cli -- diff VUL-POC-002
```
Or view the patch directly:
`remediation-output/<vulnerability-id>/changes.patch`

### Step 3: Approval / Rejection Decision

- **If Approved**:
  - In VS Code GitHub Copilot Chat:
    ```
    APPROVE PR VUL-POC-002
    ```
  - Via Control CLI:
    ```powershell
    dotnet run --project src/VulnerabilityRemediation.Cli -- publish VUL-POC-002 --approve
    dotnet run --project src/VulnerabilityRemediation.Cli -- approve-pr VUL-POC-002
    ```
  - Via MCP Tool:
    Call `approve_pr(vulnerabilityId: "VUL-POC-002", approvalNotes: "Verified secure auth configuration.")`

- **If Rejection / Revision Required**:
  Prompt the agent with specific revision feedback (e.g. *"Revise authorization rules in SecurityConfig.java"*).

