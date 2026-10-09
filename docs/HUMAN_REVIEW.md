# HUMAN APPROVAL GOVERNANCE GATE SPECIFICATION

## 1. Governance Concept

In the **Target POC Architecture**, Human Approval is an explicit **GOVERNANCE GATE** positioned immediately after Root Cause Analysis and Baseline Testing (Step 9/10), and strictly **BEFORE** any production code modification (Step 11).

> [!IMPORTANT]
> **Human Approval is NOT an AI agent.**
> It is an immutable governance barrier where the system halts and presents evidence to the human developer.
> No agent possesses the authority to bypass this gate or modify source code without documented human authorization.

---

## 2. Review Gate Information

When the workflow stops at the Human Approval Gate, the following evidence is presented to the developer:

1. **Vulnerability Overview**: Vulnerability ID, CVE, Application, Severity, Category, Location.
2. **Root Cause Analysis (RCA)**: Data flow from untrusted source to sink, affected methods, and security impact.
3. **Proposed Remediation**: Specific architectural or coding changes proposed to eliminate the vulnerability.
4. **Baseline Test Results**: Actual CLI execution logs demonstrating the unfixed baseline behavior on the current branch.

---

## 3. Governance Decisions

The developer can make one of three decisions:

### A. APPROVE
- **Action**: Authorizes the Remediation Agent to proceed with the smallest secure fix and post-fix testing.
- **Shared Markdown Record**: `## Human Approval Gate` is appended with `Decision: APPROVED`, reviewer name, and timestamp.

### B. REQUEST CHANGES
- **Action**: Provides corrective feedback or alternative implementation constraints to the RCA or Unit Test agents without modifying code.
- **Shared Markdown Record**: Feedback appended for iterative re-planning.

### C. REJECT
- **Action**: Aborts the remediation attempt. The rejection rationale is recorded in the Shared Markdown report, the CSV status is updated to `Rejected / Manual Review Required`, and all files remain untouched.

---

## 4. Local Review Commands

```powershell
# View Shared Markdown report up to Human Approval Gate
dotnet run --project src/VulnerabilityRemediation.Cli -- report VUL-POC-001

# Execute remediation with explicit human authorization
dotnet run --project src/VulnerabilityRemediation.Cli -- execute VUL-POC-001 --approve
```
