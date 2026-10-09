---
name: gcas-remediation
description: Local bounded vulnerability remediation workflow for GCAC using GitHub Copilot agents, local CSV input, and Shared Markdown state.
---

# GCAC Vulnerability Remediation Skill

This skill guides local vulnerability remediation across applications using the 7 bounded GitHub Copilot agents, local CSV files (`vulnerability/*.csv`), and Shared Vulnerability Markdown reports (`output/*.md`).

## Target POC Architecture

- **Input**: Local CSV in `vulnerability/*.csv`
- **Agents**: 7 Bounded Copilot Agents (`vulnerability-orchestrator`, `code-analysis-rca`, `unit-test`, `remediation`, `regression`, `final-validation`, `documentation`)
- **Governance Gate**: Mandatory Human Approval Gate before any production code modification
- **State**: Single Shared Vulnerability Markdown report (`output/<title>_<id>.md`)
- **Output**: Controlled single-row CSV update by Documentation Agent only
- **Environment**: Fully local in Visual Studio Code (No MCP, No SharePoint, No Graph, No SQLite, No external network APIs, No auto-push/PR)

## Workflow Execution

1. Trigger `/remediate-vulnerability` or invoke `@vulnerability-orchestrator`.
2. Select vulnerability category from local CSV.
3. Select EXACTLY ONE vulnerability finding.
4. `@code-analysis-rca` inspects code, traces data flow, identifies root cause (Read-Only).
5. `@unit-test` authors security unit tests and establishes baseline on unfixed code.
6. **STOP at Human Approval Gate**: Review RCA and baseline evidence; authorize or reject fix.
7. Upon approval only, `@remediation` applies the minimal secure fix and executes post-fix tests.
8. `@regression` runs full build and existing regression test suite.
9. `@final-validation` independently verifies diff and test outcomes (PASS / FAIL / PARTIAL, 0-100 score).
10. `@documentation` finalizes the Shared Markdown report and updates the selected row in local CSV.
