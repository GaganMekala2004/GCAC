# MODEL ROUTING STRATEGY (TARGET POC)

This document outlines the recommended AI model capability categories for the **7 runtime GitHub Copilot agents** in the Target POC Vulnerability Remediation workflow.

> [!NOTE]
> Actual model availability depends on the enterprise GitHub Copilot subscription plan and organization policy. Identifiers should be selected via VS Code's model picker UI.

---

## 1. Runtime Agent Model Capability Mapping

| Agent Role | Copilot Agent File | Recommended Capability Category | Rationale |
| :--- | :--- | :--- | :--- |
| **1. Vulnerability Orchestrator** | `vulnerability-orchestrator.agent.md` | Fast Structured Reasoning & Planning | Orchestrates discovery, user category/finding selection, Markdown initialization, and stage transitions. |
| **2. Code Analysis / RCA Agent** | `code-analysis-rca.agent.md` | Deep Codebase Understanding & Context Window | Analyzes source-to-sink data flow, call hierarchy, and root cause analysis across files. |
| **3. Unit Test Agent** | `unit-test.agent.md` | Precision Code Generation (.NET / Java) | Generates security unit tests adhering to repository conventions and runs baseline verification. |
| **4. Remediation Agent** | `remediation.agent.md` | Strongest Available Coding Model | Applies minimal, secure code changes without refactoring churn; runs post-fix verification. |
| **5. Regression Agent** | `regression.agent.md` | Reliable Build & Test Execution | Runs project regression suites (`dotnet test`), analyzes Git diff, and distinguishes pre-existing failures. |
| **6. Final Validation Agent** | `final-validation.agent.md` | Critical Adversarial Reasoning | Independently evaluates diffs, tests, and security guardrails; emits PASS/FAIL/PARTIAL and 0-100 Confidence Score. |
| **7. Documentation Agent** | `documentation.agent.md` | Accurate Structured Documentation & CSV Parsing | Finalizes Shared Markdown report and performs in-place update of the selected row in `vulnerability/*.csv`. |

---

## 2. Governance Gate

| Role | Entity | Function |
| :--- | :--- | :--- |
| **Human Approval Gate** | **Developer (Human)** | Mandatory review barrier between baseline testing and code remediation. Reviews RCA, proposed fix, and baseline test logs to provide `APPROVE`, `REQUEST CHANGES`, or `REJECT`. |
