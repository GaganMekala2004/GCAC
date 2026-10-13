# MODEL ROUTING STRATEGY

This document outlines the recommended AI model capability categories for each specialized VS Code GitHub Copilot custom agent in the Vulnerability Remediation Platform.

> [!NOTE]
> Actual model availability depends on the enterprise GitHub Copilot subscription plan and organization policy. Identifiers should be selected via VS Code's model picker UI. Do not hardcode unverified model IDs.

---

## Agent Model Capability Mapping

| Agent Name | Preferred Model Capability Category | Rationale |
| :--- | :--- | :--- |
| **`remediation-orchestrator`** | Strong Tool Calling + Multi-Agent Delegation | Requires reliable structured output and tool orchestration capabilities across subagent workflows. |
| **`vulnerability-classifier`** | Fast Structured Reasoning | High speed, deterministic classification reasoning over structured schema. |
| **`repository-context`** | Strong Codebase Understanding + Context Window | High token context capability to analyze solutions, directory structures, and dependency manifests. |
| **`dotnet-fix`** | Strongest Available C# / .NET Coding Model | Precision C# code generation, ASP.NET Core knowledge, and secure refactoring. |
| **`java-spring-fix`** | Strongest Available Java / Spring Coding Model | Deep Java 17/21, Spring Boot 3, and Spring Security configuration expertise. |
| **`dependency-fix`** | Coding + Dependency Version Reasoning | Accurate XML/JSON manifest parsing and version semver evaluation. |
| **`specialized-action-analyzer`** | Strong Vulnerability Reasoning | Synthesizes complex scanner finding text into actionable technical routes. |
| **`large-refactor-planner`** | Deep Architectural Reasoning + Large Context | High-level system design, blast radius calculation, and multi-phase migration planning. |
| **`test-validation`** | Fast Reliable Tool Execution | Speed and deterministic parsing of command execution outputs (`dotnet test`, `mvn test`). |
| **`security-review`** | Strong Independent Reasoning | Critical adversarial auditing capability to spot bypasses, subtle security flaws, and secrets. |
| **`pr-publisher`** | High Precision Administrative Model | Simple, exact execution of git commands and GitHub API PR payload creation. |

---

## Model Selection Procedure in VS Code

1. In VS Code GitHub Copilot Chat, open **Configure Agents / Model Selector**.
2. For code-generating agents (`dotnet-fix`, `java-spring-fix`), select the highest tier coding model available.
3. For independent verification (`security-review`), select a distinct model family where supported to ensure objective evaluation.
