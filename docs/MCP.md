# ARCHITECTURAL NOTE: MODEL CONTEXT PROTOCOL (MCP) STATUS

> [!NOTE]
> **MCP is NOT part of the active Target POC runtime architecture.**
> All active runtime operations are performed locally and deterministically via GitHub Copilot agents in VS Code and local .NET domain/repository services.

---

## 1. Scope & Removal Summary

In previous prototype iterations, an MCP STDIO server (`mcp/VulnerabilityDataMcp`) was explored to expose JSON-RPC endpoints for finding queries and workspace orchestration.

For the **Target POC architecture**, MCP has been completely removed from the active execution path in favor of a simpler, more controlled, and local architecture:
- **No JSON-RPC tool calling**: AI agents operate via repository instructions (`.github/copilot-instructions.md`) and specialized agent prompts (`.github/agents/*.agent.md`).
- **No external/separate MCP server process**: Workflow coordination relies on the developer-invoked `/remediate-vulnerability` prompt and local helper services.
- **Direct file-based state**: Finding input comes directly from `vulnerability/*.csv` and workflow state is tracked in the single Shared Vulnerability Markdown report (`output/<title>_<id>.md`).

---

## 2. Rationale for Removal

1. **Simplicity & Zero Setup**: Developers only require VS Code and the .NET SDK without configuring STDIO child processes or JSON-RPC endpoints in `.vscode/mcp.json`.
2. **Deterministic Bounded Workflow**: A file-based shared markdown state ensures full auditability and strict linear execution through the Human Approval Gate.
3. **Security & Sandbox Isolation**: Eliminates inter-process RPC and ensures zero external connectivity.
