# GCAS Remediation Rules & Constraints

1. **Full Autonomy on Ingestion & Preparation**:
   - Never ask the user for vulnerability IDs, file paths, repository URLs, or manual command pasting when standard tools and databases are present.
   - Use `vulnerability-data` MCP tools or C# domain libraries directly.

2. **Strict Human Review Gate & No Agent Publishing (Phase 1 P0-B)**:
   - Automated workflows MUST stop at `AWAITING_HUMAN_REVIEW`.
   - Remote Git push and Pull Request publication from AI agents, MCP tools, or CLI flags are disabled in Phase 1. Human publication occurs strictly outside the agent boundary.

3. **Real Test Execution & Single-Finding Isolation (`SEC-02`)**:
   - Never fake test results or treat `UNTESTED` / `PARTIAL` / `COULD_NOT_RUN` as passing. Execute one finding per run ID.

4. **Evidence Generation**:
   - All remediation runs must generate `changes.patch`, `remediation-report.md`, and `agent-execution-trace.log` in `remediation-output/<VULN_ID>/`.
