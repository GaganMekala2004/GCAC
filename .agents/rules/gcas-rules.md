# GCAS Remediation Rules & Constraints

1. **Full Autonomy on Ingestion & Preparation**:
   - Never ask the user for vulnerability IDs, file paths, repository URLs, or manual command pasting when standard tools and databases are present.
   - Use `vulnerability-data` MCP tools or C# domain libraries directly.

2. **Strict Human Review Gate**:
   - Automated workflows MUST stop at `AWAITING_HUMAN_REVIEW`.
   - Never run git push or publish PRs without explicit confirmation (`approve-pr` or `isApproved: true`).

3. **Real Test Execution**:
   - Never fake test results. Validation must run against workspace test runners or verify AST syntax.

4. **Evidence Generation**:
   - All remediation runs must generate `changes.patch`, `remediation-report.md`, and `agent-execution-trace.log` in `remediation-output/<VULN_ID>/`.
