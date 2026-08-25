---
name: remediation-testing
description: Standardized procedures for executing build and test suites in target repository workspaces and capturing real execution results without fabricating output.
---

# Remediation Testing Procedure

1. **Identify Build & Test Environment**:
   - For .NET: Use `dotnet build` and `dotnet test`.
   - For Maven: Use `mvn test` or `mvn verify`.
   - For Gradle: Use `./gradlew test`.

2. **Execute Commands in Cloned Repository**:
   - Execute commands within target `workspaces/<vulnerability-id>/repository`.
   - Never claim build or tests passed without actual execution logs.

3. **Distinguish Failure Causes**:
   - Differentiate between pre-existing repository failure, remediation-induced failure, and environment missing dependency failure.
