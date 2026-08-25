---
name: dotnet-secure-remediation
description: Reusable secure coding procedures for remediating .NET / C# vulnerabilities including SQL injection, authorization bypass, unsafe deserialization, path traversal, and secrets management.
---

# .NET Secure Remediation Procedure

1. **Root Cause Analysis**:
   - Inspect target C# file at `LocationPath`.
   - Identify specific flaw (e.g. string concatenation in raw SQL, missing `[Authorize]` attribute, unsafe `BinaryFormatter` usage, unvalidated file path input).

2. **Minimal Secure Fix**:
   - For SQL Injection: Replace raw SQL concatenation with parameterized SQL queries (`SqlParameter`, EF Core `FromSqlInterpolated`).
   - For Authorization Defect: Apply required ASP.NET Core authorization attributes or policy checks.
   - For Input/Path Validation: Validate inputs against allow-lists and sanitize file paths using `Path.GetFullPath()`.
   - For Cryptography / Secrets: Use standard .NET crypto primitives (AES-GCM, SHA256) and avoid hardcoded keys.

3. **Conformity & Verification**:
   - Follow existing project code formatting and architectural conventions.
   - Add targeted C# unit tests covering both the fix and edge cases.
