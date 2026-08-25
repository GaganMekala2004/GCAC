---
name: security-validation
description: Independent security evaluation procedures for auditing proposed code diffs, verifying root cause resolution, and checking for regressions or bypasses.
---

# Security Validation Procedure

1. **Diff Audit**:
   - Inspect git diff in remediation branch against base commit.
   - Verify fix addresses the true root cause documented in CVE / vulnerability finding.

2. **Bypassability & Security Control Review**:
   - Check if fix can be easily bypassed with edge-case inputs.
   - Verify no new security weaknesses (e.g. disabled CSRF, hardcoded keys, weakened SSL validation) were introduced.

3. **Scope & Cleanliness Review**:
   - Verify no unrelated files or broad formatting changes were introduced.
   - Confirm scanner rule removal was NOT used to suppress findings.
