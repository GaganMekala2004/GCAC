# Remediation pipeline corrections — 2026-11-15

This change was developed in an already modified working tree. It builds on the existing Stage 3/toolchain and Stage 6 work; the entire working-tree diff is not attributable to this investigation. No findings were marked remediated, no approval was granted, and nothing was published or merged.

## Confirmed causes and corrections

1. **016/017: silent zero-test baseline.** Both saved baseline JSON files show a successful solution VSTest target, zero executed tests, and no TRX. PaymentsAPI restore metadata points to a disposable CodeQL package directory, including `NuGetPackageRoot`, package imports, and `packageFolders`. Those paths do not exist in Docker. The existing working-tree `IsTestProject` setting exposed NETSDK1064 rather than silently skipping the test SDK imports. Staging now rebases all recorded package roots to the existing read-only sandbox NuGet mount, without changing original restore metadata. Absent cache packages are categorized as RESTORE_FAILED with the NETSDK diagnostic. No dependency download or network exception was added.
2. **Assertion failures confused with compilation failures.** A genuine failed xUnit assertion makes solution-level `dotnet test` print `Build FAILED`. That banner previously overrode TRX. Concrete compiler errors remain build failures; assertion TRX now retains test counts and test-level diagnostics. A nonzero process exit cannot become PASS from passing report counters. Multiple current-run TRX files are aggregated; stale workspace reports are not accepted as current evidence.
3. **Stage 4 shown before eligibility.** Stage 3 previously logged UNTESTED and continued to generate a patch/approval request. The shared eligibility predicate now stops this path before Stage 4. It requires executed, known, nonzero assertion counts and an eligible outcome. A genuine TESTS_FAILED baseline is eligible evidence; compiler, restore, timeout, cancelled, missing, skipped-only, and zero-test results are not. The existing explicit UNTESTED exception requires both authorization and a nonempty rationale; this investigation grants none. The same predicate guards approval execution and normalization of stale pending approval state. Exact diff/hash approval checks remain in place.
4. **State and diagnostics diverged.** Markdown inference could overwrite canonical pending/handoff stages, and a blocking failure emitted a failed-stage UI event. Canonical stages now take precedence over Markdown inference, blocking events retain BLOCKED in the dashboard, and outbound-gate errors have OUTBOUND_CONTEXT_BLOCKED rather than RUNNER_CRASH. A successful test category no longer masks a subsequent scanner/security failure.
5. **020: raw source in model context.** Free-text finding minimization did not protect full source/config embedded in classification/RCA/remediation prompts or sourceCode options. Known credential forms are now fully replaced before the unchanged OutboundContextGate inspects the exact outbound text. Classification/RCA context is centered on the finding line. The remediation prompt uses the redacted target file. An in-memory map reconstructs exact local patch context before scope checks, hashing, and approval; it is not exported to the model or persisted as a token map. Unknown/residual credential material remains subject to gate rejection.
6. **Provenance was obscured.** The secrets-config adapter intentionally includes SEC-005/CWE-89, SEC-004/CWE-78, SEC-003/CWE-327, and SEC-001/CWE-798. Its scanner name does not imply every rule is a credential finding. Rule_ID is now preserved through CSV-compatible and minimized context. Scanner CWE is retained while conflicting AI CWE advice is recorded separately and requires review.

## Finding evidence and limits

| Finding | Recorded rule | Current source evidence | Conclusion |
| --- | --- | --- | --- |
| 016 | SEC-005 / CWE-89 | PaymentController line 15 concatenates request.AccountId into SQL, then constructs SqlCommand | Unparameterized SQL construction is present. This method does not execute the command; end-to-end exploitability is not established. |
| 017 | SEC-004 / CWE-78 | ReceiptController line 9 interpolates receiptId into cmd.exe arguments | Shell injection pattern is present. Reachability and Windows execution need developer review. |
| 018 | SEC-003 / CWE-327 | LegacyCrypto line 9 calls DES.Create | Broken algorithm pattern is present. |
| 019 | SEC-003 / CWE-327, recorded line 10 | Current line 10 calls des.CreateEncryptor; it does not match SEC-003 | Recorded evidence is stale relative to current source. Re-scan; do not automatically close or invent a result. |
| 020 | SEC-001 / CWE-798 | Gate decision identifies Stripe-format source/config content | Original credential values are unnecessary for model reasoning and are not included here. |

Current 018/019 canonical artifacts say HANDED_OFF_TO_COPILOT, with NOT_EXECUTED validation and pending later stages. Their reports also say tests were not executed. There is no retained test failure from which to infer a compiler/assertion root cause. The corrected view explicitly reports that verified execution results are pending instead of inferring VALIDATION_FAILED from stale prose.

## Verification

- `node scripts/verify-baseline-discovery.js`: genuine Docker gateway execution against a disposable PaymentsAPI snapshot. Normal test: 1 passed. Added deliberate assertion failure in the disposable snapshot: 2 executed, 1 passed, 1 failed, categorized TESTS_FAILED. Both runs produced fresh TRX artifacts. See `evidence/baseline-discovery.json` for actual run IDs, pinned image digest, NO_NETWORK policy, and TRX hashes. The deliberate failure is verification only; it is not added to the sample repository.
- PaymentsAPI's existing tautological Assert.True(true) was replaced by actual exception and request-preservation assertions; the seeder matches. Intentionally vulnerable application fixtures remain in place. This smoke test does not establish SQL injection or command injection remediation.
- New targeted tests cover scanner NuGet root rebasing and original-file preservation; stale and multiple TRX artifacts; baseline eligibility; raw gate rejection and sanitized boundary inputs; local patch reconstruction; scanner-rule provenance; and stale Markdown versus canonical handoff state.
- Existing security suites continue to cover network isolation, pinned images, host-execution rejection, scope constraints, tampered/replayed approval, changed diff hashes, and evidence integrity.
- Initial restricted test launches could not access Docker, localhost listeners, or MSBuild IPC. Tests were rerun with the required approved environment access. The remediation gateway itself never falls back to host execution.
- Final suite counts and commands are recorded in `evidence/regression-summary.json`.

## External infrastructure and manual verification

- This terminal has no active VS Code `vscode.lm` Copilot session. No live model response, remediation patch, approval, credential rotation, or closure was fabricated. Verify 020 through the developer's signed-in Copilot session, including classification, proposal reconstruction, exact diff review, and revision.
- Re-run 016/017 in the interactive workflow and confirm Stage 3 counters/TRX, Stage 4 eligibility, reload behavior, and Copilot/webview agreement. Exercise missing-cache, build-failed, zero-test, genuine failing-test, and successful baselines.
- Re-scan 018/019 against current source and verify the new run's canonical identity and diagnostics before approving anything.
- Native Copilot Chat agent tools operate outside the extension gateway's interception boundary. Docker isolation governs GCAC-owned subprocesses only.
- Known-format redaction is not proof of complete secret discovery. Residual/unknown high-entropy material must remain blocked. Raw local source and approved diff artifacts can still contain credentials and require existing local access controls.
- Offline package availability and approved pinned images remain prerequisites. Unsupported/unprovisioned profiles remain blocked. No image pull, host-shell fallback, or weakened Docker boundary was introduced.
- TRX parsing retains the existing lightweight parser; syntactic checks are not a comprehensive XML validation engine. Scanner regex matches are not formal taint proofs, and the sample smoke test is not a security regression suite.

Passing these checks does not establish enterprise production readiness.
