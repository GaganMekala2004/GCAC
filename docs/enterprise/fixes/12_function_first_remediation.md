# Function-first remediation stabilization

Verdict: **PARTIALLY FUNCTIONAL**. The controlled local pipeline has passed real Docker/test/re-scan integration checks, including success, a defective patch, missing tests, and cancellation followed by retry. The real interactive Copilot provider and actual human consent dialogs still require the developer's VS Code session. Automated integration consent is explicitly labelled test-only; it is not evidence of human approval. This is local development stabilization, not a production security assessment.

## 1. Baseline verified and actual root causes fixed

The starting implementation was verified before changes: **22 extension suites and 66 .NET tests passed**. Existing TRX handling, credential redaction, pinned Docker profiles, canonical state, and diff-bound approval were retained rather than replaced.

The additional functional defects were:

- **Incorrect manifest discovery.** `discoverProjectManifests` returns repository-relative paths, but `inspectDotnetProjects` read them relative to the extension process directory. Test projects could appear absent while a solution or old TestResults directory incorrectly counted as a suite. Reads now resolve against the selected repository. A solution alone no longer counts as tests. No test project produces an explicit UNTESTED/TEST_PROJECT_NOT_FOUND record, without fake execution.
- **Offline test metadata lost at the worktree boundary.** Direct Docker testing of PaymentsAPI could work while a fresh Git worktree lacked ignored restore files. The isolated manager now copies only allowlisted NuGet restore manifests into existing project directories. Compiled output and arbitrary obj contents are excluded. The existing Docker staging rebases NuGet roots to its read-only package cache. No package download or network exception was added.
- **The approved diff was not the actual edit channel.** Stage 5 previously wrote the model's separate full-file response; the post-apply check primarily compared filenames. Stage 4 now checks that the real unified diff applies, and Stage 5 applies that exact diff using a fixed `git apply` invocation, without a shell. Parallel full-file model responses are ignored. The proposal records its base target hash; source drift invalidates approval. A changed run/diff requires new local consent.
- **019 was a scanner false positive, not merely unexplained stale state.** SEC-003's case-insensitive `DES.Create` pattern also matched the prefix of `des.CreateEncryptor`. A method-call boundary now distinguishes these calls. Scanner version is 1.3.1. The genuine DES.Create match remains at line 9; the duplicate line-10 finding is rejected by fresh source validation. This corrects the earlier report's less precise stale-evidence assessment.
- **Enterprise crypto migration policy blocked a disposable development experiment.** Enterprise behavior remains manual for the high-blast-radius crypto route. Explicitly enrolled local disposable application code may reach proposal review; ownership restrictions, exact approval, tests, and re-scan still apply. This permits testing a migration; it does not certify existing encrypted-data compatibility.
- **No explicit development policy or bounded baseline exception.** There is now an opt-in mode, explicit repository enrollment, a separate baseline acknowledgement action, and development-specific conclusions. Failed assertions, compiler errors, sandbox blocks, and cancellations/timeouts cannot use that exception.
- **Missing scan evidence could leave the combined test/re-scan stage completed.** Stage 6 now needs passing tests and the expected scanner's RESOLVED result. Missing execution or scan evidence leaves the stage blocked. A genuine failed test remains failed and requires review/revision.
- **Cancellation was not wired through the pipeline.** A run-owned cancellation bridge now forwards VS Code cancellation to the model and owned Docker test operations, disposes listeners, prevents pre-cancelled container launches, and supports an explicit Cancel Active Remediation command. Retry retains the approved patch only when the existing execution checks allow it.
- **Authorization queue used legacy review prose.** The queue now uses canonical baseline eligibility plus the actual proposed diff digest. Review text alone cannot create an actionable approval card. Copilot and Webview consume the same run identity, stage statuses, validation, scan, and local outcome.
- **SQL construction was being treated too readily as execution evidence.** Source metadata now distinguishes query construction from an observed command execution and checks that parameter binding belongs to the executing command receiver. This remains a syntactic heuristic. Local SQL runs lacking execution evidence cannot claim COMPLETED_VERIFIED merely because a scanner pattern disappears.

## 2. Using LOCAL_DEVELOPMENT

Start the extension host with `GCAC_EXECUTION_MODE=LOCAL_DEVELOPMENT`. The default is ENTERPRISE. Invalid modes fail closed. Local mode is rejected when `NODE_ENV` or `GCAC_DEPLOYMENT_ENV` declares production/prod.

Then use **GCAC: Register Trusted Disposable Development Repository**. Registration requires Workspace Trust and an explicit modal acknowledgement that the selected repository is trusted and disposable. Enrollment is stored in `.gcac/local-repositories.json`, under its canonical repository path. Automatic scan discovery and enterprise repository mappings do not confer development enrollment. Sensitive home/system/credential roots remain rejected. The Webview visibly labels LOCAL_DEVELOPMENT.

For missing baseline tests, use the labelled button in test evidence or **GCAC: Acknowledge Development Baseline Exception**. It shows the actual constraint and asks for a separate acknowledgement and rationale. The acknowledgement is bound to the run and baseline record, and prior evidence is archived. It resumes proposal generation; it does not apply a patch or change UNTESTED into PASS.

Stage 4 opens the actual proposed diff and requests explicit native local consent naming the finding, run, and SHA-256. The engine checks those values again before application. Local consent records AUTHENTICATION_NOT_VERIFIED; no SSO, independent enterprise identity, or signature is claimed. Stage 8 is DEFERRED_IN_DEV_MODE.

Stage 9/run conclusions distinguish:

| Local outcome | Meaning |
| --- | --- |
| COMPLETED_VERIFIED | Required local technical tests, re-scan, and security outcome passed without a baseline exception or identified verification limitation. Formal enterprise closure remains deferred. |
| COMPLETED_WITH_LIMITATIONS | The controlled local workflow ended, but specified verification evidence is missing. This is not verified remediation. Missing stages remain blocked/unexecuted. |
| FAILED | A genuine assertion, execution, patch, or security failure occurred. Diagnostics and revision/retry policy remain visible. |
| BLOCKED | Required safety, source, enrollment, toolchain, or execution prerequisites prevent progress. Later stages are not marked completed. |

ENTERPRISE policy remains available. Local mode does not activate publication, PR creation, push, merge, or formal closure.

## 3. Enterprise controls deferred and safety retained

Local development does not require enterprise SSO/Entra, authenticated independent review, branch protection, enterprise PR authorization for local fixture work, SIEM/compliance ingestion, external immutable evidence storage, final enterprise sign-off, or formal vulnerability closure. Several of these integrations were already optional or absent; no new pretend implementations were added. Local evidence files and tamper-detection remain useful without claiming external immutability.

The following remain enforced:

- Known credentials are locally redacted before the unchanged outbound gate; residual unsafe context still blocks. Original values are unnecessary for classification. Native Copilot tools remain outside extension interception.
- Application-controlled build/test operations use approved pinned Docker images, offline policy, dropped capabilities, bounded mounts/resources, and owned cleanup. No host-shell build/test fallback, image auto-pull, or unsupported image enablement was added.
- Registered path containment, file ownership, symlink restrictions, protected policy files, test-weakening checks, and isolated worktrees remain enforced.
- Only the reviewed exact diff is applied. Drift, changed hashes, expired/replayed approval, and out-of-scope changes remain blocked. Local consent is not enterprise authentication.
- Test counts and artifacts come from actual execution. Missing tests, missing scanners, cancellation, failed assertions, and incomplete evidence cannot become a fake PASS or verified resolution.
- Original vulnerable fixtures remain unchanged. Only disposable integration repositories receive test patches. Temporary Git commits in the verifier construct disposable test fixtures; no commit, push, or merge was made in the working repository.

## 4. Current 016–020 source verification

Fresh local rule execution is saved in `evidence/function-first/current-findings.json`. No original credential values are included.

| Finding | Provenance | Current evidence and action |
| --- | --- | --- |
| SCAN-SECRET-016 | secrets-config / SEC-005 / CWE-89 | Line 15 concatenates request.AccountId into SQL. The method constructs a SqlCommand but does not execute it. This supports an unsafe-construction finding, not a proven executing injection path. No database-backed remediation is claimed. |
| SCAN-SECRET-017 | secrets-config / SEC-004 / CWE-78 | Line 9 interpolates receiptId into cmd.exe arguments. The shell-invocation pattern is real. Functional Windows command behavior is not proven by a Linux test. |
| SCAN-SECRET-018 | secrets-config / SEC-003 / CWE-327 | DES.Create at line 9 is genuinely matched. This is the disposable integration target. |
| SCAN-SECRET-019 | secrets-config / SEC-003 / CWE-327 | Old line-10 match came from the CreateEncryptor prefix bug. It no longer matches in scanner 1.3.1. Refresh the normal scan/store before treating the old record as current; no historic finding was silently closed. |
| SCAN-SECRET-020 | secrets-config / SEC-001 / CWE-798 | The credential rule remains genuine. Existing redaction/gate tests verify safe context construction with synthetic values. No original value is exported. Provider revocation/rotation remains a real-world operator action. |

Classification preserves scanner rule IDs and authoritative CWE while recording conflicting model advice. A known secrets-config rule must match the actual isolated source location before a local proposal is generated. Source drift from the selected repository also blocks and asks for a fresh clean snapshot/scan.

## 5. Real technical end-to-end evidence

Run `node scripts/verify-function-first.js` with Docker available and the approved .NET 10 image/package cache already provisioned. It creates disposable copies of PaymentsAPI, includes genuine security tests, constructs temporary Git baselines, enrolls only those disposable repositories, and removes them after evidence collection.

**Provider boundary:** the verifier uses explicitly labelled AUTHORED_TEST_FIXTURE_NOT_COPILOT proposals/reviews and AUTOMATED_TEST_CONSENT_NOT_HUMAN consent. It verifies the production engine's technical stages and consent binding. It does not impersonate a human, call a live Copilot model, or establish that an interactive model/consent session passed.

Actual operations include scanner execution, source checks, exact-diff preflight/application, Docker compilation/xUnit, fresh TRX extraction, real targeted re-scan, canonical outcomes, and cancellation of an owned Docker child followed by authorized retry. The original sample remains vulnerable and unchanged.

| Scenario | Baseline | Post-fix tests | Actual re-scan | Local conclusion |
| --- | --- | --- | --- | --- |
| Correct authenticated AES-GCM change | 3 executed, 2 failed security assertions | 3 executed, 0 failed | RESOLVED | COMPLETED_VERIFIED |
| Defective AES-CBC substitution | 3 executed, 2 failed | 3 executed, 2 failed | REGRESSION_DETECTED | FAILED |
| No test project | UNTESTED, 0 executed; separate test acknowledgement required | UNTESTED, 0 executed | NOT_VERIFIED | COMPLETED_WITH_LIMITATIONS; Stages 6/7 blocked |
| Cancel and retry | 3 executed, 2 failed | Real Docker operation CANCELLED; retry then 3 executed, 0 failed | RESOLVED after retry | COMPLETED_VERIFIED after retry; attempt history and approved digest retained |

The added C# security tests verify AES-256 authenticated round-trip behavior and rejection of tampered ciphertext. They are compiled only into the disposable proof copies. The existing PaymentsAPI test is also executed. The defective patch compiles and removes the original scanner signature but fails those security tests; it cannot become verified remediation.

Artifacts under `evidence/function-first/` include per-scenario summaries, actual baseline/post-fix JSON/TRX, the test-consented patch, and re-scan results. The aggregate summary contains actual run IDs. Cancellation evidence explicitly identifies the local-container backend and retry eligibility. The unit/security suites separately exercise redaction, stale source rejection, unsupported/template toolchains, missing scanners, untrusted enrollment, production-mode rejection, changed diffs, and fake review prose.

## 6. Automated validation

Final results and commands are recorded in `evidence/function-first/regression-summary.json`.

- Initial baseline: 22 extension suites passed; 66 .NET tests passed.
- Final integrated extension run: 23 suites, including new local-mode/patch/discovery/SQL/cancellation policy checks and existing security suites.
- Final .NET run: 66 tests. The final invocation used the unchanged assemblies from the initial build with `--no-build --no-restore`.
- Four real disposable technical integration scenarios passed their expected-result assertions. An expected failing remediation remains FAILED; passing the verifier does not turn that scenario into a successful remediation.
- JavaScript syntax checks and `git diff --check` were run.

The initial environment requires approved Docker socket and test-host IPC access. Approved reruns succeeded. No persistent missing infrastructure prevents these Docker/.NET scenarios. A live signed-in VS Code Copilot provider and actual developer consent interactions remain external to this terminal proof.

## 7. Files changed in this stabilization batch

New implementation modules: `extension/executionMode.js`, `extension/patchApplication.js`, `extension/findingSourceEvidence.js`, `extension/runCancellation.js`.

Updated implementation: `extension/repositoryContext.js`, `extension/remediationEngine.js`, `extension/isolatedWorkspaceManager.js`, `extension/testRunner.js`, `extension/baselineEligibility.js`, `extension/runStateContract.js`, `extension/reportParser.js`, `extension/copilotOutputFormatter.js`, `extension/extension.js`, `extension/media/dashboard.js`, `extension/sandbox/containerSandboxBackend.js`, `extension/sandbox/trustedExecutionGateway.js`, `extension/scanning/adapters/secretsConfigScanner.js`, and `package.json`.

Validation: `tests/extension/localDevelopment.test.js`, `tests/extension/run-all-tests.js`, mock-contract corrections in `tests/extension/productionStabilization.test.js` and `tests/extension/realWorldUsability.test.js`, `tests/fixtures/payments/LegacyCryptoSecurityTests.cs`, `scripts/verify-function-first.js`, and this report/evidence directory. Mock test-project declarations were corrected for unit backends; they are not presented as genuine live test suites.

Existing uncommitted work, including earlier credential/TRX changes, was preserved. The complete working-tree diff includes changes from before this batch and is not solely this task's output.

## 8. Remaining defects and manual verification

- Live model proposal quality, 020 redaction with the signed-in Copilot provider, actual native consent dialogs, Webview reload, review queue transitions, and Chat/Webview synchronization need the developer's interactive VS Code run. A native Copilot handoff remains AWAITING_VERIFIED_RESULT until actual engine evidence arrives.
- Development enrollment is a local developer attestation, not proof that a repository is non-production. Declared production environments are rejected; incorrectly declared deployments cannot be inferred automatically. The mode defaults off and never grants publication.
- Generated remediation remains scoped to the target file. Cross-file architectural fixes and automatic test-suite redesign are not implemented. Prepare the required security tests in the owned disposable baseline rather than relying on a generic smoke test as security proof.
- Isolated source is a committed Git baseline, with selected offline restore metadata carried over. Target source drift is rejected. Arbitrary WIP source/manifests are not silently committed or made into a new canonical source snapshot. Use a clean disposable snapshot and a fresh scan.
- Repository layouts without a runnable build/test entry point at the selected working root may still require selecting the solution root. Multi-stack/unsupported profiles remain explicit limitations; no arbitrary command runner was introduced.
- No live database exists in the sample fixture, and no approved Windows execution environment was added for cmd.exe. No SQL execution or Windows command-injection remediation is claimed. Single-file receiver matching and regex re-scans are not formal taint or semantic proofs.
- The AES-GCM proof changes the nonce/ciphertext contract. Real callers must use a unique 12-byte nonce per key, retain the tag, and handle legacy encrypted data appropriately. No production encrypted-data migration was performed.
- Secret rotation/revocation cannot be verified by removing a literal or passing unit tests. Local secret outcomes retain explicit limitations until externalization and operator-action evidence are complete.
- The existing lightweight TRX parser and scanner heuristics retain their documented limits. Passing tests and a targeted scan are bounded local evidence, not an application-wide security guarantee.

**Final verdict: PARTIALLY FUNCTIONAL.** The controlled local technical workflow is implemented and exercised with real Docker/test/scan operations. Interactive Copilot generation and real developer approval remain unverified, rather than being replaced with fabricated results. No production readiness, formal closure, publication, push, or merge is asserted.
