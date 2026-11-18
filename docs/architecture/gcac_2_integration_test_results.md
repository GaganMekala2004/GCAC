# GCAC 2.0 integration evidence

Executed November 18, 2026 on macOS arm64. The extension entry point was extension/extension.js on branch main. Before implementation, Git reported developer changes to remediation-output/VUL-MOCK-NODIFF/run-state.json and the customer-service, gcas-agentic-e2e-test-repo, identity-provider, inventory-manager, payments-api and storefront-api sample repository entries. Regression runs that write fixtures used a disposable local clone populated with copies of the sample repositories.

## Baseline and compatibility gate

The initial plain clone lacked initialized sample Git links. Its npm test result was 27/30 suites, exit 1. With the sample trees present the unchanged baseline passed 30/30, exit 0. The manifest exposed seven commands for opening the dashboard, refreshing data, viewing a diff, scanning a repository, registering a development repository, acknowledging a baseline exception and cancelling remediation. The host also registered openRemediatedSource, reviewCryptoMigration, approveRemediation and approveFinalGate under the gcac prefix.

| Gate | Exact command | Result |
| --- | --- | --- |
| Default participant and handoff | node --test tests/extension/providerCompatibility.test.js | 1/1, exit 0 |
| Existing mocked activation, invocation and security | node tests/extension/phase1Security.test.js | 1 suite, exit 0 |
| Local adapter and proposal contract before external integration | node --test tests/extension/directProviders.test.js | 2/2 at the local gate, 3/3 after adding OpenAI. Final suite includes 8 tests. |
| Optional scanner contracts | node --test tests/extension/optionalDetection.test.js | 2/2, exit 0 |
| Final JS and security regression | npm test | 30/30 original suites and 11/11 provider/detection tests, exit 0 |
| .NET | dotnet test VulnerabilityRemediation.sln | Testhost could not find Microsoft.NETCore.App 9, exit 1 |
| .NET major roll-forward, first attempt | DOTNET_ROLL_FORWARD=Major dotnet test VulnerabilityRemediation.sln --no-build | 63/66. Three MCP tests could not start the server because its project was outside the solution build, exit 1 |
| MCP build and final .NET regression | dotnet build mcp/VulnerabilityDataMcp/VulnerabilityDataMcp.csproj followed by DOTNET_ROLL_FORWARD=Major dotnet test VulnerabilityRemediation.sln --no-build | Build exit 0. Tests 66/66, exit 0, .NET runtime 10.0.14 |

One intermediate JS run returned 29/30 because a test required exactly four registered providers. Its revised assertion checks all four local scanners and that only the two new adapters require opt-in. The final suite includes scope and approval controls, sandbox scenarios, provenance, missing test discovery, stage recovery and canonical outcomes.

## Provider and detection acceptance

All direct workflow scenarios below use a staged copy of the synthetic payments sample, a disposable Git repository and a labelled automated consent fixture. A mismatched run/diff approval must fail before the valid fixture can advance. The original source is checked after execution. Stage 8 is explicitly deferred in this development mode.

| Integration | Evidence and command | Status |
| --- | --- | --- |
| Ollama inference | GCAC_TEST_OLLAMA_MODEL=mistral:latest node --test tests/extension/ollamaLive.test.js | TESTED WITH REAL INFRASTRUCTURE. Installed GGUF model supplied a validated source edit, 1/1, exit 0. The first assertion incorrectly required replacement of a trailing semicolon. The corrected test applies the unique exact edit and verifies the resulting safe statement. |
| Ollama, SQL finding | GCAC_TEST_OLLAMA_MODEL=mistral:latest node scripts/verify-ollama-remediation.js sql | TESTED WITH REAL INFRASTRUCTURE. Exit 0. Mistral handled classification, RCA, edit attempts and review. Three proposals failed exact-edit checks. The existing deterministic .NET repair recipe generated candidate 4. One baseline test failed. The approved candidate compiled, passed 2/2 Docker tests and cleared SEC-005. Local outcome COMPLETED_VERIFIED, finding VERIFIED_LOCALLY, formal closure DEFERRED_IN_DEV_MODE. |
| Earlier failed live remediation | Same workflow harness with an earlier synthetic credential fixture | TESTED WITH REAL INFRASTRUCTURE. A proposed IConfiguration dependency was absent from the project. Docker compilation blocked approval with PROPOSAL_BUILD_FAILED, exit 1. A separate crypto trial correctly required manual migration review before inference. |
| Credential repair | GCAC_TEST_OLLAMA_MODEL=mistral:latest node scripts/verify-ollama-remediation.js | Actual Mistral source patch, 1 baseline failure and 2/2 post-fix passes. SEC-001 cleared. Three outstanding credential lifecycle checks kept the finding open. An initial acceptance assertion expecting COMPLETED_VERIFIED failed. The fixture now checks COMPLETED_WITH_LIMITATIONS and deferred closure. |
| External AI, working edit | GCAC_TEST_OPENAI_FIXTURE=1 node scripts/verify-ollama-remediation.js | TESTED WITH MOCKS for provider, SecretStorage and consent. Real Docker tests, application and scanner. 2/2 post-fix passes, re-scan RESOLVED, operator actions outstanding. Exit 0. |
| External AI, defective edit | GCAC_TEST_OPENAI_FIXTURE=1 node scripts/verify-ollama-remediation.js defective | TESTED WITH MOCKS for inference. The candidate compiled and failed a real assertion. Result FAILED with REGRESSION_DETECTED, exit 0 for the negative test. |
| External AI, no tests | GCAC_TEST_OPENAI_FIXTURE=1 node scripts/verify-ollama-remediation.js missing-tests | Real discovery returned UNTESTED and blocked approval. Exit 0 for the negative test. |
| Provider unavailable | With the test Ollama server stopped, new Ollama().models() was checked with assert.rejects | Actual connection refusal, exit 0 for the negative test. Tests also cover malformed model data, missing models, deadline/cancellation, extra approval fields, auth/policy denials and quota/rate response status. |
| OSV public dependency | GCAC_TEST_OSV=1 node --test tests/extension/osvLive.test.js | TESTED WITH REAL INFRASTRUCTURE. Root npm lockfile fixture for lodash 4.17.20 produced four normalized advisories from api.osv.dev, 1/1, exit 0. |
| AI discovery | node --test tests/extension/optionalDetection.test.js | TESTED WITH MOCKS. Selected-line candidate, source fingerprint, separate scanner identity, unknown severity and rejection of a stale result. Live candidate-review UX remains pending. |

The local SQL acceptance run ID was cc0d4b18-6a82-4e8b-966c-892f61ce013a. Its approved diff SHA-256 was b88186968a4de833e9b4c651a401684caebe7e448732557d51ab2853f5e08ca9. The fixture prints the disposable evidence location for each reproduction. Outputs include machine state, patch attempts, build diagnostics, test results, scanner evidence and the review checklist.

## Distribution

With Node 22.23.5 and @vscode/vsce 3.6.2 on PATH, npm run package:vsix -- --out out/gcac-2.0.0.vsix produced 84 archive entries, 395087 bytes, exit 0. SHA-256 is 447ca5ddc4fc9da8e16eb7a018410421613dff4df7978e2557d48c1078bf0cf1. Archive checks covered CRCs, prohibited paths, model/repository payloads, identifiable developer paths and common credential signatures. VSCE warned that the repository lacks a license file.

VSCODE_CLI points to the installed VS Code CLI. Run bash scripts/verify-installed-extension.sh. The probe installs the VSIX in a fresh isolated profile, activates the installed extension, verifies the real Chat participant API, checks registration of manifest and approval commands, and opens the dashboard. VS Code 1.146.0 on this Mac passed. The first launcher check finished before the renderer flushed its completion log. The reproducible probe waits for that completion marker.

**MANUAL VERIFICATION PENDING** covers authenticated native Copilot Chat, live approved OpenAI inference, an independent human approval/sign-off and installation on another machine. The Host probe uses a disposable trusted workspace and does not exercise live account entitlements. See gcac_2_deferred_manual_acceptance.md.

## Reproducing the checks

Run npm test in a disposable copy that includes initialized sample repository worktrees. On macOS the baseline copy was made with git clone --local and ditto of the local sample trees. Run dotnet test after building the MCP server. SDK/runtime versions matter for its subprocess tests.

For the live model checks, start the approved installed runtime with `OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 ollama serve`. Supply GCAC_TEST_OLLAMA_MODEL explicitly when invoking the tests. The extension and test scripts do not install models. The integration script requires Git, provisioned Docker profiles and the repository’s payments sample. Its generated .NET tests inspect command parameter binding or credential configuration. The SQL fixture does not connect to a database.

To reproduce packaging without changing the runtime dependency tree, install build tools in a disposable prefix with `npm install --prefix "$BUILD_TOOLS" @vscode/vsce@3.6.2 node@22.23.5`, prepend `$BUILD_TOOLS/node_modules/.bin` to PATH and run the package command above. On macOS the acceptance command used was `VSCODE_CLI="/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" bash scripts/verify-installed-extension.sh`.

The final credential run exited 0 with MODEL_PROPOSAL recorded for mistral:latest and diff eca43e945880a1074cc5027b00b5d317723c64758a3b1f3ca03681b503c27f5b. The temporary Ollama server was stopped after testing. The separate out/gcac-2-acceptance.zip contains extracted run summaries and available TRX evidence for six scenarios, including the blocked compiler proposal and missing-tests case. It is outside the VSIX.
