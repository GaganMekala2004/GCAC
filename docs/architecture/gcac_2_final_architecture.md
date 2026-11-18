# GCAC 2.0 architecture

The extension still activates through `extension/extension.js`. Copilot Chat is the default entry point. Native Chat opens with the existing finding, application, repository and scan context. Its handoff remains awaiting verified execution. Direct inference now feeds the same RemediationEngine that the participant invokes.

| Layer | Implementation and ownership |
| --- | --- |
| Developer experience | The existing dashboard HTML and JavaScript add provider configuration, an availability check, a direct run button, OSV and candidate review. The trusted host owns native selection, consent and credentials. |
| Detection | ScanController retains Roslyn/.NET, NuGet, secrets/config and optional CodeQL. The opt-in osv and aiCandidate adapters feed NormalizedFinding and FindingsStore. Deduplication includes repository, scanner and fingerprint. CSV import stays available. No new Java scanner or Excel reader was added. |
| AI gateway | extension/providers contains copilot, host, direct, openai and transport. ProviderHost resolves a run-specific model client. The Copilot LM client filters its fallback discovery by vendor. |
| Orchestration | remediationEngine persists provider and model with the run. Approvals and retries recover the provider from disk. Old records use Copilot. Concurrent runs share the engine’s active-run controls and have independent model clients. |
| Trusted execution | Existing context screening, credential redaction, repository mapping, real worktrees, exact diff approval, compilation, Docker execution and targeted re-scan remain on the host. |
| Evidence and delivery | Canonical state retains classification, RCA, patch, approvals, test and scanner results, review and closure. Valid direct responses contribute operation, provider, model, screened request size and reported usage. The VSIX allowlist includes engine code, Webview assets, trusted agent manifests/instructions and the optional CodeQL setup utility. |

## Lifecycle

1. Intake maps the finding to a registered repository.
2. Classification retains scanner authority.
3. Source analysis and baseline establish the starting evidence.
4. Human approval binds the generated Git diff and run.
5. The engine applies the approved diff in isolation.
6. Bench tests and the originating scanner check the result.
7. Security review considers code and execution evidence.
8. Enterprise sign-off requires a separate decision. Local development records deferral.
9. Closure records the actual validation and finding status.

A completed lifecycle can carry a failed validation, a remaining operator action, or a locally verified fix. Consult the test results for observed examples. The shipped extension has no model weights or runtime npm dependencies.

## Source inventory

| Changed or created | Paths relative to repository root |
| --- | --- |
| Host and inference | extension/extension.js, extension/remediationEngine.js, extension/llmClient.js, extension/credentialRedaction.js, extension/providers/{copilot,direct,host,openai,transport}.js |
| Detection | extension/scanning/{scanController,findingModel,findingsStore}.js, extension/scanning/adapters/{aiCandidate,osv}.js |
| UI and distribution | extension/media/dashboard.{html,js}, package.json, package-lock.json, .vscodeignore, out/gcac-2.0.0.vsix |
| Automated acceptance | tests/extension/{providerCompatibility,directProviders,optionalDetection,ollamaLive,osvLive,scannerAdapters}.test.js, tests/extension/installedHost.js, tests/fixtures/openaiCredentialFixture.js |
| Integration entry points | scripts/verify-ollama-remediation.js, scripts/verify-installed-extension.sh |
| Documentation | The six gcac_2 documents in docs/architecture |

Excel ingestion continues in the separate .NET CLI and Excel library. This VSIX consumes dashboard CSV imports and scanner records. CodeQL remains optional and depends on local provisioning.
