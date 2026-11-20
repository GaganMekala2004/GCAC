# GCAC capabilities, limits, and adoption guide

**Version 2.0.2 · VS Code Remediation Hub · Reviewed 19 November 2026**

**Best fit today:** a team with a trusted, local Git checkout of a .NET 10 application, repeatable tests, and a developer who can review a focused patch. GCAC can find issues in several other stacks. Its ability to **verify a fix** depends on the target’s build profile, tests, and the scanner that originally reported the issue. The separate prototype CLI and MCP workflows have different entry points. For installation and operating instructions, see the [user manual](SETUP.md).

## How much code can it scan?

**GCAC has no single repository-wide line limit.** A local scan can read thousands of lines across eligible files. The **60-line limit** applies to a developer’s selection for AI review. A file can qualify for scanning and still be too large to send to a model for a patch.

| Operation | Current limit | Developer implication |
| --- | --- | --- |
| Quick Scan | Six built-in secrets and configuration rules. Files over **2 MiB** are skipped. Rules match individual lines in eligible text files. | Scan a file, folder, or repository. Inspect skipped-file warnings. Generated outputs, nested repositories, symlinks, and several file types are excluded from traversal. A pattern split across lines can escape detection. |
| AI candidate review | **1–60 consecutive lines** in one saved file of at most **512 KiB**. | Select the relevant function or block. An AI candidate needs independent confirmation before remediation. |
| Model-assisted remediation | The default outbound gate allows **one referenced file**, **16,000 source characters**, and a **32 KiB prompt** per request. Root-cause analysis takes up to 20 lines on either side of the finding. A patch proposal can include the whole target file. | A short selection with very long lines can hit the character limit. A small defect in a large file can also exceed the proposal limit. Choosing a larger model does not raise GCAC’s limits. |
| CodeQL | One detected language per target per run. Language discovery looks up to **four directory levels below the target**. Database creation and query execution each default to **five minutes**. | In a mixed or deeply nested repository, scan the individual service folders. A timeout leaves coverage incomplete. |
| Public npm advisory lookup | One root `package-lock.json` up to **4 MiB**, with **1–100 distinct eligible public package/version pairs**. | Select the package root. Above 100 pairs the lookup stops. Private and unresolved packages are skipped. |
| Scan scheduling and history | One active scan per controller. Comprehensive Scan runs **two adapters concurrently by default**, with a maximum of three. Local history retains the **20 most recent scan sessions**. | Budget time per repository and retain evidence separately when longer reporting periods matter. |

The project’s historical macOS ARM64 benchmark recorded a **72.51 ms Quick Scan on 601 eligible synthetic files**. That benchmark did not exercise a full build-backed scan or model-assisted remediation. GCAC has no established maximum production repository size or end-to-end throughput commitment. [Benchmark and test conditions](enterprise/stabilization/05_scanner_performance_report.md) · [Scan controller](../extension/scanning/scanController.js) · [Outbound limits](../extension/outboundContextGate.js)

## Which repositories can use it?

Start with a trusted checkout on the extension host. For remediation, the finding must map to the owning repository and to a regular file committed in Git. A fresh run uses the committed baseline in an isolated worktree. Select nested repositories separately.

| Repository | What can scan today | What can reach a verified fix |
| --- | --- | --- |
| **C# / .NET 10** | Built-in patterns, sandboxed Roslyn analysis, NuGet dependency audit, and optional CodeQL. | The best-tested path. Requires the approved Linux SDK image in Docker or Podman, usable dependency assets, tests that execute, and a successful originating-scanner re-scan. |
| **C# / .NET 9** | Sandboxed Roslyn analysis, local patterns and NuGet dependency audit. | Uses the pinned .NET 9 SDK with restored dependencies. Verification also requires runnable project tests. |
| **C# / .NET 8** | Applicable local patterns and CodeQL. A supported, restored package graph can use the offline NuGet audit. | The shipped build profiles contain placeholder image digests. Build-backed verification requires provisioning the correct profile or a reviewed project migration. |
| **Java / Maven** | CodeQL Java queries and applicable configuration-file rules. | A Java 17/Maven profile exists as a template. Provision and validate it before promising build/test-backed fixes. Gradle and Ant have no approved build adapter. |
| **JavaScript / TypeScript / npm** | CodeQL, applicable secrets rules, and opt-in OSV lookup for public npm packages. | The Node 22 build profile is a template. Scanning a lockfile alone cannot establish that an upgrade works with the application. |
| **Python, C/C++, Go** | CodeQL can select these languages when the matching bundle, queries, and extraction prerequisites are available. | The shipped registry has no matching build/test profile. Use findings for developer triage and verify changes through the project’s own validation process. |
| **Mixed repositories, infrastructure, and vendor appliances** | Scan each supported service separately. Supported text and configuration files can still produce findings. | Cross-service changes and operational fixes need an owner. An imported appliance finding can be tracked and referred for patching. Live host, network, and appliance scanning fall outside this extension’s scope. |

CodeQL chooses the first language it recognizes in this order: C#, Java, JavaScript/TypeScript, Python, C/C++, Go. For example, a repository containing a C# API and a TypeScript frontend needs separate service targets to obtain CodeQL results for both. [CodeQL adapter](../extension/scanning/adapters/codeqlScanner.js) · [Shipped toolchain profiles](../extension/config/approved-toolchain-profiles.json)

## Which vulnerabilities can it find and fix?

| Finding family | Detection | Remediation boundary |
| --- | --- | --- |
| Embedded credentials and connection-string passwords | Built-in patterns for common API keys and plaintext database passwords. A separate long-token rule produces a low-confidence lead. | A focused edit can externalize a credential. The service owner must still revoke or rotate any exposed key and verify downstream configuration. |
| SQL injection and shell command injection | Selected C# string-construction patterns, applicable Roslyn diagnostics, and language-specific CodeQL queries. | GCAC can propose parameter binding or safer argument handling. Narrow C# fallback recipes cover recognized source shapes. Application tests must confirm that valid inputs still work. |
| Cross-site scripting and path traversal | Applicable Roslyn diagnostics and CodeQL queries. Coverage depends on the language, framework, and enabled queries. | The engine recognizes both categories and can propose scoped edits. A fix spanning a shared trust boundary or multiple components needs engineering review. |
| Weak cryptography | Known C# patterns such as DES or MD5 and applicable analyzer diagnostics. | Existing ciphertext, caller contracts, keys, and migration plans require owner decisions. The narrow crypto repair recipe requires an acknowledged compatibility contract. |
| Vulnerable dependencies | NuGet checks resolved versions against advisory ranges. The local advisory snapshot expires after **24 hours**. OSV checks approved public npm versions. | A candidate upgrade needs a verified target version, permission to change the manifest, working tests, and a re-scan. Dependency feed failures or an unsupported graph leave coverage incomplete. |
| Other configuration issues and CodeQL findings | Enabled queries or imported reports may identify additional issues. An AI selection can also flag suspected weaknesses. | A scanner rule, imported row, or model suggestion alone cannot establish fixability. Unknown and high-impact changes can end in manual review. |

Use the **scanner name, rule ID, and CWE** when reporting findings. For example, a `SCAN-SECRET` identifier can represent the built-in scanner’s SQL rule. Its prefix alone does not identify a leaked credential. [Built-in rules](../extension/scanning/adapters/secretsConfigScanner.js) · [Roslyn mappings](../extension/scanning/adapters/dotnetSecurityScanner.js) · [Remediation decision logic](../extension/remediationDecisionEngine.js) · [C# repair recipes](../extension/dotnetRepairRecipes.js)

## Features and evidence a team can rely on

- **Discovery and triage.** Quick Scan covers secrets and configuration. Comprehensive Scan runs the selected applicable adapters. The dashboard supports CSV intake, filtering, scan history, cancellation, and fresh scans. Check individual adapter results for skipped inputs and partial coverage.
- **Model choice and data handling.** Teams can use local Ollama, Copilot Chat, OpenAI, Claude, Gemini, Azure OpenAI, or a public OpenAI-compatible endpoint. Direct external APIs use VS Code Secret Storage, repository permission, context screening, and per-request consent. OSV separately asks to disclose public npm package names and versions. Local build containers use offline dependencies.
- **Reviewed changes.** The workflow records the baseline, proposed diff, approval, executed tests, re-scan, and security review. Stage 4 authorizes the proposed patch. Stage 8 provides final sign-off. Supported GitHub publication requires a configured destination, credentials, and approval of the reviewed change.
- **Traceability.** Per-finding artifacts, hashes, and event records let reviewers inspect what changed and what actually ran. Enterprise mode is the default. Local development mode is for enrolled disposable repositories and can report completion with limitations. A developer-mode result does not establish production closure. [Evidence checks](../extension/evidenceChecklist.js) · [Execution modes](../extension/executionMode.js) · [Re-scan outcomes](../extension/scanning/reScanVerifier.js)

## What the results mean for the business

A **finding** is a reason to investigate. A **verified remediation** ties a specific fix to executed tests, the originating scanner’s result, and review evidence. **Production closure** also depends on what happens after GCAC, including merge, deployment, and any required credential rotation or data migration. Assign ownership for those remaining actions.

For a pilot, choose a service with working tests and a team able to review patches. Track **completed scanner runs divided by requested runs**, **verified fixes divided by confirmed findings**, **median time from confirmation to review**, and **manual or blocked cases by reason**. Keep partial scans and skipped files visible. A dashboard showing zero findings after an unavailable scanner gives no assurance about that scanner’s coverage.

Budget for scanner setup, container images, offline dependencies, model usage, and reviewer time. The bundled tests and sample runs support a pilot. Production detection accuracy, false-positive rates, cost per verified fix, and time savings need measurement on the organization’s own repositories.

## Where to expand next

| Priority | Proposed improvement | How to judge success |
| --- | --- | --- |
| 1 | Provision the build/test profile for the highest-volume unsupported stack in the portfolio. | On a representative service, run baseline tests, validate a reviewed fix, and complete the originating-scanner re-scan. Include a deliberately failing patch to verify that the gate catches it. |
| 2 | Add per-project language discovery and a coverage summary for monorepos. | A mixed C#/TypeScript repository reports both services, languages actually analyzed, skipped files, and reasons for incomplete coverage. |
| 3 | Build a capacity and accuracy baseline on representative repositories. | Publish eligible files and lines, cold and cached scan times, peak memory, timeouts, confirmed findings, and reviewer dispositions by scanner. Use those results to set a supportable service target. |
| 4 | Improve large-file remediation and dependency coverage. | Retrieve bounded, relevant source sections for a patch. Add tested support for larger lockfiles or the next package ecosystem. Demonstrate that omitted context and incomplete advisory data remain visible. |
| 5 | Connect technical evidence to delivery reporting. | Link a verified change to its pull request, deployment, and any operational follow-up. Report technical verification and production closure separately. |
