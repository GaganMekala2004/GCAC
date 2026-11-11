'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const {
    canonicalizePath,
    inspectRepositoryTarget,
    isUninitializedGitSubmodule,
    discoverProjectManifests,
    RepositoryContextRegistry,
    computeLocalApplicationId,
    validateFindingContextContract
} = require('../../extension/repositoryContext');
const { resolveDotnetProjectFile, hasDotnetPackageDependencies } = require('../../extension/scanning/dotnetProjectLocator');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { DotnetSecurityScanner } = require('../../extension/scanning/adapters/dotnetSecurityScanner');
const { NugetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { CodeQLScanner } = require('../../extension/scanning/adapters/codeqlScanner');
const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { NormalizedFinding, SCANNER_STATUS } = require('../../extension/scanning/findingModel');
const { ReScanVerifier } = require('../../extension/scanning/reScanVerifier');
const {
    FAILURE_CATEGORIES,
    detectRunner,
    parseDotnetOutput,
    parseMavenOutput,
    parseNpmOutput,
    runPostFixTests,
    runBaselineTests
} = require('../../extension/testRunner');
const { RemediationEngine } = require('../../extension/remediationEngine');
const { inferStageStatuses, loadVulnerabilityDetails } = require('../../extension/reportParser');
const { buildCopilotRemediationPrompt, resolveSourceFilePath } = require('../../extension/extension');
const { buildRetryUiState, computeTestEvidenceSummary } = require('../../extension/media/dashboard');
const { OUTCOME_STATUS } = require('../../extension/outcomeContract');
const { SANDBOX_READINESS } = require('../../extension/sandbox/environmentDiscovery');

const workspaceRoot = path.resolve(__dirname, '../..');

function runGit(cwd, args) {
    return execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        shell: false,
        env: {
            ...process.env,
            GIT_AUTHOR_NAME: 'GCAC Test',
            GIT_AUTHOR_EMAIL: 'test@gcac.local',
            GIT_COMMITTER_NAME: 'GCAC Test',
            GIT_COMMITTER_EMAIL: 'test@gcac.local',
            GIT_TERMINAL_PROMPT: '0',
            GCM_INTERACTIVE: 'never'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
}

function initDisposableGitRepo(repoDir, files = {}, branchName = 'main') {
    fs.mkdirSync(repoDir, { recursive: true });
    runGit(repoDir, ['init', '-b', branchName]);
    for (const [relPath, content] of Object.entries(files)) {
        const full = path.join(repoDir, relPath);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content, 'utf8');
    }
    if (Object.keys(files).length > 0) {
        runGit(repoDir, ['add', '-A']);
        runGit(repoDir, ['commit', '-m', 'Initial commit']);
    }
    return canonicalizePath(repoDir);
}

async function run() {
    console.log('[TEST SUITE] Real-World Usability, Scan Accuracy, External Repos & Retry Tests');
    const tmpBase = canonicalizePath(fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-rwu-')));

    try {
        // =====================================================================
        // BLOCK A — Scan Accuracy, Empty Input Handling & False-Positive Controls
        // =====================================================================
        {
            const emptyRepo = path.join(tmpBase, 'empty-repo');
            fs.mkdirSync(emptyRepo, { recursive: true });

            const emptySourceRepo = path.join(tmpBase, 'empty-files-repo');
            fs.mkdirSync(path.join(emptySourceRepo, 'src'), { recursive: true });
            fs.writeFileSync(path.join(emptySourceRepo, 'src', 'Empty.cs'), '', 'utf8');
            fs.writeFileSync(path.join(emptySourceRepo, 'src', 'Whitespace.json'), '   \r\n\t  ', 'utf8');
            fs.writeFileSync(path.join(emptySourceRepo, 'src', 'NoDeps.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                'utf8');

            assert.strictEqual(hasDotnetPackageDependencies(path.join(emptySourceRepo, 'src', 'NoDeps.csproj')), false,
                'Manifest without PackageReference/PackageVersion must report no dependencies');

            const secrets = new SecretsConfigScanner();
            const dotnet = new DotnetSecurityScanner();
            const nuget = new NugetAuditScanner();
            const codeql = new CodeQLScanner();

            // A1 & A2: Scanners must return NO_SCANNABLE_INPUTS on empty repos / empty manifests
            const secEmptyRes = await secrets.scan(tmpBase, emptyRepo);
            assert.strictEqual(secEmptyRes.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(secEmptyRes.findings.length, 0);

            const secBlankFile = await secrets.scan(tmpBase, path.join(emptySourceRepo, 'src', 'Empty.cs'));
            assert.strictEqual(secBlankFile.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(secBlankFile.findings.length, 0);

            const nugetNoDeps = await nuget.scan(tmpBase, emptySourceRepo);
            assert.strictEqual(nugetNoDeps.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(nugetNoDeps.findings.length, 0);

            const dotnetEmpty = await dotnet.scan(tmpBase, emptyRepo);
            assert.strictEqual(dotnetEmpty.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(dotnetEmpty.findings.length, 0);

            assert.strictEqual(codeql._detectLanguage(emptyRepo), null,
                'CodeQL _detectLanguage must return null on empty repo without C# fallback');

            // A3: Real gitlink inside parent workspace & simulated submodule pointer must not escape
            const parentWithSubmodule = initDisposableGitRepo(path.join(tmpBase, 'parent-ws'), {
                'Root.sln': 'Microsoft Visual Studio Solution File'
            });
            fs.mkdirSync(path.join(parentWithSubmodule, 'sample-repos', 'uninit-sub'), { recursive: true });
            const headSha = runGit(parentWithSubmodule, ['rev-parse', 'HEAD']);
            runGit(parentWithSubmodule, ['update-index', '--add', '--cacheinfo', `160000,${headSha},sample-repos/uninit-sub`]);

            assert.strictEqual(
                isUninitializedGitSubmodule(path.join(parentWithSubmodule, 'sample-repos', 'uninit-sub'), parentWithSubmodule),
                true,
                'Uninitialized gitlink submodule (160000 with empty checkout) must be flagged'
            );
            const paymentsSampleDir = path.join(workspaceRoot, 'sample-repos', 'payments-api');
            if (fs.existsSync(paymentsSampleDir) && fs.readdirSync(paymentsSampleDir).length === 0) {
                assert.strictEqual(
                    isUninitializedGitSubmodule(paymentsSampleDir, workspaceRoot),
                    true,
                    'Uninitialized GCAC sample-repos/payments-api gitlink must be flagged'
                );
            }
            assert.strictEqual(
                resolveDotnetProjectFile(parentWithSubmodule, path.join(parentWithSubmodule, 'sample-repos', 'uninit-sub')),
                null,
                'Dotnet project locator must never climb out of directory target into parent GCAC root'
            );

            // A4: ScanController on empty/submodule/unsupported & failing scanner coverage honesty
            const storeDir = path.join(tmpBase, 'store-a');
            const store = new FindingsStore(parentWithSubmodule, storeDir);
            const ctrl = new ScanController(parentWithSubmodule, { findingsStore: store, isWorkspaceTrusted: true });

            const emptyScan = await ctrl.startScan({
                targetRepo: path.join(parentWithSubmodule, 'sample-repos', 'uninit-sub'),
                scannerIds: ['secrets-config', 'dotnet-security', 'nuget-audit', 'codeql']
            });
            assert.strictEqual(emptyScan.findingsSummary.total, 0);
            assert.strictEqual(emptyScan.status, 'No Scannable Inputs');

            // Unsupported Python-only repository
            const pyRepo = path.join(parentWithSubmodule, 'py-only');
            fs.mkdirSync(pyRepo, { recursive: true });
            fs.writeFileSync(path.join(pyRepo, 'app.py'), 'print("hello")\n', 'utf8');
            const pyInspect = inspectRepositoryTarget(pyRepo, parentWithSubmodule);
            assert.strictEqual(pyInspect.supported, false);
            assert.strictEqual(pyInspect.detectedTechnology, 'python');

            // Failing scanner must mark unverifiedCoverage rather than reporting clean pass
            ctrl.scanners.set('failing-adapter', {
                id: 'failing-adapter',
                name: 'Failing Mock',
                version: '1.0',
                scan: async () => ({
                    status: SCANNER_STATUS.FAILED,
                    findings: [],
                    errors: ['Analyzer crashed with exit 2'],
                    warnings: [],
                    durationMs: 5
                })
            });
            const failScan = await ctrl.startScan({ targetRepo: pyRepo, scannerIds: ['failing-adapter'] });
            assert.strictEqual(failScan.unverifiedCoverage, true);
            assert.strictEqual(failScan.status, 'Failed');

            // A5: Cross-repo stale finding isolation
            const repoAlpha = initDisposableGitRepo(path.join(tmpBase, 'repo-alpha'), {
                'appsettings.json': JSON.stringify({ Auth: { ApiKey: ['sk', 'live', 'AlphaSecretKey9988776655443322'].join('_') } })
            });
            const repoBeta = initDisposableGitRepo(path.join(tmpBase, 'repo-beta'), {
                'Clean.cs': 'public class Clean { public int Add(int a, int b) => a + b; }\n'
            });

            ctrl.addAuthorizedRoot(repoAlpha);
            ctrl.addAuthorizedRoot(repoBeta);
            const resAlpha = await ctrl.startScan({ targetRepo: repoAlpha, scannerIds: ['secrets-config'] });
            assert.strictEqual(resAlpha.findingsSummary.total, 1);

            const resBeta = await ctrl.startScan({ targetRepo: repoBeta, scannerIds: ['secrets-config'] });
            assert.strictEqual(resBeta.findingsSummary.total, 0);
            assert.strictEqual(store.getFindings({ repositoryRoot: repoBeta, includeHistorical: false }).length, 0,
                'Repo Alpha findings must never appear as fresh findings in Repo Beta');
            assert.strictEqual(store.getFindings({ repositoryRoot: repoAlpha, includeHistorical: false }).length, 0,
                'Previous repository findings become historical after fresh workspace/other-repo scan');
            assert.strictEqual(store.getFindings({ includeHistorical: true }).some(f => f.isHistorical), true,
                'Historical findings must be preserved with isHistorical=true rather than discarded');

            // A6: Comments/placeholders ignored & heuristic SEC-006 labeled clearly & NuGet no fabricated fixedVersion
            const fpRepo = path.join(tmpBase, 'false-positive-repo');
            fs.mkdirSync(fpRepo, { recursive: true });
            fs.writeFileSync(path.join(fpRepo, 'cfg.json'), JSON.stringify({
                Note: '@Microsoft.KeyVault(SecretUri=https://vault/secret)',
                EnvToken: '${MY_RUNTIME_SECRET_TOKEN_VALUE}',
                DevToken: 'token: "AbCdEfGhIjKlMnOpQrStUvWxYz123456"'
            }, null, 2), 'utf8');
            const fpScan = await secrets.scan(tmpBase, fpRepo);
            assert.strictEqual(fpScan.findings.some(f => f.ruleId === 'SEC-001'), false, 'Placeholder KeyVault/env refs must not trigger SEC-001');
            const heurFinding = fpScan.findings.find(f => f.ruleId === 'SEC-006');
            if (heurFinding) {
                assert.strictEqual(heurFinding.detectionMethod, 'HEURISTIC_PATTERN');
                assert.strictEqual(heurFinding.severity, 'Low');
                assert.strictEqual(heurFinding.confidence, 'Low');
            }

            const nugetSampleOut = JSON.stringify({
                version: 1,
                projects: [{
                    path: path.join(tmpBase, 'App.csproj'),
                    frameworks: [{
                        framework: 'net8.0',
                        topLevelPackages: [{
                            id: 'Newtonsoft.Json',
                            resolvedVersion: '12.0.1',
                            vulnerabilities: [{
                                severity: 'High',
                                advisoryurl: 'https://github.com/advisories/GHSA-5crp-9r3c-p9vr'
                            }]
                        }]
                    }]
                }]
            });
            const parsedNuget = nuget.parseJsonAuditOutput(nugetSampleOut, path.join(tmpBase, 'App.csproj'), tmpBase, 'SCAN-NUGET-1');
            assert.strictEqual(parsedNuget.length, 1);
            assert.strictEqual(parsedNuget[0].packageName, 'Newtonsoft.Json');
            assert.strictEqual(parsedNuget[0].currentVersion, '12.0.1');
            assert.strictEqual(parsedNuget[0].fixedVersion, '', 'NuGet adapter must never invent unverified fixedVersion');
            assert.strictEqual(parsedNuget[0].ruleId, 'GHSA-5CRP-9R3C-P9VR', 'NuGet advisory ID must come from genuine advisory URL');

            // A7: ReScanVerifier treats NO_SCANNABLE_INPUTS (emptied file) as INCONCLUSIVE, never RESOLVED
            const emptiedTarget = path.join(tmpBase, 'Emptied.cs');
            fs.writeFileSync(emptiedTarget, '   \n', 'utf8');
            const emptyRescanMock = {
                scanners: new Map([['secrets-config', secrets]])
            };
            const verifier = new ReScanVerifier(emptyRescanMock);
            const rescanRes = await verifier.verifyRemediation({
                originalFinding: {
                    Vulnerability_ID: 'SCAN-SEC-EMPTY-1',
                    Scanner_ID: 'secrets-config',
                    Rule_ID: 'SEC-003',
                    Location_Path: 'Emptied.cs'
                },
                targetFilePath: emptiedTarget,
                workspaceRoot: tmpBase,
                postFixTestResult: { passed: true, totalTests: 2 }
            });
            assert.strictEqual(rescanRes.isResolved, false, 'Emptied target file must never yield RESOLVED');
            assert.strictEqual(rescanRes.machineStatus, OUTCOME_STATUS.INCONCLUSIVE);

            console.log('  ✓ Block A: Empty inputs, uninitialized submodules, cross-repo isolation, heuristics & NuGet provenance verified');
        }

        // =====================================================================
        // BLOCK B — External Repository Portability & Containment (Cases B–G)
        // =====================================================================
        {
            const hostWs = path.join(tmpBase, 'gcac-host-ws');
            fs.mkdirSync(hostWs, { recursive: true });
            const registry = new RepositoryContextRegistry({ workspaceRoot: hostWs, extensionRoot: workspaceRoot });

            // B & F: Separate external .NET repo outside GCAC with spaces in path on 'master' branch
            const extDotnetDir = initDisposableGitRepo(path.join(tmpBase, 'external dotnet repo'), {
                'Service.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                'Controllers/OrderController.cs': 'using System.Security.Cryptography;\npublic class OrderController { public object Hash() => DES.Create(); }\n',
                'Controllers/WipController.cs': '// original\n'
            }, 'master');

            // External uncommitted change in unrelated WIP file must remain preserved
            fs.writeFileSync(path.join(extDotnetDir, 'Controllers', 'WipController.cs'), '// developer local uncommitted wip\n', 'utf8');

            // C: Separate external Java/Maven repo
            const extMavenDir = initDisposableGitRepo(path.join(tmpBase, 'external-java-service'), {
                'pom.xml': '<project><modelVersion>4.0.0</modelVersion><groupId>com.ext</groupId><artifactId>svc</artifactId><version>1.0</version></project>',
                'src/main/java/App.java': 'public class App { String k = "dummy"; }\n'
            }, 'main');

            // F & C: External discovery & runner detection
            const dotnetInspect = inspectRepositoryTarget(extDotnetDir, hostWs, registry);
            assert.strictEqual(dotnetInspect.supported, true);
            assert.strictEqual(dotnetInspect.detectedTechnology, 'dotnet');
            const mavenInspect = inspectRepositoryTarget(extMavenDir, hostWs, registry);
            assert.strictEqual(mavenInspect.supported, true);
            assert.strictEqual(mavenInspect.detectedTechnology, 'java-spring');
            assert.strictEqual(detectRunner({}, extMavenDir).tool, 'mvn');
            assert.strictEqual(detectRunner({}, extDotnetDir).tool, 'dotnet');

            // Register external repos locally -> deterministic LOCAL-<8hex> (no APP-* invention)
            const localReg = registry.resolveOrRegisterRepository(extDotnetDir);
            assert.strictEqual(localReg.applicationNumber, computeLocalApplicationId(extDotnetDir));
            assert(localReg.applicationNumber.startsWith('LOCAL-'), 'Local repo identity must use deterministic LOCAL-<hash>');
            assert.strictEqual(localReg.identitySource, 'LOCAL_REGISTERED_REPOSITORY');

            // B: Scan external repo via ScanController with explicit authorizedRoot
            const extStore = new FindingsStore(hostWs, path.join(hostWs, 'output', 'scans'));
            const extCtrl = new ScanController(hostWs, {
                findingsStore: extStore,
                registry,
                authorizedRoots: [hostWs, extDotnetDir],
                isWorkspaceTrusted: true
            });
            const extScan = await extCtrl.startScan({ targetRepo: extDotnetDir, scannerIds: ['secrets-config'] });
            assert.strictEqual(extScan.findingsSummary.total, 1, 'External .NET repo with spaces must be scanned cleanly');
            const extFinding = extScan.newFindings[0];
            assert.strictEqual(extFinding.applicationNumber, localReg.applicationNumber);
            assert.strictEqual(canonicalizePath(extFinding.repositoryRoot), extDotnetDir);
            assert.strictEqual(extFinding.technology, 'dotnet');

            // Resolve file strictly inside external authorized repo vs unauthorized outside path
            const resolvedExt = resolveSourceFilePath(hostWs, extDotnetDir, 'Controllers/OrderController.cs', [hostWs, extDotnetDir]);
            assert.strictEqual(canonicalizePath(resolvedExt), canonicalizePath(path.join(extDotnetDir, 'Controllers', 'OrderController.cs')));

            const unauthorizedDir = path.join(tmpBase, 'unauthorized-outside-repo');
            initDisposableGitRepo(unauthorizedDir, { 'App.cs': 'public class App {}' });
            await assert.rejects(
                () => extCtrl.startScan({ targetRepo: unauthorizedDir }),
                /outside authorized workspace/i,
                'Unauthorized external directory must be rejected'
            );

            // Restricted mode enforcement
            extCtrl.setWorkspaceTrust(false);
            await assert.rejects(
                () => extCtrl.startScan({ targetRepo: extDotnetDir }),
                /untrusted/i,
                'Untrusted workspace must block scanning'
            );

            console.log('  ✓ Block B: External .NET/Java repos, spaces in path, multi-root containment & trust checks verified');
        }

        // =====================================================================
        // BLOCK C — Scan-to-Copilot Metadata Mapping (SCAN-NUGETA-003 Reproduction)
        // =====================================================================
        {
            const mapWs = path.join(tmpBase, 'mapping-ws');
            const extPkgRepo = initDisposableGitRepo(path.join(tmpBase, 'nuget-ext-repo'), {
                'App.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>'
            });
            const reg = new RepositoryContextRegistry({ workspaceRoot: mapWs, extensionRoot: workspaceRoot });
            const store = new FindingsStore(mapWs, path.join(mapWs, 'output', 'scans'));

            // Reproduce exact reported failure: ingest 3 NuGet findings where #3 gets ID 'SCAN-NUGETA-003' with missing metadata
            const mkNuget = (pkgName) => new NormalizedFinding({
                scanId: 'SCAN-999',
                scannerId: 'nuget-audit',
                ruleId: 'NUGET-HIGH',
                title: `Vulnerable Package: ${pkgName} 12.0.1`,
                severity: 'High',
                cwe: 'CWE-1395',
                filePath: `pkg/${pkgName}.csproj`,
                rawCodeContext: pkgName,
                packageName: pkgName,
                currentVersion: '12.0.1',
                applicationNumber: '',
                repository: '',
                repositoryRoot: ''
            });
            store.ingestFindings([mkNuget('PkgA'), mkNuget('PkgB'), mkNuget('Newtonsoft.Json')]);
            const brokenNugetFinding = store.getFindingById('SCAN-NUGETA-003');
            assert.ok(brokenNugetFinding, '3rd NuGet finding must receive ID SCAN-NUGETA-003');

            const brokenEngine = new RemediationEngine(mapWs, null, {
                findingsStore: store,
                registry: reg,
                authorizedRoots: [mapWs]
            });

            await assert.rejects(
                () => brokenEngine.executePipeline('SCAN-NUGETA-003'),
                /SEC-02 Blocked: Finding 'SCAN-NUGETA-003' has missing or ambiguous Application_Number\/Repository metadata/
            );

            // Confirm request builder refuses broken finding & never falls back to mapWs or emits 'using scan ""'
            const brokenPromptRes = buildCopilotRemediationPrompt(brokenNugetFinding.toCsvCompatibleRecord(), '', {
                authorizedRoots: [mapWs],
                registry: reg
            });
            assert.strictEqual(brokenPromptRes.ok, false);
            assert.strictEqual(brokenPromptRes.requiresMapping, true);

            // Now bind explicit local repository mapping (deterministic LOCAL-<hash>) and re-verify
            const boundMeta = reg.resolveOrRegisterRepository(extPkgRepo);
            store.updateFindingMapping('SCAN-NUGETA-003', {
                applicationNumber: boundMeta.applicationNumber,
                applicationName: boundMeta.applicationName,
                applicationIdentitySource: boundMeta.identitySource,
                repository: extPkgRepo,
                repositoryRoot: extPkgRepo,
                canonicalRepositoryId: boundMeta.canonicalRepositoryId,
                technology: 'dotnet'
            });

            const mappedRecord = store.getFindingById('SCAN-NUGETA-003').toCsvCompatibleRecord();
            const fixedPromptRes = buildCopilotRemediationPrompt(mappedRecord, '', {
                authorizedRoots: [mapWs, extPkgRepo],
                registry: reg
            });
            assert.strictEqual(fixedPromptRes.ok, true);
            assert(!fixedPromptRes.query.includes('using scan ""'), 'Copilot query must NEVER contain empty using scan ""');
            assert(fixedPromptRes.query.includes('using scan "SCAN-999"'), 'Copilot query must include actual scan execution ID');
            assert(fixedPromptRes.query.includes(extPkgRepo), 'Copilot query must reference mapped external repository path');
            assert.strictEqual(fixedPromptRes.context.contextSchemaVersion, 'GCAC-FINDING-CTX-1.0');
            assert.strictEqual(fixedPromptRes.context.applicationId, boundMeta.applicationNumber);

            // Test each scanner adapter finding through buildCopilotRemediationPrompt
            const adapterIds = ['secrets-config', 'dotnet-security', 'nuget-audit', 'codeql'];
            for (const aid of adapterIds) {
                const sample = new NormalizedFinding({
                    findingId: `SCAN-${aid.toUpperCase()}-100`,
                    scanId: `SCAN-ADAPTER-${aid}`,
                    scannerId: aid,
                    ruleId: 'RULE-1',
                    title: `Sample ${aid} Finding`,
                    severity: 'High',
                    filePath: 'App.csproj',
                    repository: extPkgRepo,
                    repositoryRoot: extPkgRepo,
                    canonicalRepositoryId: boundMeta.canonicalRepositoryId,
                    applicationNumber: boundMeta.applicationNumber
                });
                const promptOut = buildCopilotRemediationPrompt(sample.toCsvCompatibleRecord(), '', {
                    authorizedRoots: [mapWs, extPkgRepo],
                    registry: reg
                });
                assert.strictEqual(promptOut.ok, true, `Adapter ${aid} finding must build valid Copilot prompt`);
                assert(!promptOut.query.includes('using scan ""'));
                assert(promptOut.query.includes(`SCAN-ADAPTER-${aid}`));
            }

            console.log('  ✓ Block C: SCAN-NUGETA-003 reproduction, SEC-02 fail-closed gate & non-empty Copilot scan query verified');
        }

        // =====================================================================
        // BLOCK D — Reliable Test Parsing, Outcome Distinctions & Diagnostics
        // =====================================================================
        {
            // Multi-project dotnet output aggregation
            const multiDotnet = [
                'Passed!  - Failed:     1, Passed:     2, Skipped:     0, Total:     3, Duration: 41 ms - Unit.dll',
                'Passed!  - Failed:     0, Passed:     4, Skipped:     1, Total:     5, Duration: 65 ms - Integration.dll'
            ].join('\n');
            const parsedMultiDotnet = parseDotnetOutput(multiDotnet, 1);
            assert.strictEqual(parsedMultiDotnet.testsPassed, 6);
            assert.strictEqual(parsedMultiDotnet.testsFailed, 1);
            assert.strictEqual(parsedMultiDotnet.testsSkipped, 1);
            assert.strictEqual(parsedMultiDotnet.testsTotal, 8);
            assert.strictEqual(parsedMultiDotnet.countsKnown, true);

            // Maven Surefire aggregate Results wins
            const mavenOut = [
                '[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.1 s - in com.ex.ATest',
                '[INFO] Results:',
                '[INFO]',
                '[ERROR] Tests run: 5, Failures: 1, Errors: 0, Skipped: 1'
            ].join('\n');
            const parsedMvn = parseMavenOutput(mavenOut, 1);
            assert.strictEqual(parsedMvn.testsTotal, 5);
            assert.strictEqual(parsedMvn.testsFailed, 1);
            assert.strictEqual(parsedMvn.testsSkipped, 1);
            assert.strictEqual(parsedMvn.testsPassed, 3);

            // npm / Node test runner output
            const nodeTapOut = 'ℹ tests 4\nℹ pass 3\nℹ fail 1\n';
            const parsedNpm = parseNpmOutput(nodeTapOut, 1);
            assert.strictEqual(parsedNpm.testsTotal, 4);
            assert.strictEqual(parsedNpm.testsPassed, 3);
            assert.strictEqual(parsedNpm.testsFailed, 1);

            // Construct disposable repo + mocked sandbox backend to verify all failure outcomes
            const diagRepo = initDisposableGitRepo(path.join(tmpBase, 'diag-dotnet-repo'), {
                'Diag.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                'TestResults/sample.trx': '<TestRun />'
            });
            const readyEnv = {
                sandboxAvailable: true,
                sandboxStatus: SANDBOX_READINESS.READY,
                selectedRuntime: 'docker',
                os: { platform: 'linux', arch: 'x64' },
                containers: { docker: { installed: true, daemonReachable: true }, podman: { installed: false, daemonReachable: false } }
            };
            const makeMockBackend = (execFn) => ({
                backendType: 'local-container',
                checkAvailability: async () => ({
                    available: true,
                    status: SANDBOX_READINESS.SANDBOX_READY,
                    backendType: 'local-container',
                    runtime: 'docker',
                    architecture: 'x64',
                    linuxContainerMode: true,
                    enforcedBoundaries: ['No network']
                }),
                validatePolicy: () => ({ valid: true }),
                prepareEnvironment: async (req) => ({ instanceId: req.instanceId, workDir: req.approvedWorkspaceReference, staged: {} }),
                executeApprovedOperation: async () => ({ durationMs: 12, ...execFn() }),
                cancelOperation: async () => ({ cancelled: true }),
                collectEvidence: async () => ({}),
                cleanup: async () => ({ cleaned: true })
            });

            const runScenario = async (backendResult, testPhase = 'POST_FIX_TEST') => {
                const mockBackend = makeMockBackend(() => backendResult);
                const fn = testPhase === 'BASELINE_SECURITY_TEST' ? runBaselineTests : runPostFixTests;
                return await fn(
                    { Vulnerability_ID: 'VUL-DIAG-1', Technology: 'dotnet', Repository: diagRepo },
                    diagRepo,
                    {
                        workingDirectory: diagRepo,
                        repositoryTested: diagRepo,
                        runId: `run-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                        applicationId: 'LOCAL-DIAG1',
                        sandboxBackend: mockBackend,
                        envReport: readyEnv
                    }
                );
            };

            // 1. Tests Passed
            const passRes = await runScenario({
                exitCode: 0,
                stdout: 'Passed!  - Failed:     0, Passed:     3, Skipped:     0, Total:     3',
                stderr: ''
            });
            assert.strictEqual(passRes.passed, true);
            assert.strictEqual(passRes.machineStatus, OUTCOME_STATUS.PASSED);

            // 2. Tests Failed (counts known, not retryEligible for blind rerun, baseline vs post-fix distinct)
            const failPostRes = await runScenario({
                exitCode: 1,
                stdout: 'Failed!  - Failed:     1, Passed:     2, Skipped:     0, Total:     3',
                stderr: ''
            }, 'POST_FIX_TEST');
            assert.strictEqual(failPostRes.failureCategory, FAILURE_CATEGORIES.TESTS_FAILED);
            assert.strictEqual(failPostRes.retryEligible, false);
            assert.strictEqual(failPostRes.countsKnown, true);
            assert(failPostRes.testReportLocation && failPostRes.testReportLocation.endsWith('sample.trx'));

            const failBaseRes = await runScenario({
                exitCode: 1,
                stdout: 'Failed!  - Failed:     1, Passed:     2, Skipped:     0, Total:     3',
                stderr: ''
            }, 'BASELINE_SECURITY_TEST');
            assert(failBaseRes.suggestedNextAction.includes('Baseline tests failed prior to patch'));

            // 3. No tests discovered (exit 0 + 0 tests MUST NOT PASS)
            const noTestsRes = await runScenario({
                exitCode: 0,
                stdout: 'Build succeeded. No test is available in Diag.dll.',
                stderr: ''
            });
            assert.strictEqual(noTestsRes.passed, false);
            assert.strictEqual(noTestsRes.failureCategory, FAILURE_CATEGORIES.NO_TESTS_DISCOVERED);
            assert.strictEqual(noTestsRes.machineStatus, OUTCOME_STATUS.UNTESTED);

            // 4. Build failed
            const buildFailRes = await runScenario({
                exitCode: 1,
                stdout: 'Controllers/OrderController.cs(12,5): error CS1002: ; expected\nBuild FAILED.',
                stderr: ''
            });
            assert.strictEqual(buildFailRes.failureCategory, FAILURE_CATEGORIES.BUILD_FAILED);
            assert.strictEqual(buildFailRes.countsKnown, false);
            assert(buildFailRes.rootError.includes('error CS1002'));

            // 5. Restore failed
            const restoreFailRes = await runScenario({
                exitCode: 1,
                stdout: 'error NU1101: Unable to find package Foo.Bar in offline cache.',
                stderr: ''
            });
            assert.strictEqual(restoreFailRes.failureCategory, FAILURE_CATEGORIES.RESTORE_FAILED);
            assert(restoreFailRes.rootError.includes('NU1101'));

            // 6. Test tool missing
            const missingToolRes = await runScenario({
                exitCode: 127,
                stdout: '',
                stderr: 'dotnet: command not found'
            });
            assert.strictEqual(missingToolRes.failureCategory, FAILURE_CATEGORIES.TEST_TOOL_MISSING);

            // 7. Timed out & Cancelled
            const timeoutRes = await runScenario({ exitCode: 124, timedOut: true, stdout: '', stderr: 'timed out' });
            assert.strictEqual(timeoutRes.failureCategory, FAILURE_CATEGORIES.TIMED_OUT);
            assert.strictEqual(timeoutRes.retryEligible, true);

            const cancelRes = await runScenario({ exitCode: 1, cancelled: true, stdout: '', stderr: 'cancelled' });
            assert.strictEqual(cancelRes.failureCategory, FAILURE_CATEGORIES.CANCELLED);
            assert.strictEqual(cancelRes.retryEligible, true);

            // 8. Parse failed
            const parseFailRes = await runScenario({
                exitCode: 2,
                stdout: 'Unexpected runner panic without standard summary line',
                stderr: ''
            });
            assert.strictEqual(parseFailRes.failureCategory, FAILURE_CATEGORIES.PARSE_FAILED);
            assert.strictEqual(parseFailRes.countsKnown, false);

            // 9. SANDBOX_UNAVAILABLE -> fail closed (no host fallback)
            const sbxUnavailEnv = {
                sandboxAvailable: false,
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                selectedRuntime: null,
                os: { platform: 'win32', arch: 'x64' },
                containers: { docker: { installed: false }, podman: { installed: false } },
                prerequisites: ['Install Docker Desktop Linux containers mode or Podman.'],
                boundaryDisclosure: { enforcedBoundaries: [] }
            };
            const sbxUnavailRes = await runPostFixTests(
                { Vulnerability_ID: 'VUL-SBX-0', Technology: 'dotnet', Repository: diagRepo },
                diagRepo,
                { workingDirectory: diagRepo, envReport: sbxUnavailEnv, runId: 'run-sbx-unavail', applicationId: 'LOCAL-1' }
            );
            assert.strictEqual(sbxUnavailRes.executed, false);
            assert.strictEqual(sbxUnavailRes.failureCategory, FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE);
            assert.strictEqual(sbxUnavailRes.sandboxStatus, SANDBOX_READINESS.SANDBOX_UNAVAILABLE);

            // 10. reportParser & dashboard UI pure helpers never fabricate '(0 passed, 0 failed)' and fix testStatus bug
            const reportDetails = {
                hasEvidence: true,
                reportMarkdown: '## Post-Fix Test Validation\n',
                validation: buildFailRes,
                stages: Array.from({ length: 7 }, (_, i) => ({ id: `s${i}`, status: 'pending', summary: '' }))
            };
            inferStageStatuses(reportDetails);
            assert.strictEqual(reportDetails.stages[4].status, 'failed');
            assert(!reportDetails.stages[4].summary.includes('(0 passed, 0 failed)'),
                'reportParser must never emit fake (0 passed, 0 failed) summary on BUILD_FAILED');
            assert(reportDetails.stages[4].summary.includes('CS1002'));

            const uiTestSummary = computeTestEvidenceSummary(buildFailRes, { score: 0 }, null);
            assert.strictEqual(uiTestSummary.statusLabel, 'BUILD FAILED');
            assert.strictEqual(uiTestSummary.countsKnown, false);

            console.log('  ✓ Block D: Multi-project parsing, 10 distinct test outcomes & non-generic diagnostics verified');
        }

        // =====================================================================
        // BLOCK E — Functional Retry Stage, Eligibility, Concurrency & Revise Fix
        // =====================================================================
        {
            const retryWs = initDisposableGitRepo(path.join(tmpBase, 'retry-ws'), {
                'Controllers/OrderController.cs': 'using Microsoft.Data.SqlClient;\npublic class OrderController { public string Find(string q) { var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = \'" + q + "\'"); return cmd.CommandText; } }\n',
                'App.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>'
            });
            fs.mkdirSync(path.join(retryWs, 'vulnerability'), { recursive: true });
            const retryCsv = path.join(retryWs, 'vulnerability', 'vulnerabilities.csv');
            fs.writeFileSync(
                retryCsv,
                'Vulnerability_ID,Application_Number,Application_Name,Title,Detailed_Name,Severity,Technology,Repository,Location_Path,Line_Number,Remediation_Guidance\n' +
                'VUL-RETRY-001,APP-R1,RetryApp,SQL Injection in OrderController,CWE-89 SQL Injection,High,dotnet,.,Controllers/OrderController.cs,2,Use parameterized query\n',
                'utf8'
            );

            let testMode = 'TIMEOUT_BASELINE';
            const readyEnv = {
                sandboxAvailable: true,
                sandboxStatus: SANDBOX_READINESS.READY,
                selectedRuntime: 'docker',
                os: { platform: 'linux', arch: 'x64' },
                containers: { docker: { installed: true, daemonReachable: true }, podman: { installed: false, daemonReachable: false } }
            };
            const readyBackend = {
                backendType: 'local-container',
                checkAvailability: async () => ({
                    available: true,
                    status: SANDBOX_READINESS.SANDBOX_READY,
                    backendType: 'local-container',
                    runtime: 'docker',
                    architecture: 'x64',
                    linuxContainerMode: true,
                    enforcedBoundaries: ['No network']
                }),
                validatePolicy: () => ({ valid: true }),
                prepareEnvironment: async (req) => ({ instanceId: req.instanceId, workDir: req.approvedWorkspaceReference, staged: {} }),
                executeApprovedOperation: async () => {
                    if (testMode === 'TIMEOUT_BASELINE') {
                        return { exitCode: 124, timedOut: true, durationMs: 25, stdout: '', stderr: 'Baseline test timed out' };
                    }
                    if (testMode === 'FAIL_POSTFIX') {
                        return { exitCode: 1, durationMs: 20, stdout: 'Failed! - Failed: 1, Passed: 2, Skipped: 0, Total: 3', stderr: 'Assertion failed in AuthTests' };
                    }
                    return { exitCode: 0, durationMs: 20, stdout: 'Passed! - Failed: 0, Passed: 3, Skipped: 0, Total: 3', stderr: '' };
                },
                cancelOperation: async () => ({ cancelled: true }),
                collectEvidence: async () => ({}),
                cleanup: async () => ({ cleaned: true })
            };

            let patchRevisionCount = 0;
            const mockLlm = {
                getAvailableModels: async () => [{ id: 'mock-gpt', name: 'Mock Copilot', vendor: 'copilot' }],
                generateJson: async (prompt) => {
                    if (prompt.includes('Classification Agent')) {
                        return { cwe: 'CWE-89', severity: 'High', exploitability: 'High', route: 'SpecializedAction', strategy: 'Parameterize SQL query', summary: 'SQLi in OrderController' };
                    }
                    if (prompt.includes('Root Cause Analysis')) {
                        return { dataFlow: 'q -> SqlCommand string concat', rootCause: 'Unparameterized SQL query concatenation', securityImpact: 'Arbitrary SQL execution', proposedFix: 'Use SqlParameter placeholder', affectedLines: 'Line 2', summary: 'Use SqlParameter' };
                    }
                    return { rating: 'PASS', score: 95, summary: 'Verified parameterized SQL patch', auditChecks: ['All tests pass'] };
                },
                generateCompletion: async (prompt) => {
                    patchRevisionCount++;
                    const marker = patchRevisionCount > 1 ? `// revision ${patchRevisionCount}\n` : '';
                    const newCode = `${marker}using Microsoft.Data.SqlClient;\npublic class OrderController { public string Find(string q) { var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = @q"); cmd.Parameters.AddWithValue("@q", q); return cmd.CommandText; } }`;
                    return '```diff\n--- a/Controllers/OrderController.cs\n+++ b/Controllers/OrderController.cs\n@@ -2 +2 @@\n-public class OrderController { public string Find(string q) { var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = \'" + q + "\'"); return cmd.CommandText; } }\n+public class OrderController { public string Find(string q) { var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = @q"); cmd.Parameters.AddWithValue("@q", q); return cmd.CommandText; } }\n```\n```full_code\n' + newCode + '\n```';
                }
            };

            const customRunner = {
                runBaselineTests: async (f, ws, opts) => {
                    if (testMode === 'TIMEOUT_BASELINE') {
                        throw new Error('Baseline runner process timed out after 30000ms');
                    }
                    return await runBaselineTests(f, ws, { ...opts, sandboxBackend: readyBackend, envReport: readyEnv });
                },
                runPostFixTests: async (f, ws, opts) => {
                    return await runPostFixTests(f, ws, { ...opts, sandboxBackend: readyBackend, envReport: readyEnv });
                }
            };

            const engine = new RemediationEngine(retryWs, retryCsv, {
                llmClient: mockLlm,
                testRunner: customRunner,
                sandboxBackend: readyBackend,
                envReport: readyEnv,
                authorizedRoots: [retryWs],
                runsRoot: path.join(tmpBase, 'retry-runs'),
                retryPolicy: { maxRetries: 2, backoffMs: [25, 50] }
            });

            // 1. Trigger transient timeout at Stage 3
            await assert.rejects(() => engine.executePipeline('VUL-RETRY-001'), /timed out/i);

            const failedState = engine.loadRunState('VUL-RETRY-001');
            assert.strictEqual(failedState.status, 'FAILED');
            assert.strictEqual(failedState.failedStage, 3);
            assert.strictEqual(failedState.failureCategory, 'TIMED_OUT');
            assert.strictEqual(failedState.retryEligibility.retryEligible, true);

            // Simulate reload interruption reconciliation on an IN_PROGRESS run
            const interruptedId = 'VUL-RETRY-INT';
            engine.saveRunState(interruptedId, {
                runId: 'run-int-1',
                vulnerabilityId: interruptedId,
                applicationNumber: 'APP-R1',
                stage: 2,
                status: 'IN_PROGRESS',
                findingContext: failedState.findingContext
            });
            const reconciled = engine.reconcileInterruptedRuns();
            assert(reconciled.some(r => r.vulnerabilityId === interruptedId));
            const intLoaded = engine.loadRunState(interruptedId);
            assert.strictEqual(intLoaded.status, 'INTERRUPTED');
            assert.strictEqual(intLoaded.failureCategory, 'INTERRUPTED_BY_RELOAD');

            // Backoff enforcement check (rejectDuringBackoff=true right after failure)
            await assert.rejects(
                () => engine.retryStage('VUL-RETRY-001', 3, { rejectDuringBackoff: true }),
                /Retry Backoff Active/
            );

            // Wait out 30ms backoff & retry Stage 3 cleanly -> preserves Stage 1 & 2, creates attempt #2, archives attempt #1, stops at Stage 4
            testMode = 'PASS_ALL';
            await new Promise(r => setTimeout(r, 40));
            const retryPause = await engine.retryStage('VUL-RETRY-001', 3);
            assert.strictEqual(retryPause.isAwaitingApproval, true, 'Retry from Stage 3 must pause at Stage 4 human gate');
            assert.strictEqual(retryPause.attemptNumber, 2);
            assert.strictEqual(retryPause.attemptHistory.length, 1);
            assert(fs.existsSync(path.join(retryWs, 'remediation-output', retryPause.attemptHistory[0].archiveDir, 'run-state.json')),
                'Prior failure run-state.json must be preserved in attempts archive');

            // Approve Stage 4, simulate genuine Stage 6 post-fix TESTS_FAILED
            testMode = 'FAIL_POSTFIX';
            const postFailRes = await engine.executePipeline('VUL-RETRY-001', { isHumanApproved: true });
            assert.strictEqual(postFailRes.failedStage, 6);
            assert.strictEqual(postFailRes.failureCategory, FAILURE_CATEGORIES.TESTS_FAILED);
            assert.strictEqual(postFailRes.retryEligibility.retryEligible, false,
                'Genuine post-fix TESTS_FAILED must disable blind Retry Stage');
            assert.strictEqual(postFailRes.retryEligibility.canReviseFix, true);

            const uiBlockedState = buildRetryUiState(postFailRes, false);
            assert.strictEqual(uiBlockedState.retryDisabled, true);
            assert.strictEqual(uiBlockedState.canReviseFix, true);

            // Blind retry at Stage 6 must be rejected
            await assert.rejects(
                () => engine.retryStage('VUL-RETRY-001', 6),
                /Retry Blocked/
            );

            // Revise Fix rolls back, creates attempt #3, requires FRESH Stage 4 approval
            testMode = 'PASS_ALL';
            const revisedPause = await engine.reviseFix('VUL-RETRY-001', { developerNotes: 'Include AES disposal note' });
            assert.strictEqual(revisedPause.isAwaitingApproval, true, 'Revise Fix must generate new patch and require fresh Stage 4 approval');
            assert.strictEqual(revisedPause.attemptNumber, 3);
            assert.strictEqual(revisedPause.attemptHistory.length, 2);
            assert.notStrictEqual(revisedPause.proposedDiffSha256, postFailRes.proposedDiffSha256 || '');

            // Concurrency & untrusted checks on UI retry state
            const activeUiState = buildRetryUiState(retryPause, true);
            assert.strictEqual(activeUiState.retryDisabled, true);
            const untrustedCheck = engine.evaluateRetryEligibility('VUL-RETRY-001', { workspaceTrusted: false });
            assert.strictEqual(untrustedCheck.retryEligible, false);

            // Bounded retry limit check (maxRetries=2)
            engine.saveRunState('VUL-MAX-RETRY', {
                runId: 'run-max',
                vulnerabilityId: 'VUL-MAX-RETRY',
                applicationNumber: 'APP-R1',
                stage: 3,
                failedStage: 3,
                status: 'FAILED',
                failureCategory: 'TIMED_OUT',
                retryCount: 2,
                findingContext: failedState.findingContext
            });
            const maxCheck = engine.evaluateRetryEligibility('VUL-MAX-RETRY');
            assert.strictEqual(maxCheck.retryEligible, false);
            assert.strictEqual(maxCheck.reasonCode, 'RETRY_LIMIT_EXCEEDED');

            console.log('  ✓ Block E: Transient retry, attempt archiving, reload recovery, bounded limits & Revise Fix verified');
        }

        // =====================================================================
        // BLOCK G — Dashboard CSP & HTML Hygiene Check
        // =====================================================================
        {
            const dashHtml = fs.readFileSync(path.join(workspaceRoot, 'extension', 'media', 'dashboard.html'), 'utf8');
            const dashJs = fs.readFileSync(path.join(workspaceRoot, 'extension', 'media', 'dashboard.js'), 'utf8');
            assert(!/\sstyle\s*=/i.test(dashHtml), 'dashboard.html must contain zero inline style= attributes');
            assert(!dashJs.includes('testStatus ==='), 'dashboard.js must not reference undefined testStatus variable');
            assert(dashJs.includes('btnReviseFix'), 'dashboard.js must wire Review Failure / Revise Fix handler');
            assert(dashJs.includes('btnMapFindingRepository'), 'dashboard.js must wire Map Repository handler');
            console.log('  ✓ Block G: Dashboard CSP compliance and testStatus ReferenceError fix verified');
        }
    } finally {
        try { fs.rmSync(tmpBase, { recursive: true, force: true }); } catch {}
    }
}

module.exports = { run };
if (require.main === module) {
    run().catch(err => {
        console.error(err);
        process.exit(1);
    });
}
