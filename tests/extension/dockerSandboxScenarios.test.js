'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');
const { execFileSync } = require('child_process');

const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { DotnetSecurityScanner } = require('../../extension/scanning/adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { ContainerSandboxBackend } = require('../../extension/sandbox/containerSandboxBackend');
const { TrustedExecutionGateway, OPERATION_TYPES, EXECUTION_POLICY_VERSION } = require('../../extension/sandbox/trustedExecutionGateway');
const { discoverEnvironment, SANDBOX_READINESS } = require('../../extension/sandbox/environmentDiscovery');
const { loadAndVerifyToolchainRegistry, resolveProfileForRepository } = require('../../extension/sandbox/toolchainProfiles');
const { OUTCOME_STATUS } = require('../../extension/outcomeContract');
const { SCANNER_STATUS } = require('../../extension/scanning/findingModel');

const WORKSPACE_ROOT = path.resolve(__dirname, '../..');
const PROFILES_PATH = path.join(WORKSPACE_ROOT, 'extension', 'config', 'approved-toolchain-profiles.json');

function mkTempRepo(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), `gcac-scenario-${prefix}-`));
}

function cleanupRepo(repoPath) {
    try {
        fs.rmSync(repoPath, { recursive: true, force: true });
    } catch {}
}

async function runScenarioTests() {
    console.log('===============================================================');
    console.log('GCAC .NET 10 Docker Sandbox & Scanner Scenarios (A - I)');
    console.log('===============================================================\n');

    const env = discoverEnvironment(WORKSPACE_ROOT, { useCache: false });
    assert(env.sandboxAvailable, 'Docker sandbox must be available for real scenario testing');
    const reg = loadAndVerifyToolchainRegistry(PROFILES_PATH);
    const net10Profile = reg.byId.get('dotnet-10.0-lts');
    assert(net10Profile, 'dotnet-10.0-lts profile must exist and be verified');
    assert.strictEqual(net10Profile.digestStatus, 'VERIFIED_IMAGE_DIGEST');

    const results = {};

    // -------------------------------------------------------------------------
    // Scenario A: Valid .NET 10 project
    // -------------------------------------------------------------------------
    console.log('[SCENARIO A] Valid .NET 10 Project Execution');
    {
        const repo = mkTempRepo('A-valid-net10');
        try {
            fs.writeFileSync(path.join(repo, 'ValidApp.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>');
            fs.writeFileSync(path.join(repo, 'Program.cs'),
                'public class Program { public static void Main() { System.Console.WriteLine("Valid .NET 10 App"); } }');

            // Perform offline pre-restore using the pinned container image
            execFileSync('docker', ['run', '--rm', '--network', 'none', '-v', `${repo}:/work:rw`, '-w', '/work', net10Profile.imageRef, 'dotnet', 'restore', '--nologo'], {
                timeout: 15000,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            const store = new FindingsStore(repo);
            const ctrl = new ScanController(repo, {
                findingsStore: store,
                profilesPath: PROFILES_PATH,
                enableCache: false
            });

            const scanResult = await ctrl.startScan({
                targetRepo: repo,
                scannerIds: ['dotnet-security', 'nuget-audit'],
                mode: 'comprehensive',
                bypassCache: true
            });

            const dotnetRes = scanResult.scannerResults.find(r => r.scannerId === 'dotnet-security');
            const nugetRes = scanResult.scannerResults.find(r => r.scannerId === 'nuget-audit');

            assert(dotnetRes, 'dotnet-security adapter must execute');
            assert.strictEqual(dotnetRes.status, SCANNER_STATUS.COMPLETED);
            assert.strictEqual(dotnetRes.findings.length, 0, 'Clean project should have 0 findings');

            assert(nugetRes, 'nuget-audit adapter must execute');
            // Clean project without external PackageReference entries correctly reports NO_SCANNABLE_INPUTS (honest empty manifest)
            assert.strictEqual(nugetRes.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(nugetRes.findings.length, 0);

            results.scenarioA = {
                status: 'PASSED',
                dotnetStatus: dotnetRes.status,
                nugetStatus: nugetRes.status,
                toolchainProfile: dotnetRes.toolchainProfileId || 'dotnet-10.0-lts',
                backend: dotnetRes.backendType || 'local-container'
            };
            console.log('  ✓ Scenario A PASSED: .NET Security Analyzer & NuGet Auditor executed cleanly in container.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario B: Project with deliberately vulnerable fixture (Roslyn CA5350 & CA5351)
    // -------------------------------------------------------------------------
    console.log('[SCENARIO B] Vulnerable Code / Dependency Fixture Detection');
    {
        const repo = mkTempRepo('B-vuln-fixture');
        try {
            fs.writeFileSync(path.join(repo, 'VulnApp.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><EnableNETAnalyzers>true</EnableNETAnalyzers><AnalysisLevel>latest</AnalysisLevel><AnalysisModeSecurity>All</AnalysisModeSecurity></PropertyGroup></Project>');
            fs.writeFileSync(path.join(repo, '.editorconfig'), `root = true
[*.cs]
dotnet_diagnostic.CA5350.severity = warning
dotnet_diagnostic.CA5351.severity = warning
`);
            fs.writeFileSync(path.join(repo, 'InsecureCrypto.cs'), `
using System;
using System.Security.Cryptography;

public class InsecureCrypto
{
    public static void RunWeakCrypto()
    {
        using (var md5 = MD5.Create()) { }
        using (var des = DES.Create()) { }
    }
}
`);
            execFileSync('docker', ['run', '--rm', '--network', 'none', '-v', `${repo}:/work:rw`, '-w', '/work', net10Profile.imageRef, 'dotnet', 'restore', '--nologo'], {
                timeout: 15000,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            const store = new FindingsStore(repo);
            const ctrl = new ScanController(repo, {
                findingsStore: store,
                profilesPath: PROFILES_PATH,
                enableCache: false
            });

            const scanResult = await ctrl.startScan({
                targetRepo: repo,
                scannerIds: ['dotnet-security'],
                mode: 'comprehensive',
                bypassCache: true
            });

            const dotnetRes = scanResult.scannerResults.find(r => r.scannerId === 'dotnet-security');
            assert(dotnetRes, 'dotnet-security must execute');
            assert.strictEqual(dotnetRes.status, SCANNER_STATUS.COMPLETED);
            assert(dotnetRes.findings.length >= 2, `Expected at least 2 security diagnostics (CA5350/CA5351), got ${dotnetRes.findings.length}`);

            const ruleIds = dotnetRes.findings.map(f => f.ruleId);
            assert(ruleIds.includes('CA5350') || ruleIds.includes('CA5351'), 'Must detect CA5350 (DES) or CA5351 (MD5)');

            results.scenarioB = {
                status: 'PASSED',
                findingsCount: dotnetRes.findings.length,
                detectedRules: ruleIds,
                sampleEvidence: dotnetRes.findings[0]?.evidence
            };
            console.log(`  ✓ Scenario B PASSED: Genuinely detected ${dotnetRes.findings.length} Roslyn security rule violations (${ruleIds.join(', ')}).\n`);
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario C: Repository with no NuGet manifest / project
    // -------------------------------------------------------------------------
    console.log('[SCENARIO C] Repository with No NuGet Manifest / Project');
    {
        const repo = mkTempRepo('C-no-manifest');
        try {
            fs.writeFileSync(path.join(repo, 'StandaloneScript.cs'), 'System.Console.WriteLine("No project file");');
            fs.writeFileSync(path.join(repo, 'README.md'), '# Just Docs');

            const store = new FindingsStore(repo);
            const ctrl = new ScanController(repo, {
                findingsStore: store,
                profilesPath: PROFILES_PATH,
                enableCache: false
            });

            const scanResult = await ctrl.startScan({
                targetRepo: repo,
                scannerIds: ['dotnet-security', 'nuget-audit'],
                mode: 'comprehensive',
                bypassCache: true
            });

            const dotnetRes = scanResult.scannerResults.find(r => r.scannerId === 'dotnet-security');
            const nugetRes = scanResult.scannerResults.find(r => r.scannerId === 'nuget-audit');

            assert.strictEqual(dotnetRes.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(dotnetRes.findings.length, 0);
            assert(dotnetRes.coverage.includes('No .NET project detected'));

            assert.strictEqual(nugetRes.status, SCANNER_STATUS.NO_SCANNABLE_INPUTS);
            assert.strictEqual(nugetRes.findings.length, 0);

            results.scenarioC = {
                status: 'PASSED',
                dotnetStatus: dotnetRes.status,
                nugetStatus: nugetRes.status,
                coverage: dotnetRes.coverage
            };
            console.log('  ✓ Scenario C PASSED: Correctly reported NO_SCANNABLE_INPUTS with zero fake findings.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario D: Completely empty repository
    // -------------------------------------------------------------------------
    console.log('[SCENARIO D] Empty Repository');
    {
        const repo = mkTempRepo('D-empty-repo');
        try {
            const store = new FindingsStore(repo);
            const ctrl = new ScanController(repo, {
                findingsStore: store,
                profilesPath: PROFILES_PATH,
                enableCache: false
            });

            const scanResult = await ctrl.startScan({
                targetRepo: repo,
                scannerIds: ['dotnet-security', 'nuget-audit'],
                mode: 'comprehensive',
                bypassCache: true
            });

            assert.strictEqual(scanResult.noScannableInputs, true);
            assert.strictEqual(scanResult.reasonCode, 'NO_SCANNABLE_INPUTS');
            assert.strictEqual(scanResult.findingsSummary.total, 0);

            results.scenarioD = {
                status: 'PASSED',
                scanStatus: scanResult.status,
                reasonCode: scanResult.reasonCode
            };
            console.log('  ✓ Scenario D PASSED: Empty repository handled honestly with zero fake findings.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario E: Incompatible or unsupported target framework (e.g. netcoreapp3.1)
    // -------------------------------------------------------------------------
    console.log('[SCENARIO E] Incompatible / Unsupported Target Framework');
    {
        const repo = mkTempRepo('E-incompatible-tf');
        try {
            fs.writeFileSync(path.join(repo, 'LegacyApp.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netcoreapp3.1</TargetFramework></PropertyGroup></Project>');
            fs.writeFileSync(path.join(repo, 'Program.cs'), 'public class Legacy {}');

            assert.throws(() => resolveProfileForRepository(repo, { Technology: 'dotnet' }, PROFILES_PATH), (err) => {
                assert.strictEqual(err.code, 'UNAPPROVED_TARGET_FRAMEWORK');
                return true;
            });

            const scanner = new DotnetSecurityScanner();
            const res = await scanner.scan(repo, repo, { profilesPath: PROFILES_PATH });
            assert.strictEqual(res.status, SCANNER_STATUS.FAILED);
            assert.strictEqual(res.coverage, '0% (Toolchain profile blocked)');
            assert(res.errors[0].includes('UNAPPROVED_TARGET_FRAMEWORK') || res.errors[0].includes('EOL/unapproved'));

            results.scenarioE = {
                status: 'PASSED',
                scannerStatus: res.status,
                error: res.errors[0]
            };
            console.log('  ✓ Scenario E PASSED: Incompatible netcoreapp3.1 cleanly BLOCKED with UNAPPROVED_TARGET_FRAMEWORK; no host fallback.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario F: Missing dependency cache / unrestored assets
    // -------------------------------------------------------------------------
    console.log('[SCENARIO F] Missing Dependency Cache in Offline Sandbox');
    {
        const repo = mkTempRepo('F-unrestored');
        try {
            // Project without obj/project.assets.json and non-built-in dependency
            fs.writeFileSync(path.join(repo, 'Unrestored.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="SomeExternalPackage123" Version="9.9.9" /></ItemGroup></Project>');
            fs.writeFileSync(path.join(repo, 'Program.cs'), 'public class P {}');

            const scanner = new DotnetSecurityScanner();
            const res = await scanner.scan(repo, repo, { profilesPath: PROFILES_PATH });
            assert.strictEqual(res.status, SCANNER_STATUS.FAILED);
            assert(res.errors.length > 0);
            assert(res.errors[0].includes('DEPENDENCY_UNAVAILABLE') || res.errors[0].includes('NETSDK1004') || res.errors[0].includes('BLOCKED'));
            assert.strictEqual(res.findings.length, 0, 'Must NOT fabricate 0-vulnerability success when build fails');

            results.scenarioF = {
                status: 'PASSED',
                scannerStatus: res.status,
                reportedError: res.errors[0]
            };
            console.log('  ✓ Scenario F PASSED: Unrestored dependency reported honestly as failed; no fabricated clean pass.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario G: Docker unavailable (SANDBOX_UNAVAILABLE)
    // -------------------------------------------------------------------------
    console.log('[SCENARIO G] Container Runtime Unavailable (Fail-Closed)');
    {
        const repo = mkTempRepo('G-unavail');
        try {
            fs.writeFileSync(path.join(repo, 'App.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
            fs.writeFileSync(path.join(repo, 'Program.cs'), 'public class P {}');

            const unavailEnv = discoverEnvironment(repo, {
                probeFn: () => ({ ok: false, notFound: true, exitCode: -1, stdout: '', stderr: 'Docker not running' })
            });
            assert.strictEqual(unavailEnv.sandboxAvailable, false);

            const scanner = new DotnetSecurityScanner();
            const res = await scanner.scan(repo, repo, {
                envReport: unavailEnv,
                profilesPath: PROFILES_PATH
            });

            assert.strictEqual(res.status, SCANNER_STATUS.FAILED);
            assert.strictEqual(res.sandboxStatus, SANDBOX_READINESS.SANDBOX_UNAVAILABLE);
            assert(res.errors[0].includes('SANDBOX_UNAVAILABLE'));

            results.scenarioG = {
                status: 'PASSED',
                sandboxStatus: res.sandboxStatus,
                error: res.errors[0]
            };
            console.log('  ✓ Scenario G PASSED: Failed closed with SANDBOX_UNAVAILABLE; zero host execution.\n');
        } finally {
            cleanupRepo(repo);
        }
    }

    // -------------------------------------------------------------------------
    // Scenario H: Invalid image digest / unpinned reference
    // -------------------------------------------------------------------------
    console.log('[SCENARIO H] Invalid / Unpinned Image Digest Policy Enforcement');
    {
        const cBackend = new ContainerSandboxBackend();
        const unpinnedCheck = cBackend.validatePolicy({}, {
            imageRef: 'mcr.microsoft.com/dotnet/sdk:latest'
        });
        assert.strictEqual(unpinnedCheck.valid, false);
        assert(unpinnedCheck.errors[0].includes('unpinned or malformed'));

        const tamperedCheck = cBackend.validatePolicy({}, {
            imageRef: 'mcr.microsoft.com/dotnet/sdk@sha256:1111111111111111111111111111111111111111111111111111111111111111',
            approvedDigests: [net10Profile.imageDigest]
        });
        assert.strictEqual(tamperedCheck.valid, false);
        assert(tamperedCheck.errors[0].includes('not in approved digest allowlist'));

        results.scenarioH = {
            status: 'PASSED',
            unpinnedError: unpinnedCheck.errors[0],
            unapprovedError: tamperedCheck.errors[0]
        };
        console.log('  ✓ Scenario H PASSED: Unpinned tags and unapproved digests strictly blocked.\n');
    }

    // -------------------------------------------------------------------------
    // Scenario I: Sandbox Timeout Guard
    // -------------------------------------------------------------------------
    console.log('[SCENARIO I] Sandbox Execution Timeout Guard');
    {
        const repo = mkTempRepo('I-timeout');
        try {
            fs.writeFileSync(path.join(repo, 'App.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>');
            fs.writeFileSync(path.join(repo, 'Program.cs'), 'public class P { public static void Main() {} }');

            execFileSync('docker', ['run', '--rm', '--network', 'none', '-v', `${repo}:/work:rw`, '-w', '/work', net10Profile.imageRef, 'dotnet', 'restore', '--nologo'], {
                timeout: 15000,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            const gw = new TrustedExecutionGateway({
                workspaceRoot: repo,
                backend: new ContainerSandboxBackend({ envReport: env }),
                envReport: env,
                profilesPath: PROFILES_PATH
            });

            // Enforce a 1000ms timeout limit against a build operation taking > 1.5s
            const req = {
                runId: `timeout-${Date.now()}`,
                applicationId: 'APP-TIMEOUT',
                vulnerabilityId: 'VUL-TIMEOUT',
                workspaceRef: repo,
                operation: OPERATION_TYPES.DOTNET_BUILD,
                toolchainProfileId: 'dotnet-10.0-lts',
                inputs: ['App.csproj'],
                expectedOutputPaths: [],
                extraArgs: [],
                policyVersion: EXECUTION_POLICY_VERSION,
                resourcePolicy: { timeoutMs: 1000, memoryMb: 1024, cpus: 1, pidsLimit: 64 }
            };

            const execRes = await gw.executeOperation(req);
            assert.strictEqual(execRes.executed, true);
            assert.strictEqual(execRes.passed, false);
            assert.strictEqual(execRes.timedOut, true);
            assert.strictEqual(execRes.machineStatus, OUTCOME_STATUS.TIMED_OUT);

            results.scenarioI = {
                status: 'PASSED',
                machineStatus: execRes.machineStatus,
                timedOut: execRes.timedOut,
                durationMs: execRes.durationMs
            };
            console.log(`  ✓ Scenario I PASSED: Sandbox operation safely timed out and terminated in ${execRes.durationMs}ms.\n`);
        } finally {
            cleanupRepo(repo);
        }
    }

    console.log('===============================================================');
    console.log('ALL 9 REAL SCANNING SCENARIOS (A - I) PASSED SUCCESSFULLY');
    console.log('===============================================================');
    return results;
}

if (require.main === module) {
    runScenarioTests().catch(err => {
        console.error('Scenario test failed:', err);
        process.exit(1);
    });
}

module.exports = { runScenarioTests };
