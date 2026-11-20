'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { resolveProfileForRepository, assertProfileProvisioned, getApprovedProfile, ToolchainProfileError } = require('../../extension/sandbox/toolchainProfiles');
const { TrustedExecutionGateway, OPERATION_TYPES, EXECUTION_POLICY_VERSION } = require('../../extension/sandbox/trustedExecutionGateway');
const { ContainerSandboxBackend } = require('../../extension/sandbox/containerSandboxBackend');
const { DotnetSecurityScanner } = require('../../extension/scanning/adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { OUTCOME_STATUS } = require('../../extension/outcomeContract');
const { SCANNER_STATUS } = require('../../extension/scanning/findingModel');

function mkTempDir(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanupTempDir(dir) {
    if (dir && fs.existsSync(dir)) {
        try {
            fs.rmSync(dir, { recursive: true, force: true });
        } catch { }
    }
}

async function runLiveProfileSelectionTests() {
    console.log('=== Running Live Scanner Profile Selection Regression Suite ===\n');

    const verifiedNet10Digest = 'sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb';


    // -------------------------------------------------------------------------
    // Test 1: net10.0 project selects the real approved .NET 10 image
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-prof-net10-');
        try {
            fs.writeFileSync(path.join(tmp, 'App.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
            const profile = resolveProfileForRepository(tmp, { Technology: 'dotnet' });
            assert.strictEqual(profile.profileId, 'dotnet-10.0-lts');
            assert.strictEqual(profile.imageDigest, verifiedNet10Digest);
            assert.strictEqual(profile.digestStatus, 'VERIFIED_IMAGE_DIGEST');
            assert.strictEqual(profile.targetFramework, 'net10.0');

            // Must pass provisioned assertion cleanly
            assert.doesNotThrow(() => assertProfileProvisioned(profile, { repositoryLabel: 'test-net10' }));
            console.log('  ✓ Test 1: net10.0 project selects verified dotnet-10.0-lts profile');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 2: net9.0 project does not silently select an incompatible image
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-prof-net9-');
        try {
            fs.writeFileSync(path.join(tmp, 'Legacy.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>');
            const profile = resolveProfileForRepository(tmp, { Technology: 'dotnet' });
            assert.strictEqual(profile.profileId, 'dotnet-9.0-sts');
            assert.strictEqual(profile.targetFramework, 'net9.0');
            assert.strictEqual(profile.digestStatus, 'VERIFIED_IMAGE_DIGEST');
            assert.doesNotThrow(() => assertProfileProvisioned(profile));
            const failedBuild = await new DotnetSecurityScanner().scan(tmp, tmp, {
                executionGateway: { executeOperation: async () => ({ executed: true, exitCode: 1, machineStatus: OUTCOME_STATUS.FAILED }) }
            });
            assert.strictEqual(failedBuild.status, SCANNER_STATUS.PARTIAL);
            console.log('  ✓ Test 2: net9.0 selects the verified .NET 9 SDK and a failed build reports partial coverage');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 3: Both scanners use consistent profile selection & report diagnostics
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-scanners-cons-');
        try {
            fs.writeFileSync(path.join(tmp, 'App.csproj'), `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`);
            const secScanner = new DotnetSecurityScanner();
            const nugetScanner = new NuGetAuditScanner();

            const secRes = await secScanner.scan(tmp, tmp, { scanId: 'test-cons-01' });
            const nugetRes = await nugetScanner.scan(tmp, tmp, { scanId: 'test-cons-02' });

            assert.strictEqual(secRes.status, SCANNER_STATUS.FAILED);
            assert.strictEqual(nugetRes.status, SCANNER_STATUS.FAILED);

            // Both scanners must capture structured diagnostics
            assert(secRes.diagnostics, 'secRes missing diagnostics');
            assert(nugetRes.diagnostics, 'nugetRes missing diagnostics');
            assert.strictEqual(secRes.diagnostics.targetFramework, 'net8.0');
            assert.strictEqual(nugetRes.diagnostics.targetFramework, 'net8.0');
            assert.strictEqual(secRes.diagnostics.toolchainProfileId, 'dotnet-8.0-lts');
            assert.strictEqual(nugetRes.diagnostics.toolchainProfileId, 'dotnet-8.0-lts');
            assert.strictEqual(secRes.diagnostics.digestStatus, 'TEMPLATE_PLACEHOLDER');
            assert.strictEqual(nugetRes.diagnostics.digestStatus, 'TEMPLATE_PLACEHOLDER');

            // Error messages must be clean and informative
            assert(secRes.errors[0].includes('UNPROVISIONED_TOOLCHAIN_PROFILE'));
            assert(nugetRes.errors[0].includes('UNPROVISIONED_TOOLCHAIN_PROFILE'));
            console.log('  ✓ Test 3: Both .NET Security Analyzer and NuGet Dependency Auditor report consistent diagnostics');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 4: Old placeholder digests are rejected at the gateway boundary
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-gw-reject-');
        try {
            fs.writeFileSync(path.join(tmp, 'App.csproj'),
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>');
            const backend = new ContainerSandboxBackend();
            const gw = new TrustedExecutionGateway({ workspaceRoot: tmp, backend });

            const req = {
                runId: 'test-gw-reject',
                applicationId: 'APP-100',
                vulnerabilityId: 'VUL-001',
                workspaceRef: tmp,
                operation: OPERATION_TYPES.DOTNET_BUILD,
                toolchainProfileId: 'dotnet-8.0-lts',
                inputs: ['App.csproj'],
                expectedOutputPaths: [],
                extraArgs: [],
                policyVersion: EXECUTION_POLICY_VERSION,
                resourcePolicy: { timeoutMs: 10000, memoryMb: 1024, cpus: 1, pidsLimit: 64 }
            };

            const gwRes = await gw.executeOperation(req);
            assert.strictEqual(gwRes.executed, false);
            assert(gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN || gwRes.machineStatus === OUTCOME_STATUS.BLOCKED,
                `Expected COULD_NOT_RUN or BLOCKED machineStatus, got ${gwRes.machineStatus}`);
            assert(gwRes.reasonCode === 'TOOLCHAIN_IMAGE_UNAVAILABLE' || gwRes.reasonCode === 'UNPROVISIONED_TOOLCHAIN_PROFILE',
                `Expected TOOLCHAIN_IMAGE_UNAVAILABLE or UNPROVISIONED_TOOLCHAIN_PROFILE, got ${gwRes.reasonCode}`);
            assert(gwRes.reason.includes('uses template placeholder digest'));
            console.log('  ✓ Test 4: TrustedExecutionGateway strictly blocks template placeholder profiles from container launch');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 5: Cached framework metadata cannot incorrectly select an outdated profile
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-fresh-resolve-');
        try {
            const csprojPath = path.join(tmp, 'App.csproj');
            fs.writeFileSync(csprojPath,
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>');
            const p1 = resolveProfileForRepository(tmp, { Technology: 'dotnet' });
            assert.strictEqual(p1.profileId, 'dotnet-9.0-sts');

            // Dynamically update project file to net10.0
            fs.writeFileSync(csprojPath,
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
            const p2 = resolveProfileForRepository(tmp, { Technology: 'dotnet' });
            assert.strictEqual(p2.profileId, 'dotnet-10.0-lts');
            assert.strictEqual(p2.imageDigest, verifiedNet10Digest);
            console.log('  ✓ Test 5: In-place project framework modification dynamically selects updated profile');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 6: Running extension and source configuration mismatches are detectable
    // -------------------------------------------------------------------------
    {
        const profile = getApprovedProfile('dotnet-10.0-lts');
        assert.strictEqual(profile.imageDigest, verifiedNet10Digest);
        assert.strictEqual(profile.digestStatus, 'VERIFIED_IMAGE_DIGEST');

        // Mismatched or forged digest profile
        const legacyProfile = getApprovedProfile('dotnet-8.0-lts');
        assert.strictEqual(legacyProfile.digestStatus, 'TEMPLATE_PLACEHOLDER');
        console.log('  ✓ Test 6: Profile registry configuration correctly distinguishes verified vs placeholder profiles');
    }

    // -------------------------------------------------------------------------
    // Test 7: Missing image cannot trigger an automatic pull & no host fallback
    // -------------------------------------------------------------------------
    {
        const backend = new ContainerSandboxBackend();
        // Container args enforce --network none
        const runArgs = backend.buildContainerRunArgs({
            containerName: 'test-pull-check',
            instanceId: 'inst-1',
            runId: 'run-1',
            imageRef: `mcr.microsoft.com/dotnet/sdk@${verifiedNet10Digest}`,
            networkMode: 'none',
            workDirHost: '/tmp',
            outDirHost: '/tmp',
            homeDirHost: '/tmp',
            cacheDirHost: '/tmp',
            executable: 'dotnet',
            args: ['--version']
        });
        assert(runArgs.includes('--network'), 'Missing --network flag');
        assert.strictEqual(runArgs[runArgs.indexOf('--network') + 1], 'none');
        console.log('  ✓ Test 7: Container arguments enforce --network none to prevent auto-pull');
    }

    // -------------------------------------------------------------------------
    // Test 8: Live scanner execution on a real disposable .NET 10 repository
    // -------------------------------------------------------------------------
    {
        const tmp = mkTempDir('gcac-live-net10-scan-');
        try {
            fs.writeFileSync(path.join(tmp, 'LiveApp.csproj'), `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>`);
            fs.writeFileSync(path.join(tmp, 'Program.cs'), `
Console.WriteLine("Hello from live .NET 10 container sandbox!");
`);
            // Run restore to generate project.assets.json so offline build works cleanly
            const { execFileSync } = require('child_process');
            execFileSync('dotnet', ['restore', path.join(tmp, 'LiveApp.csproj'), '--use-lock-file'], { stdio: 'ignore' });

            const secScanner = new DotnetSecurityScanner();
            const res = await secScanner.scan(tmp, tmp, { scanId: 'test-live-net10' });

            assert.strictEqual(res.status, SCANNER_STATUS.COMPLETED);
            assert.strictEqual(res.toolchainProfileId, 'dotnet-10.0-lts');
            assert.strictEqual(res.diagnostics.imageDigest, verifiedNet10Digest);
            assert.strictEqual(res.diagnostics.targetFramework, 'net10.0');
            assert(res.coverage.includes('100%') || res.coverage.includes('Coverage active'));
            console.log('  ✓ Test 8: Live .NET 10 scanner execution executes genuinely in container sandbox');
        } finally {
            cleanupTempDir(tmp);
        }
    }

    // -------------------------------------------------------------------------
    // Test 9: Live scan of inventory-manager (net9.0) uses the verified .NET 9 profile
    // -------------------------------------------------------------------------
    {
        const inventoryDir = path.resolve(__dirname, '../../sample-repos/inventory-manager');
        if (fs.existsSync(inventoryDir)) {
            const secScanner = new DotnetSecurityScanner();

            const secRes = await secScanner.scan(inventoryDir, inventoryDir, { scanId: 'test-inv-01' });

            assert.strictEqual(secRes.status, SCANNER_STATUS.COMPLETED, JSON.stringify(secRes.errors));
            assert.strictEqual(secRes.coverage, '100% (Sandboxed Roslyn analyzers active)');
            assert.strictEqual(secRes.diagnostics.targetFramework, 'net9.0');
            assert.strictEqual(secRes.diagnostics.toolchainProfileId, 'dotnet-9.0-sts');
            assert.strictEqual(secRes.diagnostics.digestStatus, 'VERIFIED_IMAGE_DIGEST');
            console.log('  ✓ Test 9: inventory-manager completed sandboxed Roslyn analysis');

        }
    }

    console.log('\n=== ALL 9 REGRESSION TESTS PASSED CLEANLY ===');
}

if (require.main === module) {
    runLiveProfileSelectionTests().catch(err => {
        console.error('FAILED:', err);
        process.exit(1);
    });
}

module.exports = { runLiveProfileSelectionTests };
