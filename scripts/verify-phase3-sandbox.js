#!/usr/bin/env node
'use strict';

/**
 * GCAC Phase 3 — Sandbox Readiness Verification & Digest Pinning Utility
 * ----------------------------------------------------------------------
 * Strictly non-mutating by default. Does NOT auto-install Docker/Podman/WSL2
 * and does NOT auto-pull images from remote registries.
 *
 * Usage:
 *   node scripts/verify-phase3-sandbox.js
 *   node scripts/verify-phase3-sandbox.js --pin-from-local-images [--map dotnet-9.0-sts=mycorp.jfrog.io/dotnet/sdk:9.0]
 *   node scripts/verify-phase3-sandbox.js --smoke-test [--profile dotnet-9.0-sts]
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const WORKSPACE_ROOT = path.resolve(__dirname, '..');
const PROFILES_PATH = path.join(WORKSPACE_ROOT, 'extension', 'config', 'approved-toolchain-profiles.json');

const { discoverEnvironment } = require('../extension/sandbox/environmentDiscovery');
const {
    computeProfileHash,
    isTemplateDigestProfile,
    loadAndVerifyToolchainRegistry
} = require('../extension/sandbox/toolchainProfiles');
const { ContainerSandboxBackend, isPinnedImageReference } = require('../extension/sandbox/containerSandboxBackend');
const { TrustedExecutionGateway, EXECUTION_POLICY_VERSION, OPERATION_TYPES } = require('../extension/sandbox/trustedExecutionGateway');

const DEFAULT_LOCAL_CANDIDATES = {
    'dotnet-8.0-lts': ['mcr.microsoft.com/dotnet/sdk:8.0', 'mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim'],
    'dotnet-9.0-sts': ['mcr.microsoft.com/dotnet/sdk:9.0', 'mcr.microsoft.com/dotnet/sdk:9.0-bookworm-slim'],
    'java-17-maven': ['maven:3.9-eclipse-temurin-17', 'maven:3.9.9-eclipse-temurin-17'],
    'node-22-lts': ['node:22-slim', 'node:22-bookworm-slim', 'node:22']
};

function parseArgs(argv) {
    const opts = {
        pinFromLocalImages: false,
        smokeTest: false,
        profileId: null,
        maps: {}
    };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--pin-from-local-images') opts.pinFromLocalImages = true;
        else if (arg === '--smoke-test') opts.smokeTest = true;
        else if (arg === '--profile' && argv[i + 1]) opts.profileId = argv[++i];
        else if (arg === '--map' && argv[i + 1]) {
            const pair = argv[++i];
            const eq = pair.indexOf('=');
            if (eq > 0) opts.maps[pair.slice(0, eq)] = pair.slice(eq + 1);
        }
    }
    return opts;
}

function inspectLocalImageDigest(runtimeBin, candidateRef) {
    try {
        const raw = execFileSync(runtimeBin, ['image', 'inspect', '--format', '{{json .RepoDigests}}', candidateRef], {
            encoding: 'utf8',
            timeout: 5000,
            shell: false,
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
        const digests = JSON.parse(raw);
        if (Array.isArray(digests)) {
            const match = digests.find(d => isPinnedImageReference(d));
            if (match) return match;
        }
    } catch {}
    return null;
}

function pinDigestsFromLocalDaemon(env, opts) {
    if (!env.sandboxAvailable || !env.selectedRuntime) {
        console.error('BLOCKED (G3-06): Cannot pin digests because no approved Linux container runtime (Docker/Podman) is available.');
        for (const p of env.prerequisites) console.error('  -', p);
        return false;
    }

    const runtimeMeta = env.selectedRuntime === 'docker' ? env.containers.docker : env.containers.podman;
    const runtimeBin = runtimeMeta.binaryPath || env.selectedRuntime;
    const manifest = JSON.parse(fs.readFileSync(PROFILES_PATH, 'utf8'));
    let updatedCount = 0;

    for (const profile of manifest.profiles) {
        const candidates = opts.maps[profile.profileId]
            ? [opts.maps[profile.profileId]]
            : (DEFAULT_LOCAL_CANDIDATES[profile.profileId] || []);

        let pinnedRef = null;
        for (const cand of candidates) {
            pinnedRef = inspectLocalImageDigest(runtimeBin, cand);
            if (pinnedRef) break;
        }

        if (!pinnedRef) {
            console.warn(`  [SKIP] ${profile.profileId}: No pre-pulled local image with RepoDigest found (checked: ${candidates.join(', ')}).`);
            continue;
        }

        const digestPart = pinnedRef.slice(pinnedRef.indexOf('@') + 1);
        profile.imageRef = pinnedRef;
        profile.imageDigest = digestPart;
        profile.digestStatus = 'VERIFIED_IMAGE_DIGEST';
        profile.digestPolicyNote = `Pinned from verified local ${env.selectedRuntime} daemon RepoDigests on ${new Date().toISOString()}.`;
        profile.profileSha256 = computeProfileHash(profile);
        updatedCount++;
        console.log(`  [PINNED] ${profile.profileId} -> ${pinnedRef}`);
    }

    if (updatedCount > 0) {
        manifest.generatedAt = new Date().toISOString();
        fs.writeFileSync(PROFILES_PATH, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
        loadAndVerifyToolchainRegistry(PROFILES_PATH);
        console.log(`Updated ${updatedCount} profile(s) in approved-toolchain-profiles.json with verified digests.`);
    } else {
        console.log('No profiles updated. Pre-pull approved images from your registry first, then re-run with --pin-from-local-images.');
    }
    return updatedCount > 0;
}

async function runLiveContainerSmokeTest(env, opts) {
    if (!env.sandboxAvailable) {
        console.error('BLOCKED (G3-06): Live container smoke test skipped — SANDBOX_UNAVAILABLE.');
        for (const p of env.prerequisites) console.error('  -', p);
        return false;
    }

    const reg = loadAndVerifyToolchainRegistry(PROFILES_PATH);
    const chosenId = opts.profileId || 'node-22-lts';
    const profile = reg.byId.get(chosenId);
    if (!profile) {
        console.error(`Unknown toolchain profile '${chosenId}'.`);
        return false;
    }
    if (isTemplateDigestProfile(profile)) {
        console.error(`BLOCKED (G3-07): Profile '${profile.profileId}' still uses a TEMPLATE_PLACEHOLDER digest. Pin real digests first.`);
        return false;
    }

    const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-ph3-live-smoke-'));
    try {
        if (profile.supportedStack === 'nodejs') {
            fs.writeFileSync(path.join(tmpRepo, 'package.json'), JSON.stringify({
                name: 'gcac-live-smoke',
                version: '1.0.0',
                scripts: {
                    test: 'node -e "const fs=require(\'fs\'); if(process.getuid&&process.getuid()!==65532) process.exit(2); console.log(\'1 passing\');"'
                }
            }, null, 2));
            fs.writeFileSync(path.join(tmpRepo, 'package-lock.json'), JSON.stringify({
                name: 'gcac-live-smoke',
                version: '1.0.0',
                lockfileVersion: 3,
                packages: {}
            }, null, 2));
        } else {
            fs.writeFileSync(path.join(tmpRepo, 'Smoke.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>');
        }

        const backend = new ContainerSandboxBackend({ envReport: env });
        const gw = new TrustedExecutionGateway({
            workspaceRoot: tmpRepo,
            backend,
            envReport: env,
            profilesPath: PROFILES_PATH
        });

        const req = {
            runId: `smoke-${Date.now()}`,
            applicationId: 'APP-SMOKE',
            vulnerabilityId: 'VUL-SMOKE',
            workspaceRef: tmpRepo,
            operation: profile.supportedStack === 'nodejs' ? OPERATION_TYPES.NPM_TEST : OPERATION_TYPES.DOTNET_BUILD,
            toolchainProfileId: profile.profileId,
            inputs: [],
            expectedOutputPaths: profile.outputArtifactPaths || [],
            extraArgs: [],
            policyVersion: EXECUTION_POLICY_VERSION,
            networkPolicy: 'NO_NETWORK',
            resourcePolicy: { ...profile.runtimeLimits }
        };

        const res = await gw.executeOperation(req, { requirePrePulledImage: true });
        console.log('Live Container Smoke Test Result:', JSON.stringify({
            executed: res.executed,
            passed: res.passed,
            machineStatus: res.machineStatus,
            backendType: res.backendType,
            runtime: res.runtime,
            networkPolicy: res.networkPolicy,
            imageDigest: res.imageDigest,
            reasonCode: res.reasonCode,
            reason: res.reason
        }, null, 2));
        return Boolean(res.executed && res.passed);
    } finally {
        fs.rmSync(tmpRepo, { recursive: true, force: true });
    }
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const env = discoverEnvironment(WORKSPACE_ROOT);

    console.log('=== GCAC Phase 3 Sandbox Readiness Check ===');
    console.log(`OS/Arch          : ${env.os.platform}/${env.os.arch} (${env.os.release})`);
    console.log(`Sandbox Status   : ${env.sandboxStatus} (Runtime: ${env.selectedRuntime || 'None'})`);
    console.log(`Lockfiles        : nuget=${env.workspace.hasLockfiles.nugetPackagesLock}, npm=${env.workspace.hasLockfiles.npmPackageLock}`);

    const reg = loadAndVerifyToolchainRegistry(PROFILES_PATH);
    console.log(`Toolchain Policy : ${reg.policyVersion} (${reg.profiles.length} profiles verified)`);
    for (const p of reg.profiles) {
        const tag = isTemplateDigestProfile(p) ? 'TEMPLATE_PLACEHOLDER (G3-07 OPEN)' : 'VERIFIED_IMAGE_DIGEST';
        console.log(`  - ${p.profileId}: ${tag}`);
    }

    if (!env.sandboxAvailable) {
        console.log('\nOpen Prerequisites (G3-06):');
        for (const p of env.prerequisites) console.log(`  * ${p}`);
    }

    if (opts.pinFromLocalImages) {
        console.log('\n=== Pinning Image Digests from Local Daemon ===');
        const pinned = pinDigestsFromLocalDaemon(env, opts);
        if (!pinned && !opts.smokeTest) process.exitCode = 1;
    }

    if (opts.smokeTest) {
        console.log('\n=== Executing Live Isolated Container Smoke Test ===');
        const ok = await runLiveContainerSmokeTest(env, opts);
        if (!ok) process.exitCode = 1;
    }
}

if (require.main === module) {
    main().catch(err => {
        console.error(err);
        process.exit(1);
    });
}

module.exports = {
    parseArgs,
    inspectLocalImageDigest,
    pinDigestsFromLocalDaemon,
    runLiveContainerSmokeTest
};

