'use strict';

const fs = require('fs');
const { isSeparateRepositoryDirectory } = require('../repositoryContext');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_PROFILES_PATH = path.resolve(__dirname, '..', 'config', 'approved-toolchain-profiles.json');

class ToolchainProfileError extends Error {
    constructor(reason, code = 'TOOLCHAIN_PROFILE_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'ToolchainProfileError';
        this.code = code;
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

function canonicalJson(value) {
    if (value === null || value === undefined) return JSON.stringify(value);
    if (Array.isArray(value)) {
        return '[' + value.map(item => canonicalJson(item)).join(',') + ']';
    }
    if (typeof value === 'object') {
        const keys = Object.keys(value).sort();
        return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
    }
    return JSON.stringify(value);
}

function computeProfileHash(profile) {
    const { profileSha256, ...core } = profile;
    return crypto.createHash('sha256').update(canonicalJson(core), 'utf8').digest('hex');
}

function isTemplateDigestProfile(profile) {
    if (!profile || typeof profile !== 'object') return true;
    if (String(profile.digestStatus || '').toUpperCase() === 'TEMPLATE_PLACEHOLDER') return true;
    if (/^Template digest/i.test(String(profile.digestPolicyNote || ''))) return true;
    return false;
}

function loadAndVerifyToolchainRegistry(profilesPath = DEFAULT_PROFILES_PATH) {
    if (!profilesPath || !fs.existsSync(profilesPath)) {
        throw new ToolchainProfileError(`Approved toolchain profiles manifest missing at '${profilesPath}'.`, 'MISSING_TOOLCHAIN_PROFILES');
    }

    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(profilesPath, 'utf8'));
    } catch (err) {
        throw new ToolchainProfileError(`Toolchain profiles JSON malformed: ${err.message}`, 'MALFORMED_TOOLCHAIN_PROFILES');
    }

    if (!manifest || !manifest.policyVersion || !Array.isArray(manifest.profiles) || manifest.profiles.length === 0) {
        throw new ToolchainProfileError('Toolchain profiles manifest missing policyVersion or profiles array.', 'MALFORMED_TOOLCHAIN_PROFILES');
    }

    const byId = new Map();
    for (const p of manifest.profiles) {
        if (!p.profileId || !p.supportedStack || !p.imageRef || !p.imageDigest || !p.profileSha256) {
            throw new ToolchainProfileError(`Toolchain profile '${p.profileId || 'unknown'}' missing mandatory integrity fields.`, 'INVALID_TOOLCHAIN_PROFILE');
        }
        if (!/^sha256:[0-9a-f]{64}$/i.test(p.imageDigest) || !p.imageRef.endsWith('@' + p.imageDigest)) {
            throw new ToolchainProfileError(
                `Toolchain profile '${p.profileId}' image reference is not pinned by matching immutable digest.`,
                'UNPINNED_TOOLCHAIN_IMAGE'
            );
        }
        const actualHash = computeProfileHash(p);
        if (actualHash !== p.profileSha256) {
            throw new ToolchainProfileError(
                `Toolchain profile '${p.profileId}' integrity hash mismatch (profile tampering detected).`,
                'TOOLCHAIN_PROFILE_TAMPERED',
                { expected: p.profileSha256, actual: actualHash }
            );
        }
        byId.set(p.profileId, p);
    }

    return {
        policyVersion: manifest.policyVersion,
        profiles: manifest.profiles,
        unsupportedAdapters: manifest.unsupportedFutureAdapters || [],
        hasTemplateDigests: manifest.profiles.some(isTemplateDigestProfile),
        byId
    };
}

function getApprovedProfile(profileId, profilesPath = DEFAULT_PROFILES_PATH) {
    const registry = loadAndVerifyToolchainRegistry(profilesPath);
    const profile = registry.byId.get(profileId);
    if (!profile) {
        throw new ToolchainProfileError(
            `Toolchain profile '${profileId}' is not in the approved registry.`,
            'UNAPPROVED_TOOLCHAIN_PROFILE'
        );
    }
    return profile;
}

/**
 * Asserts that a resolved toolchain profile is enterprise-provisioned with a verified
 * local image digest, failing closed immediately when unprovisioned template placeholders
 * are encountered instead of attempting container execution.
 */
function assertProfileProvisioned(profile, context = {}) {
    if (!profile) return;
    if (isTemplateDigestProfile(profile) || profile.digestStatus === 'TEMPLATE_PLACEHOLDER') {
        const repoLabel = context.repositoryLabel || profile.resolvedFrom || 'Target repository';
        const tf = profile.targetFramework || context.targetFramework || 'detected framework';
        const err = new ToolchainProfileError(
            `${repoLabel} targets '${tf}'. Profile '${profile.profileId}' uses template placeholder digest '${profile.imageDigest}'. Configure a verified digest for this framework and provision its image before scanning.`,
            'UNPROVISIONED_TOOLCHAIN_PROFILE'
        );
        err.profileId = profile.profileId;
        err.targetFramework = tf;
        err.imageDigest = profile.imageDigest;
        err.digestStatus = profile.digestStatus;
        err.failureCategory = 'TOOLCHAIN_IMAGE_UNAVAILABLE';
        err.machineStatus = 'COULD_NOT_RUN';
        throw err;
    }
}

/**
 * Inspects repository metadata (global.json, *.csproj, Directory.Build.props, pom.xml, package.json)
 * to select an approved compatible toolchain profile without trusting repo-injected
 * policy overrides.
 */
function resolveProfileForRepository(repoRoot, finding = {}, profilesPath = DEFAULT_PROFILES_PATH, resolutionOptions = {}) {
    const registry = loadAndVerifyToolchainRegistry(profilesPath);
    const tech = String(finding.Technology || finding.technology || '').toLowerCase();

    let targetDir = repoRoot;
    let targetFile = null;
    if (repoRoot && fs.existsSync(repoRoot)) {
        try {
            const stat = fs.statSync(repoRoot);
            if (stat.isFile()) {
                targetFile = repoRoot;
                targetDir = path.dirname(repoRoot);
            }
        } catch {}
    }

    // Check unsupported explicit build systems first (Gradle, Ant, Python)
    if (targetDir && fs.existsSync(targetDir)) {
        if (fs.existsSync(path.join(targetDir, 'build.gradle')) || fs.existsSync(path.join(targetDir, 'build.gradle.kts'))) {
            throw new ToolchainProfileError('Gradle toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
        }
        if (fs.existsSync(path.join(targetDir, 'build.xml'))) {
            throw new ToolchainProfileError('Apache Ant toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
        }
        if (fs.existsSync(path.join(targetDir, 'requirements.txt')) || fs.existsSync(path.join(targetDir, 'pyproject.toml'))) {
            if (!fs.existsSync(path.join(targetDir, 'package.json')) && !fs.existsSync(path.join(targetDir, 'pom.xml'))) {
                throw new ToolchainProfileError('Python toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
            }
        }
    }

    // 1. Inspect .NET global.json, .csproj, and Directory.Build.props
    let requestedDotnetSdk = null;
    const csprojFrameworks = [];

    const extractFrameworksFromXml = (xmlContent) => {
        if (!xmlContent || typeof xmlContent !== 'string') return;
        const matches = xmlContent.matchAll(/<TargetFramework[s]?>([^<]+)<\/TargetFramework[s]?>/gi);
        for (const m of matches) {
            if (m[1]) {
                const parts = m[1].split(';').map(p => p.trim().toLowerCase()).filter(Boolean);
                csprojFrameworks.push(...parts);
            }
        }
    };

    if (targetFile && targetFile.toLowerCase().endsWith('.csproj')) {
        try {
            extractFrameworksFromXml(fs.readFileSync(targetFile, 'utf8'));
        } catch {}
    }

    if (targetDir && fs.existsSync(targetDir)) {
        // Check global.json in targetDir and up to 2 parent directories
        let curr = targetDir;
        for (let d = 0; d < 3 && curr; d++) {
            const gjPath = path.join(curr, 'global.json');
            if (fs.existsSync(gjPath)) {
                try {
                    const gj = JSON.parse(fs.readFileSync(gjPath, 'utf8'));
                    if (gj.sdk?.version) {
                        requestedDotnetSdk = String(gj.sdk.version).trim();
                        break;
                    }
                } catch {
                    throw new ToolchainProfileError('Malformed global.json in repository.', 'INVALID_GLOBAL_JSON');
                }
            }
            const parent = path.dirname(curr);
            if (parent === curr) break;
            curr = parent;
        }

        // Check Directory.Build.props
        curr = targetDir;
        for (let d = 0; d < 3 && curr; d++) {
            const propsPath = path.join(curr, 'Directory.Build.props');
            if (fs.existsSync(propsPath)) {
                try {
                    extractFrameworksFromXml(fs.readFileSync(propsPath, 'utf8'));
                } catch {}
            }
            const parent = path.dirname(curr);
            if (parent === curr) break;
            curr = parent;
        }

        // Traverse directory for .csproj files (up to depth 5)
        const collectCsproj = (dir, depth = 0) => {
            if (depth > 5) return;
            let entries = [];
            try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
            for (const e of entries) {
                if (['.git', 'node_modules', 'bin', 'obj', 'workspaces', 'remediation-output', 'output'].includes(e.name)) continue;
                const full = path.join(dir, e.name);
                if (e.isDirectory() && !isSeparateRepositoryDirectory(full)) collectCsproj(full, depth + 1);
                else if (e.isFile() && e.name.toLowerCase().endsWith('.csproj')) {
                    try {
                        extractFrameworksFromXml(fs.readFileSync(full, 'utf8'));
                    } catch {}
                }
            }
        };
        collectCsproj(targetDir, 0);
    }

    let primaryFramework = null;
    let selectedProfileId = null;

    if (requestedDotnetSdk) {
        if (/^10\./.test(requestedDotnetSdk)) {
            primaryFramework = 'net10.0';
            selectedProfileId = 'dotnet-10.0-lts';
        } else if (/^9\./.test(requestedDotnetSdk)) {
            primaryFramework = 'net9.0';
            selectedProfileId = 'dotnet-9.0-sts';
        } else if (/^8\./.test(requestedDotnetSdk)) {
            primaryFramework = 'net8.0';
            selectedProfileId = 'dotnet-8.0-lts';
        } else {
            throw new ToolchainProfileError(
                `global.json requests unapproved or EOL .NET SDK version '${requestedDotnetSdk}'. Only approved 8.0 LTS, 9.0 STS, and 10.0 LTS profiles exist.`,
                'UNAPPROVED_DOTNET_SDK'
            );
        }
    } else if (csprojFrameworks.length > 0 || tech === 'dotnet' || tech === 'csharp' || tech === '.net') {
        const hasNet10 = csprojFrameworks.some(tf => tf.includes('net10.0'));
        const hasNet9 = csprojFrameworks.some(tf => tf.includes('net9.0'));
        const hasNet8 = csprojFrameworks.some(tf => tf.includes('net8.0'));
        const hasUnsupported = csprojFrameworks.some(tf => /net(?:coreapp)?[1-7]\.0|netcoreapp/.test(tf));
        if (hasUnsupported && !hasNet10 && !hasNet9 && !hasNet8) {
            throw new ToolchainProfileError(
                `TargetFramework '${csprojFrameworks.join(', ')}' is EOL/unapproved. Only net8.0 (LTS), net9.0 (STS), and net10.0 (LTS) are supported.`,
                'UNAPPROVED_TARGET_FRAMEWORK'
            );
        }
        if (hasNet10) {
            primaryFramework = 'net10.0';
            selectedProfileId = 'dotnet-10.0-lts';
        } else if (hasNet9) {
            primaryFramework = 'net9.0';
            selectedProfileId = 'dotnet-9.0-sts';
        } else {
            primaryFramework = 'net8.0';
            selectedProfileId = 'dotnet-8.0-lts';
        }
    }

    if (selectedProfileId) {
        const baseProfile = getApprovedProfile(selectedProfileId, profilesPath);
        const resolved = {
            ...baseProfile,
            targetFramework: primaryFramework || 'net10.0',
            detectedFrameworks: Array.from(new Set(csprojFrameworks)),
            resolvedFrom: targetFile ? path.basename(targetFile) : (targetDir ? path.basename(targetDir) : 'context')
        };
        if (resolutionOptions.requireProvisioned === true) {
            assertProfileProvisioned(resolved, resolutionOptions);
        }
        return resolved;
    }

    // 2. Inspect Java / Maven
    if ((targetDir && fs.existsSync(path.join(targetDir, 'pom.xml'))) || tech === 'java' || tech === 'java-spring') {
        const baseProfile = getApprovedProfile('java-17-maven', profilesPath);
        return {
            ...baseProfile,
            targetFramework: 'java-17',
            detectedFrameworks: ['java-17'],
            resolvedFrom: 'pom.xml'
        };
    }

    // 3. Inspect Node.js
    if ((targetDir && fs.existsSync(path.join(targetDir, 'package.json'))) || tech === 'javascript' || tech === 'typescript' || tech === 'node') {
        const baseProfile = getApprovedProfile('node-22-lts', profilesPath);
        return {
            ...baseProfile,
            targetFramework: 'node-22',
            detectedFrameworks: ['node-22'],
            resolvedFrom: 'package.json'
        };
    }

    throw new ToolchainProfileError(
        `No approved toolchain profile matches technology '${tech || 'unknown'}' in repository.`,
        'UNSUPPORTED_STACK'
    );
}

module.exports = {
    DEFAULT_PROFILES_PATH,
    ToolchainProfileError,
    canonicalJson,
    computeProfileHash,
    isTemplateDigestProfile,
    assertProfileProvisioned,
    loadAndVerifyToolchainRegistry,
    getApprovedProfile,
    resolveProfileForRepository
};

