'use strict';

const fs = require('fs');
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
 * Inspects repository metadata (global.json, *.csproj, pom.xml, package.json)
 * to select an approved compatible toolchain profile without trusting repo-injected
 * policy overrides.
 */
function resolveProfileForRepository(repoRoot, finding = {}, profilesPath = DEFAULT_PROFILES_PATH) {
    const registry = loadAndVerifyToolchainRegistry(profilesPath);
    const tech = String(finding.Technology || '').toLowerCase();

    // Check unsupported explicit build systems first (Gradle, Ant, Python)
    if (repoRoot && fs.existsSync(repoRoot)) {
        if (fs.existsSync(path.join(repoRoot, 'build.gradle')) || fs.existsSync(path.join(repoRoot, 'build.gradle.kts'))) {
            throw new ToolchainProfileError('Gradle toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
        }
        if (fs.existsSync(path.join(repoRoot, 'build.xml'))) {
            throw new ToolchainProfileError('Apache Ant toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
        }
        if (fs.existsSync(path.join(repoRoot, 'requirements.txt')) || fs.existsSync(path.join(repoRoot, 'pyproject.toml'))) {
            if (!fs.existsSync(path.join(repoRoot, 'package.json')) && !fs.existsSync(path.join(repoRoot, 'pom.xml'))) {
                throw new ToolchainProfileError('Python toolchain is not approved in Phase 3; documented as future adapter.', 'UNAPPROVED_TOOLCHAIN_STACK');
            }
        }
    }

    // 1. Inspect .NET global.json and .csproj
    let requestedDotnetSdk = null;
    const csprojFrameworks = [];
    if (repoRoot && fs.existsSync(repoRoot)) {
        const gjPath = path.join(repoRoot, 'global.json');
        if (fs.existsSync(gjPath)) {
            try {
                const gj = JSON.parse(fs.readFileSync(gjPath, 'utf8'));
                requestedDotnetSdk = gj.sdk?.version ? String(gj.sdk.version).trim() : null;
            } catch {
                throw new ToolchainProfileError('Malformed global.json in repository.', 'INVALID_GLOBAL_JSON');
            }
        }

        const collectCsproj = (dir, depth = 0) => {
            if (depth > 3) return;
            let entries = [];
            try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
            for (const e of entries) {
                if (['.git', 'node_modules', 'bin', 'obj'].includes(e.name)) continue;
                const full = path.join(dir, e.name);
                if (e.isDirectory()) collectCsproj(full, depth + 1);
                else if (e.isFile() && e.name.endsWith('.csproj')) {
                    const xml = fs.readFileSync(full, 'utf8');
                    const m = xml.match(/<TargetFramework[s]?>([^<]+)<\/TargetFramework[s]?>/i);
                    if (m) csprojFrameworks.push(m[1].trim().toLowerCase());
                }
            }
        };
        collectCsproj(repoRoot, 0);
    }

    if (requestedDotnetSdk) {
        if (/^8\./.test(requestedDotnetSdk)) return getApprovedProfile('dotnet-8.0-lts', profilesPath);
        if (/^9\./.test(requestedDotnetSdk)) return getApprovedProfile('dotnet-9.0-sts', profilesPath);
        throw new ToolchainProfileError(
            `global.json requests unapproved or EOL .NET SDK version '${requestedDotnetSdk}'. Only approved 8.0 LTS and 9.0 STS profiles exist.`,
            'UNAPPROVED_DOTNET_SDK'
        );
    }

    if (csprojFrameworks.length > 0 || tech === 'dotnet' || tech === 'csharp' || tech === '.net') {
        const hasNet9 = csprojFrameworks.some(tf => tf.includes('net9.0'));
        const hasUnsupported = csprojFrameworks.some(tf => /net(?:coreapp)?[1-7]\.0|netcoreapp/.test(tf));
        if (hasUnsupported && !hasNet9 && !csprojFrameworks.some(tf => tf.includes('net8.0'))) {
            throw new ToolchainProfileError(
                `TargetFramework '${csprojFrameworks.join(', ')}' is EOL/unapproved. Only net8.0 (LTS) and net9.0 (STS) are supported.`,
                'UNAPPROVED_TARGET_FRAMEWORK'
            );
        }
        return hasNet9
            ? getApprovedProfile('dotnet-9.0-sts', profilesPath)
            : getApprovedProfile('dotnet-8.0-lts', profilesPath);
    }

    // 2. Inspect Java / Maven
    if ((repoRoot && fs.existsSync(path.join(repoRoot, 'pom.xml'))) || tech === 'java' || tech === 'java-spring') {
        return getApprovedProfile('java-17-maven', profilesPath);
    }

    // 3. Inspect Node.js
    if ((repoRoot && fs.existsSync(path.join(repoRoot, 'package.json'))) || tech === 'javascript' || tech === 'typescript' || tech === 'node') {
        return getApprovedProfile('node-22-lts', profilesPath);
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
    loadAndVerifyToolchainRegistry,
    getApprovedProfile,
    resolveProfileForRepository
};

