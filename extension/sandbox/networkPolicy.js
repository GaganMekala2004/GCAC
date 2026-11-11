'use strict';

const fs = require('fs');
const path = require('path');

const NETWORK_POLICY_MODES = Object.freeze({
    NO_NETWORK: 'NO_NETWORK',
    APPROVED_INTERNAL_MIRROR_ONLY: 'APPROVED_INTERNAL_MIRROR_ONLY'
});

const PUBLIC_PACKAGE_REGISTRIES = [
    'api.nuget.org',
    'nuget.org',
    'repo.maven.apache.org',
    'repo1.maven.org',
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'pypi.org',
    'files.pythonhosted.org'
];

const EMBEDDED_CREDENTIAL_PATTERNS = [
    /ClearTextPassword/i,
    /Password\s*=\s*["']?[^"'\s<>]{4,}/i,
    /_authToken\s*=/i,
    /_auth\s*=/i,
    /https?:\/\/[^\/\s:@]+:[^\/\s@]+@/i
];

class NetworkPolicyError extends Error {
    constructor(reason, code = 'NETWORK_POLICY_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'NetworkPolicyError';
        this.code = code;
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

function isPublicRegistryUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
        const parsed = new URL(rawUrl);
        const host = parsed.hostname.toLowerCase();
        return PUBLIC_PACKAGE_REGISTRIES.some(pub => host === pub || host.endsWith('.' + pub));
    } catch {
        return PUBLIC_PACKAGE_REGISTRIES.some(pub => rawUrl.toLowerCase().includes(pub));
    }
}

function isHostLoopbackOrMetadataUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    try {
        const parsed = new URL(rawUrl);
        const host = parsed.hostname.toLowerCase();
        return host === 'localhost' ||
            host === '127.0.0.1' ||
            host === '::1' ||
            host === '169.254.169.254' ||
            host === 'host.docker.internal' ||
            host.startsWith('169.254.');
    } catch {
        return false;
    }
}

/**
 * Inspects repository feed configurations (nuget.config, .npmrc, pom.xml/settings.xml)
 * without contacting any external endpoint.
 */
function inspectRepositoryFeedConfigs(repoRoot) {
    const discoveredFeeds = [];
    const credentialLeaks = [];

    if (!repoRoot || !fs.existsSync(repoRoot)) {
        return { discoveredFeeds, credentialLeaks };
    }

    const inspectTextFile = (relName, content, urlExtractor) => {
        for (const rx of EMBEDDED_CREDENTIAL_PATTERNS) {
            if (rx.test(content)) {
                credentialLeaks.push({ file: relName, reason: 'Embedded feed credential or token detected in repository config.' });
                break;
            }
        }
        const urls = urlExtractor(content);
        for (const u of urls) {
            discoveredFeeds.push({
                file: relName,
                url: u,
                isPublicRegistry: isPublicRegistryUrl(u),
                isHostLocalOrMetadata: isHostLoopbackOrMetadataUrl(u)
            });
        }
    };

    const nugetPath = path.join(repoRoot, 'nuget.config');
    const nugetUpperPath = path.join(repoRoot, 'NuGet.Config');
    const resolvedNuget = fs.existsSync(nugetPath) ? nugetPath : (fs.existsSync(nugetUpperPath) ? nugetUpperPath : null);
    if (resolvedNuget) {
        const txt = fs.readFileSync(resolvedNuget, 'utf8');
        inspectTextFile(path.basename(resolvedNuget), txt, (c) => {
            const out = [];
            const rx = /value=["'](https?:\/\/[^"']+)["']/gi;
            let m;
            while ((m = rx.exec(c)) !== null) out.push(m[1]);
            return out;
        });
    }

    const npmrcPath = path.join(repoRoot, '.npmrc');
    if (fs.existsSync(npmrcPath)) {
        const txt = fs.readFileSync(npmrcPath, 'utf8');
        inspectTextFile('.npmrc', txt, (c) => {
            const out = [];
            const rx = /(?:registry|@[^:\s]+:registry)\s*=\s*(https?:\/\/\S+)/gi;
            let m;
            while ((m = rx.exec(c)) !== null) out.push(m[1].trim());
            return out;
        });
    }

    const pomPath = path.join(repoRoot, 'pom.xml');
    if (fs.existsSync(pomPath)) {
        const txt = fs.readFileSync(pomPath, 'utf8');
        inspectTextFile('pom.xml', txt, (c) => {
            const out = [];
            const rx = /<url>(https?:\/\/[^<]+)<\/url>/gi;
            let m;
            while ((m = rx.exec(c)) !== null) out.push(m[1].trim());
            return out;
        });
    }

    return { discoveredFeeds, credentialLeaks };
}

/**
 * Evaluates and enforces network egress policy for a sandboxed operation.
 * Defaults strictly to NO_NETWORK (docker/podman --network=none).
 */
function evaluateNetworkPolicy(request = {}, options = {}) {
    const requestedMode = (request.networkPolicy || NETWORK_POLICY_MODES.NO_NETWORK).toUpperCase();
    const approvedMirrors = Array.isArray(options.approvedInternalMirrors)
        ? options.approvedInternalMirrors.map(u => String(u).toLowerCase())
        : [
            process.env.GCAC_APPROVED_NUGET_FEED,
            process.env.GCAC_APPROVED_MAVEN_MIRROR,
            process.env.GCAC_APPROVED_NPM_REGISTRY
        ].filter(Boolean).map(u => String(u).toLowerCase());

    if (requestedMode === 'HOST' || requestedMode === 'PUBLIC' || requestedMode === 'BRIDGE' || requestedMode === 'UNRESTRICTED') {
        throw new NetworkPolicyError(
            `Permissive network mode '${requestedMode}' is strictly prohibited for sandboxed operations.`,
            'PERMISSIVE_NETWORK_DENIED'
        );
    }

    const feedInspection = request.workspaceRef
        ? inspectRepositoryFeedConfigs(request.workspaceRef)
        : { discoveredFeeds: [], credentialLeaks: [] };

    if (feedInspection.credentialLeaks.length > 0) {
        throw new NetworkPolicyError(
            `Repository package config contains embedded credentials (${feedInspection.credentialLeaks[0].file}); credentials are prohibited in build sandbox.`,
            'FEED_CREDENTIALS_PROHIBITED',
            { leaks: feedInspection.credentialLeaks }
        );
    }

    // Untrusted builds, tests, scans, and SBOM generation MUST run with NO_NETWORK
    if (requestedMode === NETWORK_POLICY_MODES.NO_NETWORK) {
        return {
            allowed: true,
            policyMode: NETWORK_POLICY_MODES.NO_NETWORK,
            containerNetworkMode: 'none',
            allowIsolatedMirrorNetwork: false,
            permittedDestinations: [],
            discoveredRepoFeeds: feedInspection.discoveredFeeds,
            enforcementSummary: 'Container network namespace isolated (--network=none); zero outbound or loopback/host-service egress.'
        };
    }

    if (requestedMode === NETWORK_POLICY_MODES.APPROVED_INTERNAL_MIRROR_ONLY) {
        if (!request.isControlledRestoreOperation) {
            throw new NetworkPolicyError(
                'Network access is only permitted during a dedicated controlled dependency restore operation, never during build/test execution.',
                'EGRESS_NOT_ALLOWED_IN_BUILD_TEST'
            );
        }

        const requestedFeeds = Array.isArray(request.requestedFeeds) ? request.requestedFeeds : [];
        if (requestedFeeds.length === 0 || approvedMirrors.length === 0) {
            throw new NetworkPolicyError(
                'Approved internal package mirror requested, but no verified internal feed is configured. Failing closed.',
                'NO_APPROVED_INTERNAL_MIRROR'
            );
        }

        for (const feed of requestedFeeds) {
            const lower = String(feed).toLowerCase();
            if (isPublicRegistryUrl(lower)) {
                throw new NetworkPolicyError(`Public internet package registry '${feed}' is blocked.`, 'PUBLIC_REGISTRY_BLOCKED');
            }
            if (isHostLoopbackOrMetadataUrl(lower)) {
                throw new NetworkPolicyError(`Host loopback/metadata URL '${feed}' is blocked.`, 'HOST_METADATA_EGRESS_BLOCKED');
            }
            if (!approvedMirrors.some(m => lower.startsWith(m))) {
                throw new NetworkPolicyError(`Unapproved package feed destination '${feed}' denied.`, 'UNAPPROVED_MIRROR_DENIED');
            }
        }

        if (!options.isolatedMirrorNetworkVerified) {
            throw new NetworkPolicyError(
                'Independently enforced container mirror network policy is not verified; refusing silent fallback to unrestricted bridge networking.',
                'UNVERIFIED_MIRROR_NETWORK_POLICY'
            );
        }

        return {
            allowed: true,
            policyMode: NETWORK_POLICY_MODES.APPROVED_INTERNAL_MIRROR_ONLY,
            containerNetworkMode: options.isolatedMirrorNetworkName || 'gcac-internal-mirror-net',
            allowIsolatedMirrorNetwork: true,
            permittedDestinations: requestedFeeds,
            discoveredRepoFeeds: feedInspection.discoveredFeeds,
            enforcementSummary: `Isolated internal mirror network enforced for destinations: [${requestedFeeds.join(', ')}].`
        };
    }

    throw new NetworkPolicyError(`Unknown network policy mode '${requestedMode}'.`, 'UNKNOWN_NETWORK_POLICY');
}

module.exports = {
    NETWORK_POLICY_MODES,
    PUBLIC_PACKAGE_REGISTRIES,
    NetworkPolicyError,
    isPublicRegistryUrl,
    isHostLoopbackOrMetadataUrl,
    inspectRepositoryFeedConfigs,
    evaluateNetworkPolicy
};

