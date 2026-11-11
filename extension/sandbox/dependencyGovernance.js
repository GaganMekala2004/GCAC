'use strict';

const fs = require('fs');
const path = require('path');
const { OUTCOME_STATUS } = require('../outcomeContract');
const { inspectRepositoryFeedConfigs, isPublicRegistryUrl } = require('./networkPolicy');

const DEPENDENCY_STATUS = Object.freeze({
    RESTORED_INTERNAL_MIRROR: 'RESTORED_INTERNAL_MIRROR',
    PREPROVISIONED_CACHE: 'PREPROVISIONED_CACHE',
    OFFLINE_NO_RESTORE: 'OFFLINE_NO_RESTORE',
    DEPENDENCY_UNAVAILABLE: 'DEPENDENCY_UNAVAILABLE',
    BLOCKED_UNAPPROVED_FEED: 'BLOCKED_UNAPPROVED_FEED'
});

const MISSING_DEPENDENCY_PATTERNS = [
    /error NETSDK1004/i,
    /Assets file .*project\.assets\.json.* not found/i,
    /Unable to resolve .* for '.NET/i,
    /error NU110[0-9]/i,
    /error NU1301/i,
    /Cannot access .* in offline mode/i,
    /Could not resolve dependencies for project/i,
    /The following artifacts could not be resolved/i,
    /npm error code ENOTCACHED/i,
    /npm ERR! code ENOTCACHED/i,
    /Cannot find module '/i,
    /offline mode.*no cached version/i
];

function hasNestedFile(rootDir, targetFileName, depth = 0) {
    if (depth > 3 || !rootDir || !fs.existsSync(rootDir)) return false;
    try {
        const entries = fs.readdirSync(rootDir, { withFileTypes: true });
        for (const e of entries) {
            if (e.isFile() && e.name === targetFileName) return true;
            if (!e.isDirectory()) continue;
            if (e.name === 'node_modules' || e.name === '.git' || e.name === 'bin' || e.name === 'obj') continue;
            if (hasNestedFile(path.join(rootDir, e.name), targetFileName, depth + 1)) return true;
        }
    } catch {}
    return false;
}

/**
 * Evaluates repository lockfile presence, offline dependency readiness,
 * and approved feed constraints before sandboxed execution.
 */
function assessDependencyGovernance(repoRoot, stack, options = {}) {
    const lockfiles = {
        packagesLockJson: repoRoot ? (fs.existsSync(path.join(repoRoot, 'packages.lock.json')) || hasNestedFile(repoRoot, 'packages.lock.json')) : false,
        directoryPackagesProps: repoRoot ? fs.existsSync(path.join(repoRoot, 'Directory.Packages.props')) : false,
        packageLockJson: repoRoot ? fs.existsSync(path.join(repoRoot, 'package-lock.json')) : false,
        npmShrinkwrapJson: repoRoot ? fs.existsSync(path.join(repoRoot, 'npm-shrinkwrap.json')) : false,
        pomXml: repoRoot ? fs.existsSync(path.join(repoRoot, 'pom.xml')) : false
    };

    const hasNugetAssets = repoRoot
        ? (fs.existsSync(path.join(repoRoot, 'obj', 'project.assets.json')) || hasNestedProjectAssets(repoRoot))
        : false;
    const hasLocalNodeModules = repoRoot ? fs.existsSync(path.join(repoRoot, 'node_modules')) : false;

    const feedCheck = repoRoot
        ? inspectRepositoryFeedConfigs(repoRoot)
        : { discoveredFeeds: [], credentialLeaks: [] };

    if (feedCheck.credentialLeaks.length > 0) {
        return {
            allowed: false,
            dependencyStatus: DEPENDENCY_STATUS.BLOCKED_UNAPPROVED_FEED,
            machineOutcome: OUTCOME_STATUS.BLOCKED,
            lockfiles,
            warnings: [],
            reason: `Embedded package feed credentials detected in ${feedCheck.credentialLeaks[0].file}.`
        };
    }

    const approvedMirrors = Array.isArray(options.approvedInternalMirrors)
        ? options.approvedInternalMirrors.map(u => String(u).toLowerCase())
        : [];
    const unapprovedPublicFeeds = feedCheck.discoveredFeeds.filter(f =>
        f.isPublicRegistry && !approvedMirrors.some(m => f.url.toLowerCase().startsWith(m))
    );

    const warnings = [];
    if (stack === 'dotnet' && !lockfiles.packagesLockJson && !lockfiles.directoryPackagesProps) {
        warnings.push('No packages.lock.json or Directory.Packages.props found; build relies on pre-provisioned NuGet cache with --no-restore.');
    }
    if (stack === 'nodejs' && !lockfiles.packageLockJson && !lockfiles.npmShrinkwrapJson) {
        warnings.push('No package-lock.json or npm-shrinkwrap.json found; reproducible offline npm install cannot be guaranteed.');
    }
    if (unapprovedPublicFeeds.length > 0 && options.allowRestoreFromPublic !== true) {
        warnings.push(`Repository references public package feed(s) [${unapprovedPublicFeeds.map(f => f.url).join(', ')}] which are unreachable in NO_NETWORK sandbox.`);
    }

    const cacheAvailable = Boolean(
        options.preprovisionedCacheDir && fs.existsSync(options.preprovisionedCacheDir)
    );

    let dependencyStatus = DEPENDENCY_STATUS.OFFLINE_NO_RESTORE;
    if (cacheAvailable || hasNugetAssets || hasLocalNodeModules) {
        dependencyStatus = DEPENDENCY_STATUS.PREPROVISIONED_CACHE;
    }

    return {
        allowed: true,
        dependencyStatus,
        machineOutcome: null,
        lockfiles,
        hasPreprovisionedArtifacts: cacheAvailable || hasNugetAssets || hasLocalNodeModules,
        cacheIsolationScope: 'PER_APP_OR_RUN_EPHEMERAL',
        publishCredentialsStripped: true,
        silentPackageUpgradeBlocked: true,
        discoveredFeeds: feedCheck.discoveredFeeds,
        warnings
    };
}

function hasNestedProjectAssets(rootDir, depth = 0) {
    if (depth > 3 || !fs.existsSync(rootDir)) return false;
    try {
        const entries = fs.readdirSync(rootDir, { withFileTypes: true });
        for (const e of entries) {
            if (!e.isDirectory()) continue;
            if (e.name === 'node_modules' || e.name === '.git') continue;
            const full = path.join(rootDir, e.name);
            if (e.name === 'obj' && fs.existsSync(path.join(full, 'project.assets.json'))) {
                return true;
            }
            if (hasNestedProjectAssets(full, depth + 1)) return true;
        }
    } catch {}
    return false;
}

/**
 * Inspects build/test stdout+stderr to detect missing dependencies accurately.
 * Missing dependencies must NEVER map to PASSED.
 */
function detectDependencyRestoreFailure(stdout = '', stderr = '') {
    const combined = `${stdout || ''}\n${stderr || ''}`;
    for (const rx of MISSING_DEPENDENCY_PATTERNS) {
        const m = combined.match(rx);
        if (m) {
            return {
                missingDependencies: true,
                dependencyStatus: DEPENDENCY_STATUS.DEPENDENCY_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
                matchedPattern: m[0],
                reason: `Dependencies unavailable in offline sandbox (${m[0]}). Configure an approved internal mirror or pre-provisioned cache.`
            };
        }
    }
    return {
        missingDependencies: false,
        dependencyStatus: null,
        machineStatus: null
    };
}

module.exports = {
    DEPENDENCY_STATUS,
    MISSING_DEPENDENCY_PATTERNS,
    assessDependencyGovernance,
    detectDependencyRestoreFailure
};

