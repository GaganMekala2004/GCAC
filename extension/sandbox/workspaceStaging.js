'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { assertPathWithinWorkspace } = require('../pathUtils');

const EXCLUDED_DIR_NAMES = new Set([
    '.git',
    '.github',
    '.vscode',
    '.agents',
    '.ssh',
    '.aws',
    '.azure',
    '.kube',
    '.gnupg',
    '.docker',
    'vulnerability',
    'remediation-output',
    'evidence',
    'output',
    'workspaces',
    'node_modules',
    'bin',
    'obj',
    'TestResults'
]);

const EXCLUDED_FILE_PATTERNS = [
    /^vulnerabilities\.csv$/i,
    /^vulnerabilities\.db(?:-wal|-shm|-journal)?$/i,
    /\.xlsx?$/i,
    /^\.env(?:\.[^.\s]+)?$/i,
    /\.(?:pem|key|pfx|p12|jks|keystore)$/i,
    /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
    /^credentials\.json$/i,
    /^\.netrc$/i,
    /^\.git-credentials$/i,
    /^\.gitconfig$/i,
    /^\.npmrc$/i,
    /^nuget\.config$/i
];

const SENSITIVE_ENV_KEY_PATTERN = /(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|SSH_|DOCKER_|AZURE_|AWS_|GH_|GITHUB_|NUGET_API|NPM_TOKEN|MAVEN_DEPLOY|USERPROFILE|HOMEPATH|APPDATA|LOCALAPPDATA)/i;

class StagingContainmentError extends Error {
    constructor(reason, code = 'STAGING_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'StagingContainmentError';
        this.code = code;
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

function canonicalPath(p) {
    const resolved = path.resolve(p);
    if (!fs.existsSync(resolved)) return resolved;
    try {
        return typeof fs.realpathSync.native === 'function'
            ? fs.realpathSync.native(resolved)
            : fs.realpathSync(resolved);
    } catch {
        return resolved;
    }
}

function isExcludedRelativePath(relPath, options = {}) {
    const norm = String(relPath || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (!norm) return false;
    const segments = norm.split('/').filter(Boolean);
    for (let i = 0; i < segments.length; i++) {
        const seg = segments[i];
        if (seg === '.git' && options.allowGitMetadata === true) continue;
        if (i < segments.length - 1 && EXCLUDED_DIR_NAMES.has(seg)) {
            return true;
        }
        if (i === segments.length - 1) {
            if (EXCLUDED_DIR_NAMES.has(seg)) return true;
            if (EXCLUDED_FILE_PATTERNS.some(rx => rx.test(seg))) return true;
        }
    }
    return false;
}

/**
 * Builds a credential-free environment map for sandboxed container execution.
 * Never inherits arbitrary host process.env variables.
 */
function buildSanitizedContainerEnv(extraEnv = {}) {
    const baseEnv = {
        CI: 'true',
        DOTNET_CLI_TELEMETRY_OPTOUT: '1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1',
        DOTNET_NOLOGO: '1',
        DOTNET_CLI_HOME: '/sandbox-home',
        HOME: '/sandbox-home',
        NUGET_PACKAGES: '/sandbox-cache/nuget',
        MAVEN_USER_HOME: '/sandbox-cache/m2',
        NPM_CONFIG_CACHE: '/sandbox-cache/npm',
        NPM_CONFIG_UPDATE_NOTIFIER: 'false'
    };

    if (extraEnv && typeof extraEnv === 'object') {
        for (const [k, v] of Object.entries(extraEnv)) {
            if (!/^[A-Z0-9_]{1,64}$/.test(k)) {
                throw new StagingContainmentError(`Invalid sandbox environment variable key '${k}'.`, 'INVALID_SANDBOX_ENV');
            }
            if (SENSITIVE_ENV_KEY_PATTERN.test(k)) {
                throw new StagingContainmentError(`Credential/host environment variable '${k}' is forbidden in sandbox.`, 'FORBIDDEN_SANDBOX_ENV');
            }
            if (typeof v !== 'string' || v.includes('\0') || /[\r\n]/.test(v)) {
                throw new StagingContainmentError(`Invalid value for sandbox environment variable '${k}'.`, 'INVALID_SANDBOX_ENV');
            }
            baseEnv[k] = v;
        }
    }

    return baseEnv;
}

class WorkspaceStagingManager {
    constructor(options = {}) {
        const rawRoot = options.stagingRoot
            ? path.resolve(options.stagingRoot)
            : path.join(os.tmpdir(), 'gcac-sandbox-staging');
        fs.mkdirSync(rawRoot, { recursive: true });
        this.stagingRoot = canonicalPath(rawRoot);
    }

    /**
     * Stages a minimized, credential-free source snapshot into a disposable directory
     * strictly contained under this.stagingRoot. Rejects symlinks and excludes secrets/master data.
     */
    stageWorkspace(params = {}) {
        const {
            instanceId,
            runId,
            sourceRoot,
            allowGitMetadata = false,
            allowCacheReuse = false,
            appCacheDir = null
        } = params;

        if (!instanceId || !/^[A-Za-z0-9_.-]{6,128}$/.test(String(instanceId))) {
            throw new StagingContainmentError('Valid instanceId is required for workspace staging.');
        }
        if (!runId || !/^[A-Za-z0-9_.-]{6,128}$/.test(String(runId))) {
            throw new StagingContainmentError('Valid runId is required for workspace staging.');
        }
        if (!sourceRoot || typeof sourceRoot !== 'string' || !fs.existsSync(sourceRoot)) {
            throw new StagingContainmentError(`Source workspace does not exist: '${sourceRoot}'.`);
        }

        const canonicalSource = canonicalPath(sourceRoot);
        if (!fs.statSync(canonicalSource).isDirectory()) {
            throw new StagingContainmentError(`Source workspace is not a directory: '${canonicalSource}'.`);
        }

        const instanceDirRaw = path.join(this.stagingRoot, instanceId);
        const instanceDir = assertPathWithinWorkspace(instanceDirRaw, this.stagingRoot);
        if (!instanceDir || instanceDir === this.stagingRoot) {
            throw new StagingContainmentError('Staging instance directory failed containment check.');
        }
        if (fs.existsSync(instanceDir)) {
            throw new StagingContainmentError(`Staging instance directory already exists for '${instanceId}'.`);
        }

        const workDir = path.join(instanceDir, 'work');
        const outDir = path.join(instanceDir, 'out');
        const homeDir = path.join(instanceDir, 'home');
        const cacheDir = (allowCacheReuse && appCacheDir)
            ? path.resolve(appCacheDir)
            : path.join(instanceDir, 'cache');

        fs.mkdirSync(workDir, { recursive: true });
        fs.mkdirSync(outDir, { recursive: true });
        fs.mkdirSync(homeDir, { recursive: true });
        fs.mkdirSync(cacheDir, { recursive: true });

        const excludedPaths = [];
        const stagedFiles = [];
        const hashAccumulator = crypto.createHash('sha256');

        const copySafe = (srcDir, relBase = '') => {
            const entries = fs.readdirSync(srcDir, { withFileTypes: true });
            entries.sort((a, b) => a.name.localeCompare(b.name));

            for (const entry of entries) {
                const srcAbs = path.join(srcDir, entry.name);
                const rel = relBase ? `${relBase}/${entry.name}` : entry.name;

                if (entry.isSymbolicLink()) {
                    throw new StagingContainmentError(
                        `Symbolic link '${rel}' detected inside source workspace; symlinks are prohibited during sandbox staging.`,
                        'SYMLINK_ESCAPE_BLOCKED',
                        { relPath: rel }
                    );
                }

                if (isExcludedRelativePath(rel, { allowGitMetadata })) {
                    excludedPaths.push(rel);
                    continue;
                }

                const destAbs = assertPathWithinWorkspace(path.join(workDir, rel), workDir);
                if (!destAbs) {
                    throw new StagingContainmentError(`Path traversal detected in staging path '${rel}'.`, 'PATH_TRAVERSAL_BLOCKED');
                }

                if (entry.isDirectory()) {
                    fs.mkdirSync(destAbs, { recursive: true });
                    copySafe(srcAbs, rel);
                } else if (entry.isFile()) {
                    fs.mkdirSync(path.dirname(destAbs), { recursive: true });
                    const buf = fs.readFileSync(srcAbs);
                    fs.writeFileSync(destAbs, buf);
                    stagedFiles.push(rel);
                    hashAccumulator.update(rel + ':');
                    hashAccumulator.update(buf);
                }
            }
        };

        try {
            copySafe(canonicalSource, '');
        } catch (err) {
            try { fs.rmSync(instanceDir, { recursive: true, force: true }); } catch {}
            throw err;
        }

        return {
            instanceId,
            runId,
            stagingRoot: this.stagingRoot,
            instanceDir,
            workDir,
            outDir,
            homeDir,
            cacheDir,
            sourceRoot: canonicalSource,
            stagedFilesCount: stagedFiles.length,
            stagedFiles,
            excludedPaths,
            stagingManifestSha256: hashAccumulator.digest('hex'),
            createdAt: new Date().toISOString()
        };
    }

    /**
     * Safely removes ONLY an owned instance directory strictly inside this.stagingRoot.
     */
    cleanupStaging(instanceDir) {
        if (!instanceDir || typeof instanceDir !== 'string') {
            throw new StagingContainmentError('cleanupStaging requires a valid instanceDir.');
        }
        const safeTarget = assertPathWithinWorkspace(canonicalPath(instanceDir), this.stagingRoot);
        if (!safeTarget || path.resolve(safeTarget) === path.resolve(this.stagingRoot)) {
            throw new StagingContainmentError(
                `Refusing cleanup outside staging root '${this.stagingRoot}': '${instanceDir}'.`,
                'CLEANUP_ESCAPE_BLOCKED'
            );
        }
        if (fs.existsSync(safeTarget)) {
            fs.rmSync(safeTarget, { recursive: true, force: true });
        }
        return { cleaned: true, instanceDir: safeTarget };
    }
}

module.exports = {
    EXCLUDED_DIR_NAMES,
    EXCLUDED_FILE_PATTERNS,
    StagingContainmentError,
    isExcludedRelativePath,
    buildSanitizedContainerEnv,
    WorkspaceStagingManager
};

