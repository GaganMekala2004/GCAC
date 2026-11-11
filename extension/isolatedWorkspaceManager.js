'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { assertPathWithinWorkspace } = require('./pathUtils');
const { assertPathWithinAuthorizedRoots, isUninitializedGitSubmodule } = require('./repositoryContext');

const EXCLUDED_CONFIDENTIAL_PATTERNS = [
    /(?:^|[\\/])vulnerability[\\/]vulnerabilities\.csv$/i,
    /(?:^|[\\/])vulnerabilities\.csv$/i,
    /(?:^|[\\/])vulnerabilities\.db(?:-wal|-shm)?$/i,
    /\.xlsx?$/i,
    /(?:^|[\\/])\.env(?:\.[^\\/\s]+)?$/i,
    /\.(?:pem|key|pfx|p12|jks|keystore)$/i,
    /(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
    /(?:^|[\\/])credentials\.json$/i
];

class IsolatedWorkspaceBlockedError extends Error {
    constructor(reason, details = {}) {
        super(`BLOCKED (IsolatedWorkspace): ${reason}`);
        this.name = 'IsolatedWorkspaceBlockedError';
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

function isRemoteGitUrl(candidate) {
    if (!candidate || typeof candidate !== 'string') return false;
    return /^(?:https?:\/\/|ssh:\/\/|git:\/\/|git@|file:\/\/)/i.test(candidate.trim());
}

function isConfidentialExcludedPath(relPath) {
    const norm = String(relPath || '').replace(/\\/g, '/');
    return EXCLUDED_CONFIDENTIAL_PATTERNS.some(rx => rx.test(norm));
}

/**
 * Safe local per-run isolated Git worktree manager.
 *
 * Important Security Boundary Disclosure:
 * A Git worktree provides working-copy separation (preventing edits from touching
 * the developer's active checkout or uncommitted changes). It is NOT an OS/container
 * credential or network sandbox — those controls belong to Phase 3.
 */
function canonicalExistingPath(targetPath) {
    const resolved = path.resolve(targetPath);
    if (!fs.existsSync(resolved)) return resolved;
    try {
        return typeof fs.realpathSync.native === 'function'
            ? fs.realpathSync.native(resolved)
            : fs.realpathSync(resolved);
    } catch {
        return resolved;
    }
}

class IsolatedWorkspaceManager {
    constructor(workspaceRoot, options = {}) {
        if (!workspaceRoot || typeof workspaceRoot !== 'string') {
            throw new IsolatedWorkspaceBlockedError('workspaceRoot is required.');
        }
        this.workspaceRoot = canonicalExistingPath(workspaceRoot);
        const rawAuth = Array.isArray(options.authorizedRoots) ? options.authorizedRoots : [];
        this.authorizedRoots = Array.from(new Set([
            this.workspaceRoot,
            ...rawAuth.filter(r => typeof r === 'string' && r.trim()).map(r => canonicalExistingPath(r))
        ]));
        const wsHash = crypto.createHash('sha256').update(this.workspaceRoot, 'utf8').digest('hex').slice(0, 12);
        const rawRunsRoot = options.runsRoot
            ? path.resolve(options.runsRoot)
            : path.join(os.tmpdir(), 'gcac-isolated-runs', wsHash);
        fs.mkdirSync(rawRunsRoot, { recursive: true });
        this.runsRoot = canonicalExistingPath(rawRunsRoot);
    }

    setAuthorizedRoots(roots = []) {
        this.authorizedRoots = Array.from(new Set([
            this.workspaceRoot,
            ...(Array.isArray(roots) ? roots : []).filter(r => typeof r === 'string' && r.trim()).map(r => canonicalExistingPath(r))
        ]));
    }

    _runGit(cwd, args) {
        return execFileSync('git', args, {
            cwd,
            encoding: 'utf8',
            shell: false,
            timeout: 15000,
            env: {
                ...process.env,
                GIT_TERMINAL_PROMPT: '0',
                GCM_INTERACTIVE: 'never'
            },
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
    }

    /**
     * Creates an isolated per-run git worktree + agent-facing sanitized context folder.
     * Fails closed with IsolatedWorkspaceBlockedError if a safe worktree cannot be created.
     */
    createIsolatedWorkspace(params = {}) {
        const {
            runId,
            vulnerabilityId,
            applicationId,
            repositoryPath,
            expectedFileRelPath = null,
            minimizedFinding = null
        } = params;

        // 1. Validate single-run identity (SEC-02)
        if (!runId || typeof runId !== 'string' || !/^[A-Za-z0-9_.-]{6,128}$/.test(runId.trim())) {
            throw new IsolatedWorkspaceBlockedError('Valid single runId is required.');
        }
        if (!vulnerabilityId || typeof vulnerabilityId !== 'string' || !/^[A-Za-z0-9_.-]{3,64}$/.test(vulnerabilityId.trim())) {
            throw new IsolatedWorkspaceBlockedError('Valid single vulnerabilityId is required.');
        }
        if (!applicationId || typeof applicationId !== 'string' || applicationId.includes(',')) {
            throw new IsolatedWorkspaceBlockedError('Single unambiguous applicationId is required.');
        }
        if (!repositoryPath || typeof repositoryPath !== 'string' || isRemoteGitUrl(repositoryPath)) {
            throw new IsolatedWorkspaceBlockedError('Remote repository URLs and empty paths are prohibited; local workspace repository required.');
        }

        // 2. Validate workspace & resolve approved repository root inside authorized roots
        if (!fs.existsSync(this.workspaceRoot) || !fs.statSync(this.workspaceRoot).isDirectory()) {
            throw new IsolatedWorkspaceBlockedError(`Workspace root does not exist: ${this.workspaceRoot}`);
        }
        const effectiveAllowedRoots = Array.from(new Set([
            ...this.authorizedRoots,
            ...(Array.isArray(params.authorizedRoots) ? params.authorizedRoots.map(r => canonicalExistingPath(r)) : [])
        ]));
        const authRepoMatch = assertPathWithinAuthorizedRoots(repositoryPath, effectiveAllowedRoots);
        const safeRepoAbs = authRepoMatch ? authRepoMatch.canonicalPath : null;
        const matchedAuthorizedRoot = authRepoMatch ? authRepoMatch.authorizedRoot : this.workspaceRoot;

        if (!safeRepoAbs || !fs.existsSync(safeRepoAbs) || !fs.statSync(safeRepoAbs).isDirectory()) {
            throw new IsolatedWorkspaceBlockedError(`Repository path '${repositoryPath}' is missing or outside workspace boundary.`);
        }

        if (isUninitializedGitSubmodule(safeRepoAbs, matchedAuthorizedRoot)) {
            throw new IsolatedWorkspaceBlockedError(`Repository '${repositoryPath}' is an uninitialized Git submodule / gitlink without checked-out source files.`);
        }

        // 3. Verify Git repository state without running fetch/push/reset/clean
        let gitTopLevel;
        let baseCommitSha;
        try {
            gitTopLevel = canonicalExistingPath(this._runGit(safeRepoAbs, ['rev-parse', '--show-toplevel']));
            const safeGitTopMatch = assertPathWithinAuthorizedRoots(gitTopLevel, effectiveAllowedRoots);
            if (!safeGitTopMatch) {
                throw new IsolatedWorkspaceBlockedError(
                    `Ambiguous Git root '${gitTopLevel}' sits outside approved workspace/repository root.`
                );
            }
            gitTopLevel = safeGitTopMatch.canonicalPath;
            baseCommitSha = this._runGit(gitTopLevel, ['rev-parse', '--verify', 'HEAD']);
        } catch (err) {
            if (err instanceof IsolatedWorkspaceBlockedError) throw err;
            throw new IsolatedWorkspaceBlockedError(`Approved Git repository state unavailable (requires committed HEAD): ${err.message}`);
        }

        if (!/^[0-9a-f]{40,64}$/i.test(baseCommitSha)) {
            throw new IsolatedWorkspaceBlockedError('Unable to resolve valid base commit SHA.');
        }

        // 4. Create strictly isolated per-run directories inside runsRoot
        const cleanRunSegment = `${vulnerabilityId.replace(/[^A-Za-z0-9_.-]/g, '_')}_${runId.replace(/[^A-Za-z0-9_.-]/g, '_')}`;
        const runDir = path.join(this.runsRoot, cleanRunSegment);
        const safeRunDir = assertPathWithinWorkspace(runDir, this.runsRoot);
        if (!safeRunDir || safeRunDir === this.runsRoot) {
            throw new IsolatedWorkspaceBlockedError('Run directory containment check failed.');
        }
        if (fs.existsSync(safeRunDir)) {
            throw new IsolatedWorkspaceBlockedError(`Isolated run directory already exists for runId '${runId}'.`);
        }

        const worktreeDir = path.join(safeRunDir, 'worktree');
        const agentContextDir = path.join(safeRunDir, 'agent-context');
        fs.mkdirSync(safeRunDir, { recursive: true });

        try {
            // Detached HEAD worktree leaves developer's active branch & uncommitted edits completely untouched
            this._runGit(gitTopLevel, ['worktree', 'add', '--detach', worktreeDir, baseCommitSha]);
        } catch (err) {
            try { fs.rmSync(safeRunDir, { recursive: true, force: true }); } catch {}
            throw new IsolatedWorkspaceBlockedError(`Failed to create isolated git worktree: ${err.message}`);
        }

        const repoRelFromGitRoot = path.relative(gitTopLevel, safeRepoAbs);
        const isolatedRepoPath = repoRelFromGitRoot ? path.join(worktreeDir, repoRelFromGitRoot) : worktreeDir;
        const safeIsolatedRepo = assertPathWithinWorkspace(isolatedRepoPath, worktreeDir);
        if (!safeIsolatedRepo || !fs.existsSync(safeIsolatedRepo)) {
            this.cleanupWorkspace({ runDir: safeRunDir, worktreeDir, gitRoot: gitTopLevel });
            throw new IsolatedWorkspaceBlockedError('Target repository subpath missing inside isolated worktree.');
        }

        // 5. Verify expected target file is available inside isolated worktree (if provided)
        let isolatedTargetFile = null;
        if (expectedFileRelPath && typeof expectedFileRelPath === 'string') {
            const candidateInRepo = assertPathWithinWorkspace(path.join(safeIsolatedRepo, expectedFileRelPath), safeIsolatedRepo);
            const candidateInWorktree = assertPathWithinWorkspace(path.join(worktreeDir, expectedFileRelPath), worktreeDir);
            if (candidateInRepo && fs.existsSync(candidateInRepo) && fs.statSync(candidateInRepo).isFile()) {
                isolatedTargetFile = candidateInRepo;
            } else if (candidateInWorktree && fs.existsSync(candidateInWorktree) && fs.statSync(candidateInWorktree).isFile()) {
                isolatedTargetFile = candidateInWorktree;
            } else {
                this.cleanupWorkspace({ runDir: safeRunDir, worktreeDir, gitRoot: gitTopLevel });
                throw new IsolatedWorkspaceBlockedError(`Expected target file '${expectedFileRelPath}' not found inside isolated worktree.`);
            }
        }

        // 6. Prepare sanitized agent-facing context folder excluding master CSVs/DBs/confidential files
        fs.mkdirSync(agentContextDir, { recursive: true });
        if (minimizedFinding && typeof minimizedFinding === 'object') {
            fs.writeFileSync(
                path.join(agentContextDir, 'minimized-finding.json'),
                JSON.stringify(minimizedFinding, null, 2),
                'utf8'
            );
        }
        if (isolatedTargetFile && !isConfidentialExcludedPath(path.relative(worktreeDir, isolatedTargetFile))) {
            const destTarget = path.join(agentContextDir, path.basename(isolatedTargetFile));
            fs.copyFileSync(isolatedTargetFile, destTarget);
        }

        const excludedDetected = this._scanExcludedFiles(worktreeDir);

        return {
            runId,
            vulnerabilityId,
            applicationId,
            isolationMode: 'GIT_WORKTREE_DETACHED',
            sandboxLimitationNote: 'Git worktree isolates working files only; host credentials and network egress require Phase 3 container/CI sandbox.',
            originalWorkspaceRoot: this.workspaceRoot,
            originalGitRoot: gitTopLevel,
            originalRepoPath: safeRepoAbs,
            baseCommitSha,
            runsRoot: this.runsRoot,
            runDir: safeRunDir,
            worktreeDir,
            isolatedRepoPath: safeIsolatedRepo,
            isolatedTargetFile,
            agentContextDir,
            excludedConfidentialPaths: excludedDetected,
            createdAt: new Date().toISOString()
        };
    }

    _scanExcludedFiles(rootDir) {
        const excluded = [];
        const walk = (dir) => {
            let entries = [];
            try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
            for (const entry of entries) {
                if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'bin' || entry.name === 'obj') continue;
                const full = path.join(dir, entry.name);
                const rel = path.relative(rootDir, full).replace(/\\/g, '/');
                if (entry.isDirectory()) {
                    walk(full);
                } else if (isConfidentialExcludedPath(rel)) {
                    excluded.push(rel);
                }
            }
        };
        walk(rootDir);
        return excluded;
    }

    /**
     * Lists non-confidential agent-facing files in the isolated worktree.
     */
    getAgentFacingFiles(isolatedWorkspace) {
        const results = [];
        if (!isolatedWorkspace || !isolatedWorkspace.isolatedRepoPath || !fs.existsSync(isolatedWorkspace.isolatedRepoPath)) {
            return results;
        }
        const walk = (dir) => {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'bin' || entry.name === 'obj') continue;
                const full = path.join(dir, entry.name);
                const relFromWorktree = path.relative(isolatedWorkspace.worktreeDir, full).replace(/\\/g, '/');
                if (entry.isDirectory()) {
                    walk(full);
                } else if (!isConfidentialExcludedPath(relFromWorktree)) {
                    results.push(relFromWorktree);
                }
            }
        };
        walk(isolatedWorkspace.isolatedRepoPath);
        return results;
    }

    /**
     * Safely removes ONLY the designated run directory inside this.runsRoot.
     * Never deletes outside this.runsRoot or inside original repositories.
     */
    cleanupWorkspace(handle = {}) {
        const targetRunDir = handle.runDir;
        if (!targetRunDir || typeof targetRunDir !== 'string') {
            throw new IsolatedWorkspaceBlockedError('Cannot cleanup workspace without a valid runDir.');
        }

        const safeRunDir = assertPathWithinWorkspace(canonicalExistingPath(targetRunDir), this.runsRoot);
        if (!safeRunDir || path.resolve(safeRunDir) === path.resolve(this.runsRoot)) {
            throw new IsolatedWorkspaceBlockedError(
                `Refusing cleanup outside designated run root '${this.runsRoot}': '${targetRunDir}'.`
            );
        }

        if (handle.gitRoot && handle.worktreeDir && fs.existsSync(handle.gitRoot)) {
            const safeWorktree = assertPathWithinWorkspace(handle.worktreeDir, safeRunDir);
            if (safeWorktree) {
                try {
                    this._runGit(handle.gitRoot, ['worktree', 'remove', '--force', safeWorktree]);
                } catch {
                    // Fallback to removing directory inside safeRunDir + pruning stale worktree admin metadata
                    try { this._runGit(handle.gitRoot, ['worktree', 'prune']); } catch {}
                }
            }
        }

        if (fs.existsSync(safeRunDir)) {
            fs.rmSync(safeRunDir, { recursive: true, force: true });
        }

        return { cleaned: true, runDir: safeRunDir };
    }
}

module.exports = {
    IsolatedWorkspaceManager,
    IsolatedWorkspaceBlockedError,
    isRemoteGitUrl,
    isConfidentialExcludedPath
};
