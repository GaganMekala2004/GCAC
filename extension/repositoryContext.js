'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { assertPathWithinWorkspace } = require('./pathUtils');

const FINDING_CONTEXT_SCHEMA_VERSION = 'GCAC-FINDING-CTX-1.0';

const IGNORED_SCAN_DIRS = new Set([
    '.git', '.github', '.vscode', '.agents', 'node_modules',
    'bin', 'obj', 'output', 'remediation-output', 'evidence',
    'workspaces', 'TestResults', '.gcac', 'target'
]);

const SENSITIVE_DIR_PATTERNS = [
    /(?:^|[\\/])\.(?:ssh|aws|azure|kube|gnupg|docker)(?:[\\/]|$)/i
];

function canonicalizePath(targetPath) {
    if (!targetPath || typeof targetPath !== 'string') return '';
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

function normalizePosix(p) {
    return String(p || '').replace(/\\/g, '/');
}

function isRemoteRepositoryReference(candidate) {
    if (!candidate || typeof candidate !== 'string') return false;
    return /^(?:https?:\/\/|ssh:\/\/|git:\/\/|git@|file:\/\/)/i.test(candidate.trim());
}

function isSensitiveSystemOrCredentialRoot(candidatePath) {
    if (!candidatePath || typeof candidatePath !== 'string') return true;
    const norm = canonicalizePath(candidatePath);
    const lower = norm.toLowerCase().replace(/[\\/]+$/, '') || path.sep;
    const parsed = path.parse(norm);
    const rootLower = parsed.root.toLowerCase().replace(/[\\/]+$/, '') || path.sep;
    if (lower === rootLower) return true;

    const blockedExact = [
        os.homedir(),
        process.env.USERPROFILE,
        process.env.HOME,
        '/root',
        '/home',
        '/users',
        'c:\\users',
        'c:\\windows',
        '/etc',
        '/var',
        '/usr',
        '/bin'
    ].filter(Boolean).map(p => canonicalizePath(p).toLowerCase().replace(/[\\/]+$/, ''));

    if (blockedExact.includes(lower)) return true;
    if (SENSITIVE_DIR_PATTERNS.some(rx => rx.test(norm))) return true;
    return false;
}

function isPathWithinRoot(candidatePath, rootPath) {
    return Boolean(assertPathWithinWorkspace(candidatePath, rootPath));
}

/**
 * Validates that candidatePath is contained strictly inside at least one authorized root.
 * Returns { canonicalPath, authorizedRoot } or null.
 */
function assertPathWithinAuthorizedRoots(candidatePath, authorizedRoots = []) {
    if (!candidatePath || typeof candidatePath !== 'string') return null;
    const roots = (Array.isArray(authorizedRoots) ? authorizedRoots : [authorizedRoots])
        .filter(r => typeof r === 'string' && r.trim().length > 0);

    for (const root of roots) {
        const resolvedCandidate = path.isAbsolute(candidatePath)
            ? candidatePath
            : path.resolve(root, candidatePath);
        const safe = assertPathWithinWorkspace(resolvedCandidate, root);
        if (safe) {
            return {
                canonicalPath: safe,
                authorizedRoot: canonicalizePath(root)
            };
        }
    }
    return null;
}

function safeGit(cwd, args) {
    try {
        return execFileSync('git', args, {
            cwd,
            encoding: 'utf8',
            shell: false,
            timeout: 5000,
            env: {
                ...process.env,
                GIT_TERMINAL_PROMPT: '0',
                GCM_INTERACTIVE: 'never'
            },
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
    } catch {
        return null;
    }
}

function isDirectoryEmptyOfEntries(dirPath) {
    try {
        const entries = fs.readdirSync(dirPath);
        return entries.length === 0;
    } catch {
        return true;
    }
}

/**
 * Checks whether targetDir is an uninitialized Git submodule or gitlink in a parent repository.
 */
function isUninitializedGitSubmodule(targetDir, workspaceRoot = null) {
    if (!targetDir || !fs.existsSync(targetDir)) return false;
    let stat;
    try { stat = fs.statSync(targetDir); } catch { return false; }
    if (!stat.isDirectory()) return false;

    const dotGitPath = path.join(targetDir, '.git');
    if (fs.existsSync(dotGitPath)) {
        // Detect broken submodule .git file pointing to a nonexistent gitdir when folder has no checked-out files
        try {
            const st = fs.statSync(dotGitPath);
            if (st.isFile()) {
                const entries = fs.readdirSync(targetDir);
                const rawGit = fs.readFileSync(dotGitPath, 'utf8');
                const m = rawGit.match(/gitdir:\s*(.+)/i);
                const resolvedGitDir = m ? path.resolve(targetDir, m[1].trim()) : '';
                if (entries.length === 1 && (!resolvedGitDir || !fs.existsSync(resolvedGitDir))) {
                    return true;
                }
            }
        } catch { }
        return false;
    }

    if (!isDirectoryEmptyOfEntries(targetDir)) {
        return false;
    }

    const parentDir = workspaceRoot && isPathWithinRoot(targetDir, workspaceRoot)
        ? canonicalizePath(workspaceRoot)
        : path.dirname(canonicalizePath(targetDir));
    const parentGitTop = safeGit(parentDir, ['rev-parse', '--show-toplevel']);
    if (!parentGitTop) return false;

    const rel = normalizePosix(path.relative(parentGitTop, canonicalizePath(targetDir)));
    if (!rel || rel.startsWith('..')) return false;

    const stageOut = safeGit(parentGitTop, ['ls-files', '--stage', '--', rel]);
    if (stageOut && /^160000\s+/m.test(stageOut)) {
        return true;
    }

    const gitmodulesPath = path.join(parentGitTop, '.gitmodules');
    if (fs.existsSync(gitmodulesPath)) {
        try {
            const txt = fs.readFileSync(gitmodulesPath, 'utf8');
            if (txt.includes(`path = ${rel}`)) return true;
        } catch { }
    }

    return false;
}

/**
 * Discovers project/dependency manifests and non-empty source files inside targetRoot.
 * Never escapes above targetRoot.
 */
function discoverProjectManifests(targetRoot, maxDepth = 5) {
    const manifests = {
        slnFiles: [],
        csprojFiles: [],
        packagesLockFiles: [],
        directoryPackagesProps: [],
        packagesConfigFiles: [],
        pomFiles: [],
        packageJsonFiles: [],
        packageLockFiles: [],
        gradleFiles: [],
        antFiles: [],
        pythonFiles: [],
        goModFiles: [],
        csprojTargets: [],
        hasAnyPackageReference: false
    };

    const sourceCounts = {
        csharp: 0,
        java: 0,
        javascript: 0,
        python: 0,
        config: 0,
        otherText: 0,
        emptyFiles: 0,
        totalFiles: 0,
        nonEmptyFiles: 0
    };

    if (!targetRoot || !fs.existsSync(targetRoot)) {
        return { manifests, sourceCounts };
    }

    const canonicalRoot = canonicalizePath(targetRoot);
    const rootStat = fs.statSync(canonicalRoot);

    const inspectSingleFile = (fullPath) => {
        const name = path.basename(fullPath);
        const lower = name.toLowerCase();
        const rel = normalizePosix(path.relative(canonicalRoot, fullPath)) || name;
        sourceCounts.totalFiles++;

        let size = 0;
        let nonEmpty = false;
        let contentPreview = '';
        try {
            const st = fs.statSync(fullPath);
            size = st.size;
            if (size > 0) {
                const readLen = Math.min(size, 65536);
                const fd = fs.openSync(fullPath, 'r');
                try {
                    const buf = Buffer.alloc(readLen);
                    const bytesRead = fs.readSync(fd, buf, 0, readLen, 0);
                    contentPreview = buf.slice(0, bytesRead).toString('utf8');
                    nonEmpty = contentPreview.trim().length > 0;
                } finally {
                    fs.closeSync(fd);
                }
            }
        } catch { }

        if (!nonEmpty) {
            sourceCounts.emptyFiles++;
            return;
        }
        sourceCounts.nonEmptyFiles++;

        if (lower.endsWith('.sln')) manifests.slnFiles.push(rel);
        else if (lower.endsWith('.csproj')) {
            manifests.csprojFiles.push(rel);
            const tfMatch = contentPreview.match(/<TargetFramework[s]?>([^<]+)<\/TargetFramework[s]?>/i);
            if (tfMatch) manifests.csprojTargets.push({ file: rel, targetFramework: tfMatch[1].trim() });
            if (/<PackageReference\b/i.test(contentPreview)) manifests.hasAnyPackageReference = true;
        }
        else if (lower === 'packages.lock.json') manifests.packagesLockFiles.push(rel);
        else if (lower === 'directory.packages.props') manifests.directoryPackagesProps.push(rel);
        else if (lower === 'packages.config') {
            manifests.packagesConfigFiles.push(rel);
            manifests.hasAnyPackageReference = true;
        }
        else if (lower === 'pom.xml') manifests.pomFiles.push(rel);
        else if (lower === 'package.json') manifests.packageJsonFiles.push(rel);
        else if (lower === 'package-lock.json' || lower === 'npm-shrinkwrap.json') manifests.packageLockFiles.push(rel);
        else if (lower === 'build.gradle' || lower === 'build.gradle.kts') manifests.gradleFiles.push(rel);
        else if (lower === 'build.xml') manifests.antFiles.push(rel);
        else if (lower === 'requirements.txt' || lower === 'pyproject.toml') manifests.pythonFiles.push(rel);
        else if (lower === 'go.mod') manifests.goModFiles.push(rel);

        if (lower.endsWith('.cs')) sourceCounts.csharp++;
        else if (lower.endsWith('.java')) sourceCounts.java++;
        else if (/\.(js|ts|jsx|tsx|mjs|cjs)$/i.test(lower)) sourceCounts.javascript++;
        else if (lower.endsWith('.py')) sourceCounts.python++;
        else if (/\.(json|config|xml|env|yaml|yml|properties)$/i.test(lower)) sourceCounts.config++;
        else sourceCounts.otherText++;
    };

    if (rootStat.isFile()) {
        inspectSingleFile(canonicalRoot);
        return { manifests, sourceCounts };
    }

    const walk = (dir, depth) => {
        if (depth > maxDepth) return;
        let entries = [];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const entry of entries) {
            if (entry.isSymbolicLink()) continue;
            if (entry.isDirectory()) {
                if (IGNORED_SCAN_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
                walk(path.join(dir, entry.name), depth + 1);
            } else if (entry.isFile()) {
                if (entry.name.startsWith('.') && entry.name !== '.env') continue;
                inspectSingleFile(path.join(dir, entry.name));
            }
        }
    };

    walk(canonicalRoot, 0);
    return { manifests, sourceCounts };
}

/**
 * Inspects a repository or file target, computing repositoryRoot, technology,
 * manifest coverage, uninitialized submodule status, and scannable input presence.
 */
function inspectRepositoryTarget(targetPath, optionsOrWs = {}, maybeRegistry = null) {
    const options = typeof optionsOrWs === 'string'
        ? { workspaceRoot: optionsOrWs, registry: maybeRegistry }
        : (optionsOrWs || {});
    const activeRegistry = options.registry || maybeRegistry || null;

    if (!targetPath || typeof targetPath !== 'string' || !fs.existsSync(targetPath)) {
        return {
            exists: false,
            canonicalTargetPath: targetPath ? path.resolve(targetPath) : '',
            repositoryRoot: '',
            canonicalRepositoryPath: '',
            canonicalRepositoryId: '',
            applicationNumber: '',
            applicationName: '',
            isDirectory: false,
            isGitRepo: false,
            gitTopLevel: null,
            isUninitializedSubmodule: false,
            manifests: null,
            sourceCounts: null,
            detectedTechnology: 'unknown',
            supported: false,
            unsupportedReason: 'Target path does not exist on disk.',
            hasScannableInputs: false
        };
    }

    const canonicalTarget = canonicalizePath(targetPath);
    const stat = fs.statSync(canonicalTarget);
    const isDir = stat.isDirectory();
    const workspaceRoot = options.workspaceRoot ? canonicalizePath(options.workspaceRoot) : null;

    let repoRoot = isDir ? canonicalTarget : path.dirname(canonicalTarget);
    let isGitRepo = false;
    let gitTopLevel = null;

    const uninitSubmodule = isDir && isUninitializedGitSubmodule(canonicalTarget, workspaceRoot);

    if (!uninitSubmodule) {
        const probedTop = safeGit(isDir ? canonicalTarget : path.dirname(canonicalTarget), ['rev-parse', '--show-toplevel']);
        if (probedTop) {
            const canonicalTop = canonicalizePath(probedTop);
            if (isDir) {
                // Only adopt gitTopLevel as repoRoot if gitTopLevel is inside target or equals target,
                // OR if target is a subfolder inside an authorized repo that doesn't have its own nested .git
                if (canonicalTop === canonicalTarget || isPathWithinRoot(canonicalTop, canonicalTarget)) {
                    repoRoot = canonicalTop;
                    isGitRepo = true;
                    gitTopLevel = canonicalTop;
                } else {
                    // Target is a subdirectory inside a larger git repository (e.g. monorepo or sample-repos/subdir without own .git)
                    repoRoot = canonicalTarget;
                    isGitRepo = true;
                    gitTopLevel = canonicalTop;
                }
            } else {
                // Single file: walk up only inside workspaceRoot/authorizedRoot
                const boundary = workspaceRoot && isPathWithinRoot(canonicalTarget, workspaceRoot) ? workspaceRoot : canonicalTop;
                if (isPathWithinRoot(canonicalTop, boundary) || canonicalTop === boundary) {
                    repoRoot = canonicalTop;
                } else {
                    repoRoot = boundary;
                }
                isGitRepo = true;
                gitTopLevel = canonicalTop;
            }
        }
    }

    const { manifests, sourceCounts } = discoverProjectManifests(isDir ? repoRoot : canonicalTarget);

    let detectedTechnology = 'unknown';
    let supported = false;
    let unsupportedReason = null;

    const hasDotnet = manifests.slnFiles.length > 0 || manifests.csprojFiles.length > 0 || sourceCounts.csharp > 0;
    const hasMaven = manifests.pomFiles.length > 0;
    const hasJava = hasMaven || sourceCounts.java > 0;
    const hasNode = manifests.packageJsonFiles.length > 0 || sourceCounts.javascript > 0;
    const hasGradle = manifests.gradleFiles.length > 0;
    const hasAnt = manifests.antFiles.length > 0;
    const hasPythonOnly = (manifests.pythonFiles.length > 0 || sourceCounts.python > 0) && !hasDotnet && !hasMaven && !hasNode;

    if (uninitSubmodule) {
        detectedTechnology = 'uninitialized-submodule';
        supported = false;
        unsupportedReason = 'Target directory is an uninitialized Git submodule / gitlink with no checked-out files.';
    } else if (sourceCounts.nonEmptyFiles === 0) {
        detectedTechnology = 'empty';
        supported = false;
        unsupportedReason = sourceCounts.emptyFiles > 0
            ? 'Repository contains only empty or whitespace-only files.'
            : 'Repository directory contains no scannable source or manifest files.';
    } else if (hasDotnet) {
        detectedTechnology = 'dotnet';
        supported = true;
    } else if (hasMaven) {
        detectedTechnology = 'java-spring';
        supported = true;
    } else if (hasGradle) {
        detectedTechnology = 'gradle';
        supported = false;
        unsupportedReason = 'Gradle build detected (build.gradle); automated Gradle build/test toolchain is not approved in Phase 3.';
    } else if (hasAnt) {
        detectedTechnology = 'ant';
        supported = false;
        unsupportedReason = 'Apache Ant build detected (build.xml); Ant toolchain is not approved in Phase 3.';
    } else if (hasJava) {
        detectedTechnology = 'java-spring';
        supported = true;
    } else if (hasNode) {
        detectedTechnology = 'nodejs';
        supported = true;
    } else if (hasPythonOnly) {
        detectedTechnology = 'python';
        supported = false;
        unsupportedReason = 'Python repository detected; Python build/test toolchain is not approved in Phase 3.';
    } else if (sourceCounts.config > 0) {
        detectedTechnology = 'config';
        supported = true;
    } else {
        detectedTechnology = 'unsupported';
        supported = false;
        unsupportedReason = 'No supported .NET, Java/Maven, Node.js, or config security inputs detected.';
    }

    const hasScannableInputs = !uninitSubmodule && sourceCounts.nonEmptyFiles > 0;
    const regEntry = activeRegistry ? activeRegistry.findByRepositoryPath(repoRoot) : null;

    return {
        exists: true,
        canonicalTargetPath: canonicalTarget,
        repositoryRoot: repoRoot,
        canonicalRepositoryPath: repoRoot,
        canonicalRepositoryId: computeCanonicalRepoId(repoRoot),
        applicationNumber: regEntry?.applicationNumber || '',
        applicationName: regEntry?.applicationName || '',
        isDirectory: isDir,
        isGitRepo,
        gitTopLevel,
        isUninitializedSubmodule: uninitSubmodule,
        manifests,
        sourceCounts,
        detectedTechnology,
        supported,
        unsupportedReason,
        hasScannableInputs
    };
}

function computeCanonicalRepoId(canonicalRepoRoot) {
    const norm = canonicalizePath(canonicalRepoRoot).replace(/\\/g, '/').toLowerCase();
    return crypto.createHash('sha256').update(norm, 'utf8').digest('hex').slice(0, 12);
}

function computeLocalApplicationId(canonicalRepoRoot) {
    return `LOCAL-${computeCanonicalRepoId(canonicalRepoRoot).slice(0, 8).toUpperCase()}`;
}

/**
 * Deterministic repository registry resolving enterprise mappings (config/repositories.json)
 * and explicitly registered local repositories (.gcac/local-repositories.json).
 */
class RepositoryContextRegistry {
    constructor(options = {}) {
        const opts = (typeof options === 'string') ? { workspaceRoot: options } : (options || {});
        this.extensionRoot = opts.extensionRoot ? canonicalizePath(opts.extensionRoot) : path.resolve(__dirname, '..');
        this.workspaceRoot = opts.workspaceRoot ? canonicalizePath(opts.workspaceRoot) : this.extensionRoot;
        this.localRegistryPath = opts.localRegistryPath
            || path.join(this.workspaceRoot, '.gcac', 'local-repositories.json');
        this.enterpriseMappings = new Map();
        this.localMappings = new Map();
        this.reload();
    }

    setWorkspaceRoot(workspaceRoot) {
        if (!workspaceRoot || typeof workspaceRoot !== 'string') return;
        const nextWs = canonicalizePath(workspaceRoot);
        if (nextWs === this.workspaceRoot) return;
        this.workspaceRoot = nextWs;
        this.localRegistryPath = path.join(this.workspaceRoot, '.gcac', 'local-repositories.json');
        this.reload();
    }

    reload() {
        this.enterpriseMappings.clear();
        this.localMappings.clear();

        const candidateEnterprisePaths = Array.from(new Set([
            path.join(this.workspaceRoot, 'config', 'repositories.json'),
            path.join(this.extensionRoot, 'config', 'repositories.json')
        ]));

        for (const cfgPath of candidateEnterprisePaths) {
            if (!fs.existsSync(cfgPath)) continue;
            try {
                const baseRoot = path.dirname(path.dirname(cfgPath));
                const raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
                for (const [appNum, entry] of Object.entries(raw || {})) {
                    if (!entry || typeof entry !== 'object' || !entry.repositoryUrl) continue;
                    if (isRemoteRepositoryReference(entry.repositoryUrl)) continue;
                    const absRepo = canonicalizePath(
                        path.isAbsolute(entry.repositoryUrl)
                            ? entry.repositoryUrl
                            : path.resolve(baseRoot, entry.repositoryUrl)
                    );
                    if (!this.enterpriseMappings.has(appNum)) {
                        this.enterpriseMappings.set(appNum, {
                            applicationNumber: appNum,
                            applicationName: entry.applicationName || path.basename(absRepo),
                            repositoryUrl: entry.repositoryUrl,
                            canonicalRepositoryPath: absRepo,
                            canonicalRepositoryId: computeCanonicalRepoId(absRepo),
                            technology: entry.technology || 'unknown',
                            defaultBranch: entry.defaultBranch || 'main',
                            identitySource: 'ENTERPRISE_REGISTRY'
                        });
                    }
                }
            } catch { }
        }

        if (fs.existsSync(this.localRegistryPath)) {
            try {
                const rawLocal = JSON.parse(fs.readFileSync(this.localRegistryPath, 'utf8'));
                const entries = Array.isArray(rawLocal) ? rawLocal : Object.values(rawLocal || {});
                for (const item of entries) {
                    if (!item || !item.canonicalRepositoryPath || !item.applicationNumber) continue;
                    if (isRemoteRepositoryReference(item.canonicalRepositoryPath)) continue;
                    const canon = canonicalizePath(item.canonicalRepositoryPath);
                    this.localMappings.set(canon.toLowerCase(), {
                        ...item,
                        canonicalRepositoryPath: canon,
                        canonicalRepositoryId: item.canonicalRepositoryId || computeCanonicalRepoId(canon),
                        identitySource: 'LOCAL_REGISTERED_REPOSITORY'
                    });
                }
            } catch { }
        }
    }

    _saveLocalRegistry() {
        try {
            const dir = path.dirname(this.localRegistryPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const arr = Array.from(this.localMappings.values());
            fs.writeFileSync(this.localRegistryPath, JSON.stringify(arr, null, 2), 'utf8');
        } catch { }
    }

    /**
     * Explicitly registers an authorized local repository and assigns a deterministic local identity
     * if it is not already mapped in enterprise config/repositories.json.
     */
    registerLocalRepository(repoPath, metadata = {}) {
        if (!repoPath || typeof repoPath !== 'string' || isRemoteRepositoryReference(repoPath)) {
            throw new Error('BLOCKED (INVALID_REPOSITORY): Remote or empty repository paths cannot be registered.');
        }
        if (!fs.existsSync(repoPath) || !fs.statSync(repoPath).isDirectory()) {
            throw new Error(`BLOCKED (INVALID_REPOSITORY): Repository directory does not exist: '${repoPath}'.`);
        }
        const canonical = canonicalizePath(repoPath);
        if (isSensitiveSystemOrCredentialRoot(canonical)) {
            throw new Error(`BLOCKED (SENSITIVE_PATH): Refusing to register OS/home/credential directory '${canonical}'.`);
        }

        const enterpriseMatch = this.findByRepositoryPath(canonical);
        if (enterpriseMatch) {
            return enterpriseMatch;
        }

        const inspection = inspectRepositoryTarget(canonical, { workspaceRoot: this.workspaceRoot });
        const appId = computeLocalApplicationId(canonical);
        const branch = safeGit(canonical, ['rev-parse', '--abbrev-ref', 'HEAD']) || 'main';

        const entry = {
            applicationNumber: appId,
            applicationName: metadata.applicationName || path.basename(canonical) || 'Local Repository',
            repositoryUrl: canonical,
            canonicalRepositoryPath: canonical,
            canonicalRepositoryId: computeCanonicalRepoId(canonical),
            technology: metadata.technology || (inspection.detectedTechnology !== 'empty' && inspection.detectedTechnology !== 'unknown'
                ? inspection.detectedTechnology
                : 'unknown'),
            defaultBranch: branch === 'HEAD' ? 'main' : branch,
            identitySource: 'LOCAL_REGISTERED_REPOSITORY',
            registeredAt: new Date().toISOString()
        };

        this.localMappings.set(canonical.toLowerCase(), entry);
        this._saveLocalRegistry();
        return entry;
    }

    resolveOrRegisterRepository(repoPath, metadata = {}) {
        return this.registerLocalRepository(repoPath, metadata);
    }

    findByRepositoryPath(repoPath) {
        if (!repoPath || typeof repoPath !== 'string') return null;
        const canonical = canonicalizePath(repoPath);
        const lower = canonical.toLowerCase();

        for (const entry of this.enterpriseMappings.values()) {
            if (entry.canonicalRepositoryPath.toLowerCase() === lower) {
                return entry;
            }
        }
        if (this.localMappings.has(lower)) {
            return this.localMappings.get(lower);
        }
        return null;
    }

    findByApplicationId(appId) {
        if (!appId || typeof appId !== 'string') return null;
        const trimmed = appId.trim();
        for (const [k, v] of this.enterpriseMappings.entries()) {
            if (k.toUpperCase() === trimmed.toUpperCase()) return v;
        }
        for (const v of this.localMappings.values()) {
            if (String(v.applicationNumber).toUpperCase() === trimmed.toUpperCase()) return v;
        }
        return null;
    }

    getAllAuthorizedRepositoryRoots() {
        const roots = new Set();
        for (const e of this.enterpriseMappings.values()) {
            if (fs.existsSync(e.canonicalRepositoryPath)) roots.add(e.canonicalRepositoryPath);
        }
        for (const l of this.localMappings.values()) {
            if (fs.existsSync(l.canonicalRepositoryPath)) roots.add(l.canonicalRepositoryPath);
        }
        return Array.from(roots);
    }
}

/**
 * Extracts normalized fields from any finding object regardless of naming convention
 * (CSV uppercase snake_case, camelCase NormalizedFinding, or .NET PascalCase/JSON).
 */
function normalizeFindingMetadataFields(finding = {}) {
    const pick = (...vals) => {
        for (const v of vals) {
            if (typeof v === 'string' && v.trim().length > 0) return v.trim();
        }
        return '';
    };

    return {
        findingId: pick(finding.Vulnerability_ID, finding.vulnerabilityId, finding.findingId),
        applicationId: pick(finding.Application_Number, finding.applicationNumber, finding.applicationId, finding.ApplicationId),
        applicationName: pick(finding.Application_Name, finding.applicationName),
        applicationIdentitySource: pick(finding.Application_Identity_Source, finding.applicationIdentitySource),
        repository: pick(finding.Repository, finding.repository, finding.repositoryPath, finding.targetRepo),
        repositoryRoot: pick(finding.Repository_Root, finding.repositoryRoot, finding.workspaceRoot),
        canonicalRepositoryId: pick(finding.Canonical_Repository_ID, finding.canonicalRepositoryId),
        projectPath: pick(finding.Project_Path, finding.projectPath, finding.manifestPath),
        scannerId: pick(finding.Scanner_ID, finding.scannerId, finding.scanner_id),
        scanExecutionId: pick(finding.Scan_ID, finding.scanId, finding.scanExecutionId),
        sourceOrigin: pick(finding.Source_Origin, finding.Source_Type, finding.sourceClassification),
        detectionMethod: pick(finding.Detection_Method, finding.detectionMethod),
        findingFingerprint: pick(finding.Finding_Fingerprint, finding.findingFingerprint, finding.fingerprint),
        originalSeverity: pick(finding.Severity, finding.severity, finding.authoritativeSeverity),
        locationPath: pick(finding.Location_Path, finding.locationPath, finding.filePath),
        lineNumber: parseInt(finding.Line_Number ?? finding.line ?? 1, 10) || 1,
        technology: pick(finding.Technology, finding.technology)
    };
}

/**
 * Builds canonical versioned finding-to-repository context contract (GCAC-FINDING-CTX-1.0).
 */
function buildCanonicalFindingContext(finding = {}, repoResolution = null) {
    const norm = normalizeFindingMetadataFields(finding);
    const repoPath = repoResolution?.canonicalRepositoryPath || norm.repositoryRoot || norm.repository;
    const canonRepoId = repoResolution?.canonicalRepositoryId || norm.canonicalRepositoryId || (repoPath ? computeCanonicalRepoId(repoPath) : '');
    const appId = norm.applicationId || repoResolution?.applicationNumber || '';
    const appSource = norm.applicationIdentitySource || repoResolution?.identitySource || (norm.sourceOrigin === 'CSV' ? 'CSV_DECLARED' : '');

    return {
        contextSchemaVersion: FINDING_CONTEXT_SCHEMA_VERSION,
        findingId: norm.findingId,
        applicationId: appId,
        applicationName: norm.applicationName || repoResolution?.applicationName || (repoPath ? path.basename(repoPath) : ''),
        applicationIdentitySource: appSource,
        canonicalRepositoryId: canonRepoId,
        repositoryReference: norm.repository || repoPath,
        repositoryPath: repoPath ? canonicalizePath(repoPath) : '',
        projectPath: norm.projectPath || '',
        scannerId: norm.scannerId || (norm.sourceOrigin === 'CSV' ? 'csv-import' : ''),
        scanExecutionId: norm.scanExecutionId || '',
        sourceOrigin: norm.sourceOrigin || 'Unknown',
        detectionMethod: norm.detectionMethod || '',
        findingFingerprint: norm.findingFingerprint,
        originalSeverity: norm.originalSeverity,
        technology: norm.technology || repoResolution?.technology || '',
        evidenceLocation: norm.locationPath ? `${norm.locationPath}:${norm.lineNumber}` : ''
    };
}

/**
 * Fail-closed receiving boundary validation for finding-to-repository metadata (SEC-02).
 * Never silently resolves a missing/ambiguous finding to an unrelated workspace (like GCAC).
 */
function validateFindingContextContract(finding = {}, options = {}) {
    const norm = normalizeFindingMetadataFields(finding);
    const authorizedRoots = (options.authorizedRoots || []).map(r => canonicalizePath(r));
    const registry = options.registry || null;

    if (!norm.findingId || !/^[A-Za-z0-9_.-]{3,64}$/.test(norm.findingId) || /^(?:ALL|ANY|BATCH|MULTI)/i.test(norm.findingId)) {
        return {
            valid: false,
            reasonCode: 'INVALID_FINDING_ID',
            reason: `SEC-02 Blocked: Finding ID '${norm.findingId || 'empty'}' is invalid or multi-finding.`
        };
    }

    if (!norm.applicationId || norm.applicationId.includes(',')) {
        return {
            valid: false,
            requiresMapping: true,
            reasonCode: 'MISSING_APPLICATION_METADATA',
            reason: `SEC-02 Blocked: Finding '${norm.findingId}' has missing or ambiguous Application_Number/Repository metadata.`
        };
    }

    const rawRepo = norm.repositoryRoot || norm.repository;
    if (!rawRepo || rawRepo.includes(',') || isRemoteRepositoryReference(rawRepo)) {
        return {
            valid: false,
            requiresMapping: true,
            reasonCode: 'MISSING_REPOSITORY_METADATA',
            reason: `SEC-02 Blocked: Finding '${norm.findingId}' has missing or ambiguous Application_Number/Repository metadata.`
        };
    }

    // Resolve candidate repository path against authorized roots without blind GCAC fallback
    let resolvedRepo = null;
    if (path.isAbsolute(rawRepo)) {
        const authMatch = authorizedRoots.length > 0
            ? assertPathWithinAuthorizedRoots(rawRepo, authorizedRoots)
            : (fs.existsSync(rawRepo) ? { canonicalPath: canonicalizePath(rawRepo), authorizedRoot: canonicalizePath(rawRepo) } : null);
        if (authMatch && fs.existsSync(authMatch.canonicalPath) && fs.statSync(authMatch.canonicalPath).isDirectory()) {
            resolvedRepo = authMatch.canonicalPath;
        }
    } else {
        for (const root of authorizedRoots) {
            const candidate = path.resolve(root, rawRepo);
            const safe = assertPathWithinWorkspace(candidate, root);
            if (safe && fs.existsSync(safe) && fs.statSync(safe).isDirectory()) {
                resolvedRepo = safe;
                break;
            }
        }
    }

    // Also try deterministic registry resolution by applicationId if rawRepo was a relative registry alias
    if (!resolvedRepo && registry) {
        const regMatch = registry.findByApplicationId(norm.applicationId);
        if (regMatch && fs.existsSync(regMatch.canonicalRepositoryPath)) {
            const matchesAlias = rawRepo === regMatch.repositoryUrl ||
                rawRepo === regMatch.canonicalRepositoryPath ||
                path.basename(regMatch.canonicalRepositoryPath).toLowerCase() === rawRepo.toLowerCase();
            if (matchesAlias) {
                resolvedRepo = regMatch.canonicalRepositoryPath;
            }
        }
    }

    if (!resolvedRepo) {
        return {
            valid: false,
            requiresMapping: true,
            reasonCode: 'UNRESOLVED_OR_UNAUTHORIZED_REPOSITORY',
            reason: `SEC-02 Blocked: Repository '${rawRepo}' for finding '${norm.findingId}' could not be resolved within authorized local repositories.`
        };
    }

    if (isSensitiveSystemOrCredentialRoot(resolvedRepo)) {
        return {
            valid: false,
            requiresMapping: true,
            reasonCode: 'SENSITIVE_REPOSITORY_BLOCKED',
            reason: `SEC-02 Blocked: Repository path '${resolvedRepo}' points to a restricted OS/credential directory.`
        };
    }

    const regInfo = registry ? registry.findByRepositoryPath(resolvedRepo) : null;
    const context = buildCanonicalFindingContext(finding, regInfo || {
        canonicalRepositoryPath: resolvedRepo,
        canonicalRepositoryId: computeCanonicalRepoId(resolvedRepo),
        applicationNumber: norm.applicationId,
        applicationName: norm.applicationName || path.basename(resolvedRepo),
        technology: norm.technology
    });

    return {
        valid: true,
        requiresMapping: false,
        resolvedRepositoryPath: resolvedRepo,
        context
    };
}

module.exports = {
    FINDING_CONTEXT_SCHEMA_VERSION,
    IGNORED_SCAN_DIRS,
    canonicalizePath,
    normalizePosix,
    isRemoteRepositoryReference,
    isSensitiveSystemOrCredentialRoot,
    assertPathWithinAuthorizedRoots,
    isUninitializedGitSubmodule,
    discoverProjectManifests,
    inspectRepositoryTarget,
    computeCanonicalRepoId,
    computeLocalApplicationId,
    RepositoryContextRegistry,
    normalizeFindingMetadataFields,
    buildCanonicalFindingContext,
    validateFindingContextContract
};
