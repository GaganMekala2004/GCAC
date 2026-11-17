const path = require('path');
const fs = require('fs');
const { DotnetSecurityScanner } = require('./adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('./adapters/nugetAuditScanner');
const { SecretsConfigScanner } = require('./adapters/secretsConfigScanner');
const { CodeQLScanner } = require('./adapters/codeqlScanner');
const { FindingsStore } = require('./findingsStore');
const { SCANNER_STATUS } = require('./findingModel');
const { ScanCache, computeInputFingerprint, stableHashObject } = require('./scanCache');
const { discoverEnvironment } = require('../sandbox/environmentDiscovery');
const {
    canonicalizePath,
    assertPathWithinAuthorizedRoots,
    inspectRepositoryTarget,
    computeCanonicalRepoId,
    computeLocalApplicationId,
    RepositoryContextRegistry
} = require('../repositoryContext');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('../contentInjectionScreen');

const QUICK_MODE_SCANNERS = Object.freeze(['secrets-config']);

function elapsedMsSince(startNs) {
    return Number((Number(process.hrtime.bigint() - startNs) / 1e6).toFixed(2));
}

/**
 * Scan Controller for GCAC Vulnerability Remediation Hub
 * Coordinates discovery, configuration validation, execution, timeouts, cancellation,
 * incremental key-bound caching, monotonic performance instrumentation,
 * repository-scoped provenance, and progress reporting across approved local scanners.
 */
class ScanController {
    constructor(workspaceRoot, options = {}) {
        this.workspaceRoot = workspaceRoot;
        this.extensionRoot = options.extensionRoot || path.resolve(__dirname, '../..');
        this.findingsStore = options.findingsStore || new FindingsStore(workspaceRoot);
        this.enableCache = options.enableCache !== false;
        this.scanCache = options.scanCache || new ScanCache(
            this.findingsStore?.storageDir || path.join(workspaceRoot, 'output', 'scans'),
            options.cacheOptions || {}
        );
        this.isWorkspaceTrusted = options.isWorkspaceTrusted !== undefined ? options.isWorkspaceTrusted : true;
        this.executionGateway = options.executionGateway || null;
        this.sandboxBackend = options.sandboxBackend || null;
        this.envReport = options.envReport || null;
        this.profilesPath = options.profilesPath || undefined;
        this.authorizedRoots = Array.isArray(options.authorizedRoots) && options.authorizedRoots.length > 0
            ? options.authorizedRoots.map(r => canonicalizePath(r))
            : [canonicalizePath(workspaceRoot)];
        this.registry = options.registry || new RepositoryContextRegistry({
            workspaceRoot,
            extensionRoot: this.extensionRoot
        });

        this.scanners = new Map();
        this.registerScanner(new DotnetSecurityScanner());
        this.registerScanner(new NuGetAuditScanner());
        this.registerScanner(new SecretsConfigScanner());
        this.registerScanner(new CodeQLScanner({ workspaceRoot, extensionRoot: this.extensionRoot }));

        this.isScanning = false;
        this.currentScanId = null;
        this.currentCancelToken = null;
        this.currentAbortController = null;
        this._cancelRequestedAtNs = null;
    }

    setAuthorizedRoots(roots = []) {
        const set = new Set([canonicalizePath(this.workspaceRoot)]);
        for (const r of (roots || [])) {
            if (typeof r === 'string' && r.trim()) {
                set.add(canonicalizePath(r));
            }
        }
        this.authorizedRoots = Array.from(set);
    }

    addAuthorizedRoot(rootPath) {
        if (!rootPath || typeof rootPath !== 'string') return;
        const canon = canonicalizePath(rootPath);
        if (!this.authorizedRoots.some(r => r.toLowerCase() === canon.toLowerCase())) {
            this.authorizedRoots.push(canon);
        }
    }

    registerScanner(scanner) {
        this.scanners.set(scanner.id, scanner);
        if (!scanner.id.endsWith('-scanner')) {
            this.scanners.set(`${scanner.id}-scanner`, scanner);
        } else {
            this.scanners.set(scanner.id.replace(/-scanner$/, ''), scanner);
        }
    }

    _registerScanner(scanner) {
        this.registerScanner(scanner);
    }

    setWorkspaceTrust(trusted) {
        this.isWorkspaceTrusted = !!trusted;
    }

    async getAvailableScanners(targetWorkspaceRoot = null, options = {}) {
        const result = [];
        const seen = new Set();
        const effectiveWs = targetWorkspaceRoot || this.workspaceRoot;
        const sharedEnvReport = options.envReport || this.envReport || discoverEnvironment({
            workspaceRoot: effectiveWs,
            useCache: options.forceRefresh !== true
        });
        for (const scanner of this.scanners.values()) {
            if (seen.has(scanner.id)) continue;
            seen.add(scanner.id);
            try {
                const avail = await scanner.isAvailable({
                    workspaceRoot: effectiveWs,
                    extensionRoot: this.extensionRoot,
                    executionGateway: this.executionGateway,
                    sandboxBackend: this.sandboxBackend,
                    envReport: sharedEnvReport
                });
                result.push({
                    id: scanner.id,
                    name: scanner.name,
                    version: avail.version || scanner.version,
                    available: avail.available,
                    reason: avail.reason || '',
                    status: avail.available ? SCANNER_STATUS.READY : SCANNER_STATUS.NOT_INSTALLED,
                    description: scanner.description || `${scanner.name} security analyzer module.`,
                    languages: scanner.supportedLanguages,
                    supportedLanguages: scanner.supportedLanguages,
                    categories: scanner.supportedCategories,
                    supportedCategories: scanner.supportedCategories,
                    rulesCount: scanner.rulesCount || (scanner.rules ? scanner.rules.length : 'Configured')
                });
            } catch (e) {
                result.push({
                    id: scanner.id,
                    name: scanner.name,
                    version: scanner.version,
                    available: false,
                    reason: e.message,
                    status: SCANNER_STATUS.UNAVAILABLE,
                    description: scanner.description || `${scanner.name} security analyzer module.`,
                    languages: scanner.supportedLanguages,
                    supportedLanguages: scanner.supportedLanguages,
                    categories: scanner.supportedCategories,
                    supportedCategories: scanner.supportedCategories,
                    rulesCount: 0
                });
            }
        }
        return result;
    }

    _resolveRepoContext(targetFullPath, scanRequest = {}) {
        const inspection = inspectRepositoryTarget(targetFullPath, { workspaceRoot: this.workspaceRoot });
        const repoRoot = inspection.repositoryRoot || targetFullPath;
        const canonRoot = canonicalizePath(repoRoot);
        const canonRepoId = computeCanonicalRepoId(canonRoot);

        // Reload registry to pick up any recent mappings
        this.registry.reload();
        let regEntry = this.registry.findByRepositoryPath(canonRoot);

        if (!regEntry && scanRequest.persistRegistration === true && fs.existsSync(canonRoot) && fs.statSync(canonRoot).isDirectory()) {
            try {
                regEntry = this.registry.registerLocalRepository(canonRoot, {
                    technology: inspection.detectedTechnology
                });
            } catch {
                regEntry = null;
            }
        }
        const deterministicLocalId = !regEntry && scanRequest.registerRepository !== false && fs.existsSync(canonRoot)
            ? computeLocalApplicationId(canonRoot)
            : '';

        const wsRel = this.workspaceRoot ? path.relative(canonicalizePath(this.workspaceRoot), canonRoot).replace(/\\/g, '/') : '';
        const isInsideMainWs = wsRel && !wsRel.startsWith('..') && !path.isAbsolute(wsRel) && wsRel !== '.';

        return {
            inspection,
            repositoryRoot: canonRoot,
            repository: isInsideMainWs ? wsRel : canonRoot,
            canonicalRepositoryId: canonRepoId,
            applicationNumber: scanRequest.applicationNumber || regEntry?.applicationNumber || deterministicLocalId,
            applicationName: scanRequest.applicationName || regEntry?.applicationName || path.basename(canonRoot) || 'Repository',
            applicationIdentitySource: regEntry?.identitySource || (deterministicLocalId ? 'LOCAL_REGISTERED_REPOSITORY' : ''),
            detectedTechnology: inspection.detectedTechnology || regEntry?.technology || 'unknown',
            supported: inspection.supported,
            unsupportedReason: inspection.unsupportedReason,
            hasScannableInputs: inspection.hasScannableInputs,
            isUninitializedSubmodule: inspection.isUninitializedSubmodule
        };
    }

    async startScan(scanRequest = {}) {
        if (!this.isWorkspaceTrusted) {
            throw new Error('Scan execution blocked: Workspace is untrusted (Restricted Mode). Please trust workspace before running security scanners.');
        }

        if (this.isScanning) {
            throw new Error('A scan is already in progress. Please wait for completion or cancel current scan.');
        }

        const scanId = `SCAN-${Date.now()}`;
        this.isScanning = true;
        this.currentScanId = scanId;
        this.currentAbortController = new AbortController();
        this._cancelRequestedAtNs = null;
        const abortSignal = this.currentAbortController.signal;

        const tTotalNs = process.hrtime.bigint();
        const startTime = Date.now();
        const rawOnProgress = typeof scanRequest.onProgress === 'function' ? scanRequest.onProgress : () => { };
        let uiProgressEmitCount = 0;
        let uiUpdateNs = 0n;
        const emitProgress = (evt) => {
            const tUi0 = process.hrtime.bigint();
            uiProgressEmitCount++;
            try {
                rawOnProgress({
                    ...evt,
                    elapsedMs: evt.elapsedMs !== undefined ? evt.elapsedMs : Math.round(elapsedMsSince(tTotalNs))
                });
            } finally {
                uiUpdateNs += (process.hrtime.bigint() - tUi0);
            }
        };

        const rawMode = String(scanRequest.mode || scanRequest.scanMode || 'comprehensive').trim().toLowerCase();
        const scanMode = rawMode === 'quick' ? 'quick' : 'comprehensive';

        try {
            const allAllowedRoots = Array.from(new Set([
                ...this.authorizedRoots,
                ...this.registry.getAllAuthorizedRepositoryRoots(),
                ...(Array.isArray(scanRequest.authorizedRoots) ? scanRequest.authorizedRoots.map(r => canonicalizePath(r)) : [])
            ]));

            let targetFullPath = canonicalizePath(this.workspaceRoot);
            if (scanRequest.targetRepo) {
                const authMatch = assertPathWithinAuthorizedRoots(scanRequest.targetRepo, allAllowedRoots);
                if (!authMatch) {
                    throw new Error(`Target path '${scanRequest.targetRepo}' is outside authorized workspace and registered repository boundaries.`);
                }
                targetFullPath = authMatch.canonicalPath;
            }

            if (!fs.existsSync(targetFullPath)) {
                throw new Error(`Scan target does not exist on disk: '${targetFullPath}'.`);
            }

            const tDisc0 = process.hrtime.bigint();
            const repoContext = this._resolveRepoContext(targetFullPath, scanRequest);
            const tDiscRepoMs = elapsedMsSince(tDisc0);

            const allRegisteredIds = Array.from(new Set(Array.from(this.scanners.values()).map(s => s.id)));
            const hasExplicitSelection = Array.isArray(scanRequest.scannerIds) && scanRequest.scannerIds.length > 0;
            const selectedIds = hasExplicitSelection
                ? scanRequest.scannerIds
                : (scanMode === 'quick' ? QUICK_MODE_SCANNERS.filter(id => this.scanners.has(id)) : allRegisteredIds);

            const activeAdapters = [];
            const seenAdapters = new Set();
            for (const id of selectedIds) {
                if (this.scanners.has(id)) {
                    const adapter = this.scanners.get(id);
                    if (!seenAdapters.has(adapter.id)) {
                        seenAdapters.add(adapter.id);
                        activeAdapters.push(adapter);
                    }
                }
            }

            const omittedScanners = allRegisteredIds.filter(id => !seenAdapters.has(id));
            const coverageDisclosure = scanMode === 'quick'
                ? `Quick Scan covers fast local secrets and configuration checks only (${activeAdapters.map(a => a.id).join(', ')}). Omitted analyzers (${omittedScanners.join(', ') || 'none'}): not equivalent to a comprehensive security assessment.`
                : (seenAdapters.has('codeql')
                    ? 'Comprehensive Scan includes all selected SAST, SCA, secrets/configuration, and optional CodeQL semantic analyzers.'
                    : `Comprehensive Scan executed with explicitly selected analyzers (${activeAdapters.map(a => a.id).join(', ')}); omitted: ${omittedScanners.join(', ') || 'none'}.`);

            emitProgress({
                type: 'SCAN_STARTED',
                scanId,
                scanMode,
                coverageDisclosure,
                omittedScanners,
                targetPath: targetFullPath,
                repositoryRoot: repoContext.repositoryRoot,
                applicationNumber: repoContext.applicationNumber,
                totalScanners: activeAdapters.length,
                indeterminate: true,
                currentOperation: 'Initializing repository inspection'
            });

            const builtinScannerIds = new Set([
                'secrets-config', 'secrets-config-scanner',
                'dotnet-security', 'dotnet-security-scanner',
                'nuget-audit', 'nuget-audit-scanner',
                'codeql', 'codeql-scanner'
            ]);
            const allAreBuiltIn = activeAdapters.length > 0 && activeAdapters.every(a => builtinScannerIds.has(a.id));

            // Fast fail-honest path for uninitialized git submodules or empty targets (preserve injected test adapters)
            if (allAreBuiltIn && (repoContext.isUninitializedSubmodule || !repoContext.hasScannableInputs)) {
                const reasonCode = repoContext.isUninitializedSubmodule ? 'UNINITIALIZED_SUBMODULE' : 'NO_SCANNABLE_INPUTS';
                const warnMsg = repoContext.unsupportedReason || 'Target repository contains no scannable non-empty source or manifest files.';
                const durationMs = Date.now() - startTime;
                const emptySummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 };

                const scannerResults = activeAdapters.map(scanner => ({
                    scannerId: scanner.id,
                    status: SCANNER_STATUS.NO_SCANNABLE_INPUTS,
                    noScannableInputs: true,
                    findings: [],
                    durationMs: 0,
                    errors: [],
                    warnings: [warnMsg],
                    coverage: `0% (${reasonCode})`,
                    fromCache: false
                }));

                const tPersist0 = process.hrtime.bigint();
                const ingestStats = this.findingsStore.ingestScanFindings([], scanId, {
                    canonicalRepositoryId: repoContext.canonicalRepositoryId,
                    repositoryRoot: repoContext.repositoryRoot,
                    fullScanCompleted: true
                });

                const metrics = {
                    environmentProbeMs: 0,
                    discoveryMs: tDiscRepoMs,
                    cacheLookupMs: 0,
                    normalizationMs: 0,
                    persistenceMs: 0,
                    uiUpdateMs: Number((Number(uiUpdateNs) / 1e6).toFixed(2)),
                    uiProgressEmitCount,
                    cancellationMs: 0,
                    totalMs: elapsedMsSince(tTotalNs),
                    repositoryFileCount: repoContext.inspection?.sourceCounts?.totalFiles || 0,
                    eligibleFileCount: repoContext.inspection?.sourceCounts?.nonEmptyFiles || 0,
                    filesScanned: 0,
                    cacheHits: 0,
                    cacheMisses: 0,
                    scannerTimings: {}
                };

                const sessionRecord = {
                    scanId,
                    scanMode,
                    coverageDisclosure,
                    omittedScanners,
                    timestamp: new Date().toISOString(),
                    targetPath: repoContext.repository || targetFullPath,
                    repositoryRoot: repoContext.repositoryRoot,
                    canonicalRepositoryId: repoContext.canonicalRepositoryId,
                    applicationNumber: repoContext.applicationNumber,
                    durationMs,
                    status: 'No Scannable Inputs',
                    reasonCode,
                    noScannableInputs: true,
                    scannersCount: activeAdapters.length,
                    scannerSummary: scannerResults.map(r => ({ id: r.scannerId, status: r.status, coverage: r.coverage, fromCache: false })),
                    findingsSummary: emptySummary,
                    ingestStats,
                    metrics
                };
                this.findingsStore.recordScanSession(sessionRecord);
                metrics.persistenceMs = elapsedMsSince(tPersist0);

                emitProgress({
                    type: 'SCAN_FINISHED',
                    scanId,
                    scanMode,
                    status: 'No Scannable Inputs',
                    reasonCode,
                    durationMs,
                    findingsSummary: emptySummary,
                    indeterminate: false
                });

                return {
                    scanId,
                    scanMode,
                    coverageDisclosure,
                    omittedScanners,
                    status: 'No Scannable Inputs',
                    reasonCode,
                    noScannableInputs: true,
                    timestamp: sessionRecord.timestamp,
                    durationMs,
                    scannersExecuted: activeAdapters.length,
                    scannerResults,
                    findingsSummary: emptySummary,
                    ingestStats,
                    newFindings: [],
                    errors: [],
                    warnings: [warnMsg],
                    repoContext,
                    metrics
                };
            }

            const needsSandboxEnv = activeAdapters.some(a => a.id === 'dotnet-security' || a.id === 'nuget-audit');
            const tEnv0 = process.hrtime.bigint();
            const sharedEnvReport = scanRequest.envReport || this.envReport || (needsSandboxEnv
                ? discoverEnvironment({
                    workspaceRoot: targetFullPath,
                    useCache: scanRequest.forceRefreshEnv !== true
                })
                : null);
            const environmentProbeMs = elapsedMsSince(tEnv0);

            const useCache = this.enableCache && scanRequest.bypassCache !== true && !scanRequest.skipCache;
            const tFinger0 = process.hrtime.bigint();
            const inputFingerprint = useCache
                ? await computeInputFingerprint(targetFullPath, { abortSignal })
                : null;
            const fingerprintMs = useCache ? elapsedMsSince(tFinger0) : 0;

            const targetRelativePath = repoContext.repositoryRoot
                ? path.relative(repoContext.repositoryRoot, targetFullPath).replace(/\\/g, '/')
                : path.basename(targetFullPath);

            const toolchainContextHash = stableHashObject({
                sandboxAvailable: Boolean(sharedEnvReport?.sandboxAvailable),
                selectedRuntime: sharedEnvReport?.selectedRuntime || null,
                dotnetSdk: sharedEnvReport?.toolchains?.dotnet?.activeVersion || null,
                platform: process.platform
            });

            const allDiscoveredFindings = [];
            const scannerResults = new Array(activeAdapters.length);
            const globalErrors = [];
            const globalWarnings = [];
            const scannerTimings = {};
            let cacheHits = 0;
            let cacheMisses = 0;
            let totalFilesScanned = 0;
            let cacheLookupNs = 0n;
            let lastFileProgressEmitMs = 0;

            const screen = new ContentInjectionScreen();
            let normalizationNs = 0n;

            const runAdapter = async (i) => {
                const scanner = activeAdapters[i];
                if (abortSignal.aborted) {
                    scannerResults[i] = {
                        scannerId: scanner.id,
                        status: SCANNER_STATUS.CANCELLED || 'Cancelled',
                        cancelled: true,
                        findings: [],
                        durationMs: 0,
                        errors: ['Scan cancelled before adapter execution.'],
                        warnings: [],
                        coverage: '0% (Cancelled)',
                        fromCache: false
                    };
                    return;
                }

                emitProgress({
                    type: 'SCANNER_START',
                    scanId,
                    scannerId: scanner.id,
                    scannerName: scanner.name,
                    progressIndex: i + 1,
                    totalScanners: activeAdapters.length,
                    currentOperation: `Preparing ${scanner.name}`,
                    totalEligibleFiles: inputFingerprint ? inputFingerprint.eligibleFileCount : undefined,
                    indeterminate: !inputFingerprint || scanner.id !== 'secrets-config'
                });

                let cacheDescriptor = null;
                if (useCache && scanner.id !== 'nuget-audit' && inputFingerprint && repoContext.canonicalRepositoryId) {
                    const tCache0 = process.hrtime.bigint();
                    const ruleConfigHash = stableHashObject({
                        scannerId: scanner.id,
                        version: scanner.version,
                        scanMode,
                        rulesCount: scanner.rulesCount || 0,
                        rules: Array.isArray(scanner.rules) ? scanner.rules.map(r => r.ruleId) : [],
                        categories: scanner.supportedCategories || []
                    });
                    cacheDescriptor = {
                        canonicalRepositoryId: repoContext.canonicalRepositoryId,
                        targetRelativePath,
                        inputHash: inputFingerprint.inputHash,
                        scannerId: scanner.id,
                        scannerVersion: scanner.version,
                        ruleConfigHash,
                        toolchainHash: toolchainContextHash,
                        isAdvisoryDependent: scanner.id === 'nuget-audit'
                    };
                    const cacheCheck = this.scanCache.get(cacheDescriptor, {
                        scanId,
                        advisoryTtlMs: scanRequest.advisoryTtlMs,
                        staticTtlMs: scanRequest.staticTtlMs,
                        nowMs: scanRequest.nowMs
                    });
                    cacheLookupNs += (process.hrtime.bigint() - tCache0);

                    if (cacheCheck.hit) {
                        cacheHits++;
                        const cachedRes = cacheCheck.result;
                        scannerResults[i] = cachedRes;
                        scannerTimings[scanner.id] = 0;
                        if (cachedRes.scannedFileCount) {
                            totalFilesScanned += cachedRes.scannedFileCount;
                        }
                        if (cachedRes.findings && cachedRes.findings.length > 0) {
                            allDiscoveredFindings.push(...cachedRes.findings);
                        }
                        if (cachedRes.warnings && cachedRes.warnings.length > 0) {
                            globalWarnings.push(...cachedRes.warnings.map(w => `[${scanner.name}] ${w}`));
                        }
                        emitProgress({
                            type: 'SCANNER_COMPLETE',
                            scanId,
                            scannerId: scanner.id,
                            scannerName: scanner.name,
                            status: cachedRes.status,
                            findingsCount: cachedRes.findings ? cachedRes.findings.length : 0,
                            durationMs: 0,
                            fromCache: true,
                            cachedAt: cachedRes.cachedAt,
                            freshnessStatus: cachedRes.freshnessStatus,
                            filesScanned: cachedRes.scannedFileCount || 0
                        });
                        return;
                    }
                    cacheMisses++;
                }

                try {
                    const tAdapter0 = process.hrtime.bigint();
                    const result = await scanner.scan(this.workspaceRoot, targetFullPath, {
                        scanId,
                        scanMode,
                        // Let adapters choose a workload-appropriate default.
                        timeoutMs: scanRequest.scannerTimeouts?.[scanner.id] ?? scanRequest.timeoutMs,
                        advisorySnapshotPath: scanRequest.advisorySnapshotPath,
                        extensionRoot: this.extensionRoot,
                        repoContext,
                        authorizedRoots: allAllowedRoots,
                        executionGateway: scanRequest.executionGateway || this.executionGateway,
                        sandboxBackend: scanRequest.sandboxBackend || this.sandboxBackend,
                        envReport: sharedEnvReport,
                        profilesPath: scanRequest.profilesPath || this.profilesPath,
                        abortSignal,
                        onProgress: (subEvt) => {
                            const nowMs = Date.now();
                            if ((nowMs - lastFileProgressEmitMs) < 75 && subEvt.filesScanned !== subEvt.totalEligibleFiles) {
                                return;
                            }
                            lastFileProgressEmitMs = nowMs;
                            emitProgress({
                                ...subEvt,
                                scanId,
                                scannerId: scanner.id,
                                scannerName: scanner.name
                            });
                        }
                    });
                    scannerTimings[scanner.id] = elapsedMsSince(tAdapter0);
                    result.fromCache = false;
                    if (result.scannedFileCount) {
                        totalFilesScanned += result.scannedFileCount;
                    }

                    scannerResults[i] = result;
                    if (result.findings && result.findings.length > 0) {
                        const tNorm0 = process.hrtime.bigint();
                        for (const f of result.findings) {
                            if (!f.repository && repoContext.repository) f.repository = repoContext.repository;
                            if (!f.repositoryRoot && repoContext.repositoryRoot) f.repositoryRoot = repoContext.repositoryRoot;
                            if (!f.canonicalRepositoryId && repoContext.canonicalRepositoryId) f.canonicalRepositoryId = repoContext.canonicalRepositoryId;
                            if (!f.applicationNumber && repoContext.applicationNumber) f.applicationNumber = repoContext.applicationNumber;
                            if (!f.applicationName && repoContext.applicationName) f.applicationName = repoContext.applicationName;
                            if (!f.applicationIdentitySource && repoContext.applicationIdentitySource) f.applicationIdentitySource = repoContext.applicationIdentitySource;

                            const untrustedText = [f.title, f.description, f.evidence, f.remediationGuidance].filter(Boolean).join('\n');
                            const screenRes = screen.screen({
                                text: untrustedText,
                                contentSource: `scanner:${scanner.id}:${f.findingId || f.ruleId}`,
                                trustClass: TRUST_CLASSES.UNTRUSTED_SCANNER_FINDING,
                                runId: scanId,
                                filePath: f.filePath || scanner.id
                            });
                            f.injectionScreening = screenRes.record;
                            if (f.status !== 'Detected') {
                                f.status = 'Detected';
                            }
                            if (screenRes.outcome !== SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA) {
                                f.classificationType = 'POTENTIAL_INJECTION_HOLD_FOR_REVIEW';
                                f.description = `[SCREENED:${screenRes.outcome}:${screenRes.ruleId}] Untrusted scanner text quarantined; inspect raw source manually.`;
                                f.remediationGuidance = '[QUARANTINED_SCANNER_GUIDANCE] Verify vulnerability directly in source code.';
                                f.evidence = '[QUARANTINED_UNTRUSTED_EVIDENCE]';
                            }
                        }
                        normalizationNs += (process.hrtime.bigint() - tNorm0);
                        allDiscoveredFindings.push(...result.findings);
                    }

                    if (cacheDescriptor && (result.status === SCANNER_STATUS.COMPLETED || result.status === SCANNER_STATUS.NO_SCANNABLE_INPUTS)) {
                        this.scanCache.set(cacheDescriptor, result);
                    }

                    if (result.errors && result.errors.length > 0) {
                        globalErrors.push(...result.errors.map(e => `[${scanner.name}] ${e}`));
                    }
                    if (result.warnings && result.warnings.length > 0) {
                        globalWarnings.push(...result.warnings.map(w => `[${scanner.name}] ${w}`));
                    }

                    emitProgress({
                        type: result.cancelled ? 'SCANNER_CANCELLED' : 'SCANNER_COMPLETE',
                        scanId,
                        scannerId: scanner.id,
                        scannerName: scanner.name,
                        status: result.status,
                        findingsCount: result.findings ? result.findings.length : 0,
                        durationMs: result.durationMs,
                        fromCache: false,
                        timedOut: Boolean(result.timedOut),
                        timeoutReason: result.timeoutReason || '',
                        filesScanned: result.scannedFileCount || 0
                    });
                } catch (err) {
                    const failResult = {
                        scannerId: scanner.id,
                        status: SCANNER_STATUS.FAILED,
                        findings: [],
                        durationMs: 0,
                        errors: [err.message],
                        warnings: [],
                        coverage: '0% (Execution error)',
                        fromCache: false
                    };
                    scannerResults[i] = failResult;
                    globalErrors.push(`[${scanner.name}] Unexpected error: ${err.message}`);

                    emitProgress({
                        type: 'SCANNER_FAILED',
                        scanId,
                        scannerId: scanner.id,
                        scannerName: scanner.name,
                        error: err.message
                    });
                }
            };

            const maxConcurrency = Math.max(1, Math.min(3, scanRequest.concurrency || 2));
            let nextIdx = 0;
            const adapterWorker = async () => {
                while (nextIdx < activeAdapters.length) {
                    const idx = nextIdx++;
                    await runAdapter(idx);
                }
            };
            const pool = [];
            const workerCount = Math.min(maxConcurrency, Math.max(1, activeAdapters.length));
            for (let w = 0; w < workerCount; w++) {
                pool.push(adapterWorker());
            }
            await Promise.all(pool);

            const wasCancelled = abortSignal.aborted || scannerResults.some(r => r && (r.cancelled || r.status === SCANNER_STATUS.CANCELLED));
            const anyTimedOut = scannerResults.some(r => r && r.timedOut);

            const allNoInputs = !wasCancelled && !anyTimedOut && scannerResults.length > 0 &&
                scannerResults.every(r => r.status === SCANNER_STATUS.NO_SCANNABLE_INPUTS || r.noScannableInputs === true) &&
                allDiscoveredFindings.length === 0 &&
                globalErrors.length === 0;

            const hasScannerFailures = wasCancelled || anyTimedOut || globalErrors.length > 0 ||
                scannerResults.some(r => r.status === SCANNER_STATUS.FAILED || r.status === SCANNER_STATUS.UNAVAILABLE);
            const hasSuccessfulScanner = scannerResults.some(r => r.status === SCANNER_STATUS.COMPLETED);

            const tPersist0 = process.hrtime.bigint();
            const ingestStats = this.findingsStore.ingestScanFindings(allDiscoveredFindings, scanId, {
                canonicalRepositoryId: repoContext.canonicalRepositoryId,
                repositoryRoot: repoContext.repositoryRoot,
                fullScanCompleted: !hasScannerFailures
            });

            const findingsSummary = {
                total: allDiscoveredFindings.length,
                critical: allDiscoveredFindings.filter(f => f.severity === 'Critical').length,
                high: allDiscoveredFindings.filter(f => f.severity === 'High').length,
                medium: allDiscoveredFindings.filter(f => f.severity === 'Medium').length,
                low: allDiscoveredFindings.filter(f => f.severity === 'Low').length,
                informational: allDiscoveredFindings.filter(f => f.severity === 'Informational').length
            };

            const totalDuration = Date.now() - startTime;
            let overallStatus = 'Completed';
            if (wasCancelled) {
                overallStatus = 'Cancelled';
            } else if (allNoInputs) {
                overallStatus = 'No Scannable Inputs';
            } else if (hasScannerFailures) {
                overallStatus = (allDiscoveredFindings.length > 0 || hasSuccessfulScanner) ? 'Partial' : 'Failed';
            }

            const metrics = {
                environmentProbeMs,
                discoveryMs: Number((tDiscRepoMs + fingerprintMs).toFixed(2)),
                cacheLookupMs: Number((Number(cacheLookupNs) / 1e6).toFixed(2)),
                normalizationMs: Number((Number(normalizationNs) / 1e6).toFixed(2)),
                persistenceMs: 0,
                uiUpdateMs: Number((Number(uiUpdateNs) / 1e6).toFixed(2)),
                uiProgressEmitCount,
                cancellationMs: (wasCancelled && this._cancelRequestedAtNs) ? elapsedMsSince(this._cancelRequestedAtNs) : 0,
                totalMs: elapsedMsSince(tTotalNs),
                repositoryFileCount: inputFingerprint ? inputFingerprint.repositoryFileCount : (repoContext.inspection?.sourceCounts?.totalFiles || 0),
                eligibleFileCount: inputFingerprint ? inputFingerprint.eligibleFileCount : (repoContext.inspection?.sourceCounts?.nonEmptyFiles || 0),
                filesScanned: totalFilesScanned,
                cacheHits,
                cacheMisses,
                scannerTimings
            };

            const sessionRecord = {
                scanId,
                scanMode,
                coverageDisclosure,
                omittedScanners,
                timestamp: new Date().toISOString(),
                targetPath: repoContext.repository || targetFullPath,
                repositoryRoot: repoContext.repositoryRoot,
                canonicalRepositoryId: repoContext.canonicalRepositoryId,
                applicationNumber: repoContext.applicationNumber,
                durationMs: totalDuration,
                status: overallStatus,
                cancelled: wasCancelled,
                timedOut: anyTimedOut,
                noScannableInputs: allNoInputs,
                unverifiedCoverage: hasScannerFailures,
                scannersCount: activeAdapters.length,
                scannerSummary: scannerResults.map(r => ({
                    id: r.scannerId,
                    status: r.status,
                    coverage: r.coverage,
                    findingsCount: r.findings ? r.findings.length : 0,
                    fromCache: Boolean(r.fromCache),
                    cachedAt: r.cachedAt || null,
                    freshnessStatus: r.freshnessStatus || null,
                    errors: r.errors || []
                })),
                findingsSummary,
                ingestStats,
                metrics
            };
            this.findingsStore.recordScanSession(sessionRecord);
            metrics.persistenceMs = elapsedMsSince(tPersist0);

            emitProgress({
                type: wasCancelled ? 'SCAN_CANCELLED' : 'SCAN_FINISHED',
                scanId,
                scanMode,
                coverageDisclosure,
                status: overallStatus,
                cancelled: wasCancelled,
                timedOut: anyTimedOut,
                durationMs: totalDuration,
                findingsSummary,
                cacheHits,
                cacheMisses,
                indeterminate: false
            });

            return {
                scanId,
                scanMode,
                coverageDisclosure,
                omittedScanners,
                status: overallStatus,
                cancelled: wasCancelled,
                timedOut: anyTimedOut,
                noScannableInputs: allNoInputs,
                reasonCode: wasCancelled ? 'SCAN_CANCELLED' : (allNoInputs ? 'NO_SCANNABLE_INPUTS' : null),
                unverifiedCoverage: hasScannerFailures,
                timestamp: sessionRecord.timestamp,
                durationMs: totalDuration,
                scannersExecuted: activeAdapters.length,
                scannerResults,
                findingsSummary,
                ingestStats,
                newFindings: allDiscoveredFindings,
                errors: globalErrors,
                warnings: globalWarnings,
                repoContext,
                fromCache: cacheHits > 0 && cacheMisses === 0,
                cacheHits,
                cacheMisses,
                metrics
            };
        } finally {
            this.isScanning = false;
            this.currentScanId = null;
            this.currentAbortController = null;
            this._cancelRequestedAtNs = null;
        }
    }

    getScannersInfo() {
        const unique = Array.from(new Set(this.scanners.values()));
        return unique.map(s => ({
            id: s.id,
            name: s.name,
            version: s.version,
            status: s.status || 'Ready',
            description: s.description || '',
            languages: s.supportedLanguages || ['csharp'],
            categories: s.supportedCategories || [],
            rulesCount: s.rulesCount || (s.rules ? s.rules.length : 6)
        }));
    }

    getScanHistory() {
        return this.findingsStore ? this.findingsStore.getScanHistory() : [];
    }

    cancelScan() {
        if (!this.isScanning) return { cancelled: false, reason: 'NO_ACTIVE_SCAN' };
        this._cancelRequestedAtNs = process.hrtime.bigint();
        const cancelledScanId = this.currentScanId;
        if (this.currentAbortController) {
            try { this.currentAbortController.abort(); } catch {}
        }
        for (const scanner of this.scanners.values()) {
            scanner.cancel();
        }
        this.isScanning = false;
        this.currentScanId = null;
        return {
            cancelled: true,
            scanId: cancelledScanId,
            cancellationMs: elapsedMsSince(this._cancelRequestedAtNs)
        };
    }
}

module.exports = {
    ScanController
};
