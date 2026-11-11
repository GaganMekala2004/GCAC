const path = require('path');
const fs = require('fs');
const { DotnetSecurityScanner } = require('./adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('./adapters/nugetAuditScanner');
const { SecretsConfigScanner } = require('./adapters/secretsConfigScanner');
const { CodeQLScanner } = require('./adapters/codeqlScanner');
const { FindingsStore } = require('./findingsStore');
const { SCANNER_STATUS } = require('./findingModel');
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

/**
 * Scan Controller for GCAC Vulnerability Remediation Hub
 * Coordinates discovery, configuration validation, execution, timeouts, cancellation,
 * repository-scoped provenance, and progress reporting across approved local scanners.
 */
class ScanController {
    constructor(workspaceRoot, options = {}) {
        this.workspaceRoot = workspaceRoot;
        this.extensionRoot = options.extensionRoot || path.resolve(__dirname, '../..');
        this.findingsStore = options.findingsStore || new FindingsStore(workspaceRoot);
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
        this.registerScanner(new CodeQLScanner());

        this.isScanning = false;
        this.currentScanId = null;
        this.currentCancelToken = null;
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

    async getAvailableScanners(targetWorkspaceRoot = null) {
        const result = [];
        const seen = new Set();
        const effectiveWs = targetWorkspaceRoot || this.workspaceRoot;
        for (const scanner of this.scanners.values()) {
            if (seen.has(scanner.id)) continue;
            seen.add(scanner.id);
            try {
                const avail = await scanner.isAvailable({
                    workspaceRoot: effectiveWs,
                    executionGateway: this.executionGateway,
                    sandboxBackend: this.sandboxBackend,
                    envReport: this.envReport
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
        const startTime = Date.now();
        const onProgress = typeof scanRequest.onProgress === 'function' ? scanRequest.onProgress : () => { };

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

            const repoContext = this._resolveRepoContext(targetFullPath, scanRequest);
            const selectedIds = Array.isArray(scanRequest.scannerIds) && scanRequest.scannerIds.length > 0
                ? scanRequest.scannerIds
                : Array.from(new Set(Array.from(this.scanners.values()).map(s => s.id)));

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

            onProgress({
                type: 'SCAN_STARTED',
                scanId,
                targetPath: targetFullPath,
                repositoryRoot: repoContext.repositoryRoot,
                applicationNumber: repoContext.applicationNumber,
                totalScanners: activeAdapters.length
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
                    coverage: `0% (${reasonCode})`
                }));

                const ingestStats = this.findingsStore.ingestScanFindings([], scanId, {
                    canonicalRepositoryId: repoContext.canonicalRepositoryId,
                    repositoryRoot: repoContext.repositoryRoot,
                    fullScanCompleted: true
                });

                const sessionRecord = {
                    scanId,
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
                    scannerSummary: scannerResults.map(r => ({ id: r.scannerId, status: r.status, coverage: r.coverage })),
                    findingsSummary: emptySummary,
                    ingestStats
                };
                this.findingsStore.recordScanSession(sessionRecord);

                onProgress({
                    type: 'SCAN_FINISHED',
                    scanId,
                    status: 'No Scannable Inputs',
                    reasonCode,
                    durationMs,
                    findingsSummary: emptySummary
                });

                return {
                    scanId,
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
                    repoContext
                };
            }

            const allDiscoveredFindings = [];
            const scannerResults = [];
            const globalErrors = [];
            const globalWarnings = [];

            for (let i = 0; i < activeAdapters.length; i++) {
                const scanner = activeAdapters[i];
                onProgress({
                    type: 'SCANNER_START',
                    scanId,
                    scannerId: scanner.id,
                    scannerName: scanner.name,
                    progressIndex: i + 1,
                    totalScanners: activeAdapters.length
                });

                try {
                    const result = await scanner.scan(this.workspaceRoot, targetFullPath, {
                        scanId,
                        timeoutMs: 60000,
                        repoContext,
                        authorizedRoots: allAllowedRoots,
                        executionGateway: scanRequest.executionGateway || this.executionGateway,
                        sandboxBackend: scanRequest.sandboxBackend || this.sandboxBackend,
                        envReport: scanRequest.envReport || this.envReport,
                        profilesPath: scanRequest.profilesPath || this.profilesPath
                    });

                    scannerResults.push(result);
                    if (result.findings && result.findings.length > 0) {
                        const screen = new ContentInjectionScreen();
                        for (const f of result.findings) {
                            // Ensure canonical repository provenance is attached even if custom scanner adapter emitted partial metadata
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
                        allDiscoveredFindings.push(...result.findings);
                    }
                    if (result.errors && result.errors.length > 0) {
                        globalErrors.push(...result.errors.map(e => `[${scanner.name}] ${e}`));
                    }
                    if (result.warnings && result.warnings.length > 0) {
                        globalWarnings.push(...result.warnings.map(w => `[${scanner.name}] ${w}`));
                    }

                    onProgress({
                        type: 'SCANNER_COMPLETE',
                        scanId,
                        scannerId: scanner.id,
                        status: result.status,
                        findingsCount: result.findings ? result.findings.length : 0,
                        durationMs: result.durationMs
                    });
                } catch (err) {
                    const failResult = {
                        scannerId: scanner.id,
                        status: SCANNER_STATUS.FAILED,
                        findings: [],
                        durationMs: 0,
                        errors: [err.message],
                        warnings: [],
                        coverage: '0% (Execution error)'
                    };
                    scannerResults.push(failResult);
                    globalErrors.push(`[${scanner.name}] Unexpected error: ${err.message}`);

                    onProgress({
                        type: 'SCANNER_FAILED',
                        scanId,
                        scannerId: scanner.id,
                        error: err.message
                    });
                }
            }

            const allNoInputs = scannerResults.length > 0 &&
                scannerResults.every(r => r.status === SCANNER_STATUS.NO_SCANNABLE_INPUTS || r.noScannableInputs === true) &&
                allDiscoveredFindings.length === 0 &&
                globalErrors.length === 0;

            const hasScannerFailures = globalErrors.length > 0 ||
                scannerResults.some(r => r.status === SCANNER_STATUS.FAILED || r.status === SCANNER_STATUS.UNAVAILABLE);
            const hasSuccessfulScanner = scannerResults.some(r => r.status === SCANNER_STATUS.COMPLETED);

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
            if (allNoInputs) {
                overallStatus = 'No Scannable Inputs';
            } else if (hasScannerFailures) {
                overallStatus = (allDiscoveredFindings.length > 0 || hasSuccessfulScanner) ? 'Partial' : 'Failed';
            }

            const sessionRecord = {
                scanId,
                timestamp: new Date().toISOString(),
                targetPath: repoContext.repository || targetFullPath,
                repositoryRoot: repoContext.repositoryRoot,
                canonicalRepositoryId: repoContext.canonicalRepositoryId,
                applicationNumber: repoContext.applicationNumber,
                durationMs: totalDuration,
                status: overallStatus,
                noScannableInputs: allNoInputs,
                unverifiedCoverage: hasScannerFailures,
                scannersCount: activeAdapters.length,
                scannerSummary: scannerResults.map(r => ({
                    id: r.scannerId,
                    status: r.status,
                    coverage: r.coverage,
                    findingsCount: r.findings ? r.findings.length : 0,
                    errors: r.errors || []
                })),
                findingsSummary,
                ingestStats
            };
            this.findingsStore.recordScanSession(sessionRecord);

            onProgress({
                type: 'SCAN_FINISHED',
                scanId,
                status: overallStatus,
                durationMs: totalDuration,
                findingsSummary
            });

            return {
                scanId,
                status: overallStatus,
                noScannableInputs: allNoInputs,
                reasonCode: allNoInputs ? 'NO_SCANNABLE_INPUTS' : null,
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
                repoContext
            };
        } finally {
            this.isScanning = false;
            this.currentScanId = null;
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
        if (!this.isScanning) return;
        for (const scanner of this.scanners.values()) {
            scanner.cancel();
        }
        this.isScanning = false;
        this.currentScanId = null;
    }
}

module.exports = {
    ScanController
};
