const path = require('path');
const fs = require('fs');
const { DotnetSecurityScanner } = require('./adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('./adapters/nugetAuditScanner');
const { SecretsConfigScanner } = require('./adapters/secretsConfigScanner');
const { CodeQLScanner } = require('./adapters/codeqlScanner');
const { FindingsStore } = require('./findingsStore');
const { SCANNER_STATUS } = require('./findingModel');
const { assertPathWithinWorkspace } = require('../pathUtils');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('../contentInjectionScreen');

/**
 * Scan Controller for GCAC Vulnerability Remediation Hub
 * Coordinates discovery, configuration validation, execution, timeouts, cancellation,
 * and progress reporting across approved local scanners.
 */
class ScanController {
    /**
     * @param {string} workspaceRoot 
     * @param {object} [options]
     * @param {FindingsStore} [options.findingsStore]
     * @param {boolean} [options.isWorkspaceTrusted]
     */
    constructor(workspaceRoot, options = {}) {
        this.workspaceRoot = workspaceRoot;
        this.findingsStore = options.findingsStore || new FindingsStore(workspaceRoot);
        this.isWorkspaceTrusted = options.isWorkspaceTrusted !== undefined ? options.isWorkspaceTrusted : true;

        // Register approved local scanners
        this.scanners = new Map();
        this.registerScanner(new DotnetSecurityScanner());
        this.registerScanner(new NuGetAuditScanner());
        this.registerScanner(new SecretsConfigScanner());
        this.registerScanner(new CodeQLScanner());

        this.isScanning = false;
        this.currentScanId = null;
        this.currentCancelToken = null;
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

    /**
     * Updates workspace trust state
     * @param {boolean} trusted 
     */
    setWorkspaceTrust(trusted) {
        this.isWorkspaceTrusted = !!trusted;
    }

    /**
     * Retrieves status and availability for all registered scanners
     * @returns {Promise<Array<{ id: string, name: string, version: string, available: boolean, reason?: string, categories: string[] }>>}
     */
    async getAvailableScanners() {
        const result = [];
        const seen = new Set();
        for (const scanner of this.scanners.values()) {
            if (seen.has(scanner.id)) continue;
            seen.add(scanner.id);
            try {
                const avail = await scanner.isAvailable();
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

    /**
     * Executes repository vulnerability scan across selected or all scanners.
     * Enforces Workspace Trust, path containment, per-scanner timeout, and independent error isolation.
     * 
     * @param {object} [scanRequest]
     * @param {string[]} [scanRequest.scannerIds] - IDs of scanners to execute (default: all)
     * @param {string} [scanRequest.targetRepo] - Specific subdirectory/repository to scan (default: workspace root)
     * @param {function} [scanRequest.onProgress] - Progress event callback: (event) => void
     * @returns {Promise<{
     *   scanId: string,
     *   status: string,
     *   timestamp: string,
     *   durationMs: number,
     *   scannersExecuted: number,
     *   scannerResults: object[],
     *   findingsSummary: { total: number, critical: number, high: number, medium: number, low: number },
     *   newFindings: import('./findingModel').NormalizedFinding[],
     *   errors: string[]
     * }>}
     */
    async startScan(scanRequest = {}) {
        // 1. Strict Workspace Trust Verification
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
        const onProgress = typeof scanRequest.onProgress === 'function' ? scanRequest.onProgress : () => {};

        // 2. Resolve and validate target path within workspace
        let targetFullPath = this.workspaceRoot;
        if (scanRequest.targetRepo) {
            const resolvedTarget = path.isAbsolute(scanRequest.targetRepo)
                ? scanRequest.targetRepo
                : path.join(this.workspaceRoot, scanRequest.targetRepo);
            
            const safeTarget = assertPathWithinWorkspace(resolvedTarget, this.workspaceRoot);
            if (!safeTarget) {
                this.isScanning = false;
                throw new Error(`Target path '${scanRequest.targetRepo}' is outside the approved workspace boundary.`);
            }
            targetFullPath = safeTarget;
        }

        // 3. Resolve scanners to run
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
            totalScanners: activeAdapters.length
        });

        const allDiscoveredFindings = [];
        const scannerResults = [];
        const globalErrors = [];

        // 4. Execute each scanner independently (Failure of one scanner does NOT crash overall scan)
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
                    timeoutMs: 60000
                });

                scannerResults.push(result);
                if (result.findings && result.findings.length > 0) {
                    const screen = new ContentInjectionScreen();
                    for (const f of result.findings) {
                        const untrustedText = [f.title, f.description, f.evidence, f.remediationGuidance].filter(Boolean).join('\n');
                        const screenRes = screen.screen({
                            text: untrustedText,
                            contentSource: `scanner:${scanner.id}:${f.findingId || f.ruleId}`,
                            trustClass: TRUST_CLASSES.UNTRUSTED_SCANNER_FINDING,
                            runId: scanId,
                            filePath: f.filePath || scanner.id
                        });
                        f.injectionScreening = screenRes.record;
                        // Scanner findings are always untrusted data and can never alter workflow closure/status
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

        // 5. Ingest into local workspace findings store (deduplicating and updating statuses)
        const ingestStats = this.findingsStore.ingestScanFindings(allDiscoveredFindings, scanId);

        // 6. Calculate summary metrics
        const findingsSummary = {
            total: allDiscoveredFindings.length,
            critical: allDiscoveredFindings.filter(f => f.severity === 'Critical').length,
            high: allDiscoveredFindings.filter(f => f.severity === 'High').length,
            medium: allDiscoveredFindings.filter(f => f.severity === 'Medium').length,
            low: allDiscoveredFindings.filter(f => f.severity === 'Low').length,
            informational: allDiscoveredFindings.filter(f => f.severity === 'Informational').length
        };

        const totalDuration = Date.now() - startTime;
        const overallStatus = globalErrors.length === 0 ? 'Completed' : (allDiscoveredFindings.length > 0 ? 'Partial' : 'Failed');

        // 7. Record session into history
        const sessionRecord = {
            scanId,
            timestamp: new Date().toISOString(),
            targetPath: path.relative(this.workspaceRoot, targetFullPath) || '.',
            durationMs: totalDuration,
            status: overallStatus,
            scannersCount: activeAdapters.length,
            findingsSummary,
            ingestStats
        };
        this.findingsStore.recordScanSession(sessionRecord);

        this.isScanning = false;
        this.currentScanId = null;

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
            timestamp: sessionRecord.timestamp,
            durationMs: totalDuration,
            scannersExecuted: activeAdapters.length,
            scannerResults,
            findingsSummary,
            ingestStats,
            newFindings: allDiscoveredFindings,
            errors: globalErrors
        };
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

    /**
     * Cancels any active scan process
     */
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
