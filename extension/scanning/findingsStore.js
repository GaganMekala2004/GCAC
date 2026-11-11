const fs = require('fs');
const path = require('path');
const { NormalizedFinding } = require('./findingModel');

const MAX_HISTORY_SESSIONS = 20;

/**
 * Local Workspace-Associated Findings Store for GCAC Remediation Hub
 * Pure local JSON persistence inside `output/scans/`. Zero external DB/SharePoint/telemetry.
 * Features repository-scoped deduplication, historical isolation across scans/repos,
 * bounded retention, and CSV row adapter.
 */
class FindingsStore {
    /**
     * @param {string} workspaceRoot 
     * @param {string} [storageDir] 
     */
    constructor(workspaceRoot, storageDir = null) {
        this.workspaceRoot = workspaceRoot;
        this.storageDir = storageDir || path.join(workspaceRoot, 'output', 'scans');
        this.findingsFile = path.join(this.storageDir, 'findings.json');
        this.historyFile = path.join(this.storageDir, 'scan-history.json');

        this._ensureStorageDir();
    }

    _ensureStorageDir() {
        try {
            if (!fs.existsSync(this.storageDir)) {
                fs.mkdirSync(this.storageDir, { recursive: true });
            }
        } catch (e) {}
    }

    _repoKey(finding) {
        if (!finding) return '';
        const canonId = (finding.canonicalRepositoryId || '').trim().toLowerCase();
        if (canonId) return `id:${canonId}`;
        const root = (finding.repositoryRoot || '').trim().replace(/\\/g, '/').toLowerCase();
        if (root) return `root:${root}`;
        const repo = (finding.repository || '').trim().replace(/\\/g, '/').toLowerCase();
        if (repo) return `repo:${repo}`;
        return 'unscoped';
    }

    _dedupeKey(finding) {
        return `${this._repoKey(finding)}::${finding.findingFingerprint || ''}`;
    }

    _nextUniqueFindingId(existingFindings, scannerId) {
        const scannerPrefix = (scannerId || 'SEC').replace(/[^a-zA-Z0-9]/g, '').toUpperCase().substring(0, 6) || 'SEC';
        const usedIds = new Set(existingFindings.map(f => f.findingId).filter(Boolean));
        let maxNum = 0;
        const prefixRe = new RegExp(`^SCAN-${scannerPrefix}-(\\d+)$`, 'i');
        for (const id of usedIds) {
            const m = String(id).match(prefixRe);
            if (m) {
                const n = parseInt(m[1], 10);
                if (n > maxNum) maxNum = n;
            }
        }
        let seq = Math.max(maxNum + 1, existingFindings.length + 1);
        let candidate = `SCAN-${scannerPrefix}-${String(seq).padStart(3, '0')}`;
        while (usedIds.has(candidate)) {
            seq++;
            candidate = `SCAN-${scannerPrefix}-${String(seq).padStart(3, '0')}`;
        }
        return candidate;
    }

    /**
     * Loads all active normalized findings from local disk
     * @returns {NormalizedFinding[]}
     */
    loadFindings() {
        this._ensureStorageDir();
        if (!fs.existsSync(this.findingsFile)) {
            return [];
        }
        try {
            const raw = fs.readFileSync(this.findingsFile, 'utf-8');
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            return parsed.map(item => new NormalizedFinding(item));
        } catch (e) {
            console.warn('Could not read findings store:', e.message);
            return [];
        }
    }

    /**
     * Atomically saves findings to local disk
     * @param {NormalizedFinding[]} findings 
     */
    saveFindings(findings) {
        this._ensureStorageDir();
        const tmpFile = `${this.findingsFile}.${process.pid}.${Date.now()}.tmp`;
        try {
            const json = JSON.stringify(findings, null, 2);
            fs.writeFileSync(tmpFile, json, 'utf-8');
            fs.renameSync(tmpFile, this.findingsFile);
        } catch (e) {
            try { if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile); } catch (err) {}
            console.error('Failed to save findings store:', e.message);
        }
    }

    /**
     * Merges newly discovered scan findings with existing store.
     * Deduplicates strictly within the same repository + findingFingerprint.
     * Marks previously active findings for the SAME scanned repository that were not
     * present in the latest full scan as historical (unless scan was partial/failed),
     * and keeps findings from OTHER repositories isolated as historical so they never
     * leak as fresh output of another repository.
     *
     * @param {NormalizedFinding[]} newFindings 
     * @param {string} scanId 
     * @param {object} [options]
     * @returns {{ added: number, updated: number, total: number, newCount: number, updatedCount: number }}
     */
    ingestScanFindings(newFindings, scanId, options = {}) {
        const existing = this.loadFindings();
        const existingMap = new Map();

        for (const item of existing) {
            existingMap.set(this._dedupeKey(item), item);
        }

        const scannedRepoKey = options.canonicalRepositoryId
            ? `id:${String(options.canonicalRepositoryId).toLowerCase()}`
            : (options.repositoryRoot
                ? `root:${String(options.repositoryRoot).replace(/\\/g, '/').toLowerCase()}`
                : null);
        const allowMarkAbsentHistorical = options.fullScanCompleted === true && scannedRepoKey;
        const freshKeys = new Set();

        let added = 0;
        let updated = 0;

        for (const rawFinding of (newFindings || [])) {
            const finding = rawFinding instanceof NormalizedFinding ? rawFinding : new NormalizedFinding(rawFinding);
            const key = this._dedupeKey(finding);
            freshKeys.add(key);

            if (existingMap.has(key)) {
                // Deduplication match within same repository: update provenance/location, retain active remediation status
                const match = existingMap.get(key);
                match.line = finding.line || match.line;
                match.column = finding.column || match.column;
                match.timestamp = finding.timestamp;
                if (scanId || !match.scanId) match.scanId = scanId || finding.scanId || `scan-${Date.now()}`;
                match.lastSeenScanId = match.scanId;
                match.isHistorical = false;
                match.evidence = finding.evidence || match.evidence;
                match.evidenceRef = finding.evidenceRef || match.evidenceRef;
                match.detectionMethod = finding.detectionMethod || match.detectionMethod;
                if (finding.repository) match.repository = finding.repository;
                if (finding.repositoryRoot) match.repositoryRoot = finding.repositoryRoot;
                if (finding.canonicalRepositoryId) match.canonicalRepositoryId = finding.canonicalRepositoryId;
                if (finding.applicationNumber) match.applicationNumber = finding.applicationNumber;
                if (finding.applicationName) match.applicationName = finding.applicationName;
                if (finding.applicationIdentitySource) match.applicationIdentitySource = finding.applicationIdentitySource;
                if (finding.projectPath) match.projectPath = finding.projectPath;
                if (finding.technology && finding.technology !== 'unknown') match.technology = finding.technology;
                if (match.status === 'Resolved') {
                    match.status = 'Detected';
                }
                updated++;
            } else {
                finding.findingId = this._nextUniqueFindingId(existing, finding.scannerId);
                finding.scanId = scanId || finding.scanId || `scan-${Date.now()}`;
                finding.lastSeenScanId = finding.scanId;
                finding.isHistorical = false;
                existing.push(finding);
                existingMap.set(key, finding);
                added++;
            }
        }

        // Preserve historical results as historical; never present absent or prior-repo findings as fresh scan output
        if (scannedRepoKey) {
            for (const item of existing) {
                const key = this._dedupeKey(item);
                const itemRepoKey = this._repoKey(item);
                if (itemRepoKey && itemRepoKey !== scannedRepoKey) {
                    item.isHistorical = true;
                } else if (allowMarkAbsentHistorical && itemRepoKey === scannedRepoKey && !freshKeys.has(key)) {
                    item.isHistorical = true;
                }
            }
        }

        this.saveFindings(existing);
        const scopedActiveCount = scannedRepoKey
            ? existing.filter(f => this._repoKey(f) === scannedRepoKey && !f.isHistorical).length
            : existing.length;

        return {
            added,
            updated,
            total: existing.length,
            activeTotal: scopedActiveCount,
            newCount: added,
            updatedCount: updated
        };
    }

    /**
     * Explicitly updates repository/application mapping on a stored finding (for SEC-02 mapping workflow).
     */
    updateFindingMapping(findingIdOrFingerprint, mapping = {}) {
        const findings = this.loadFindings();
        const finding = findings.find(f => f.findingId === findingIdOrFingerprint || f.findingFingerprint === findingIdOrFingerprint);
        if (!finding) return null;

        if (mapping.applicationNumber !== undefined) finding.applicationNumber = mapping.applicationNumber;
        if (mapping.applicationName !== undefined) finding.applicationName = mapping.applicationName;
        if (mapping.applicationIdentitySource !== undefined) finding.applicationIdentitySource = mapping.applicationIdentitySource;
        if (mapping.repository !== undefined) finding.repository = mapping.repository;
        if (mapping.repositoryRoot !== undefined) finding.repositoryRoot = mapping.repositoryRoot;
        if (mapping.canonicalRepositoryId !== undefined) finding.canonicalRepositoryId = mapping.canonicalRepositoryId;
        if (mapping.technology !== undefined) finding.technology = mapping.technology;

        this.saveFindings(findings);
        return finding;
    }

    getFindings(filter = null) {
        const all = this.loadFindings();
        if (!filter || typeof filter !== 'object') return all;

        return all.filter(f => {
            if (filter.includeHistorical === false && f.isHistorical) return false;
            if (filter.scanId && f.scanId !== filter.scanId && f.lastSeenScanId !== filter.scanId) return false;
            if (filter.canonicalRepositoryId || filter.repositoryRoot || filter.repository) {
                const targetId = (filter.canonicalRepositoryId || '').toLowerCase();
                const targetRoot = (filter.repositoryRoot || '').replace(/\\/g, '/').toLowerCase();
                const targetRepo = (filter.repository || '').replace(/\\/g, '/').toLowerCase();

                const fId = (f.canonicalRepositoryId || '').toLowerCase();
                const fRoot = (f.repositoryRoot || '').replace(/\\/g, '/').toLowerCase();
                const fRepo = (f.repository || '').replace(/\\/g, '/').toLowerCase();

                if (targetId && fId) return targetId === fId;
                if (targetRoot && fRoot) return targetRoot === fRoot;
                if (targetRepo && fRepo) return targetRepo === fRepo;
                if (targetRoot && fRepo) return fRepo === targetRoot || fRepo === path.basename(targetRoot);
                return false;
            }
            return true;
        });
    }

    ingestFindings(newFindings, scanId = null, options = {}) {
        return this.ingestScanFindings(newFindings, scanId, options);
    }

    /**
     * Retrieves finding by its unique findingFingerprint
     * @param {string} fingerprint 
     * @returns {NormalizedFinding|null}
     */
    getFindingByFingerprint(fingerprint) {
        if (!fingerprint) return null;
        const findings = this.loadFindings();
        return findings.find(f => f.findingFingerprint === fingerprint || f.fingerprint === fingerprint) || null;
    }

    /**
     * Retrieves finding by its unique findingId
     * @param {string} findingId 
     * @returns {NormalizedFinding|null}
     */
    getFindingById(findingId) {
        if (!findingId) return null;
        const findings = this.loadFindings();
        return findings.find(f => f.findingId === findingId || f.findingFingerprint === findingId) || null;
    }

    /**
     * Updates status for a specific finding (e.g. 'Remediating', 'Resolved', 'Still Present')
     * @param {string} findingIdOrFingerprint 
     * @param {string} newStatus 
     * @param {object} [metadata] 
     * @returns {boolean}
     */
    updateFindingStatus(findingIdOrFingerprint, newStatus, metadata = {}) {
        const findings = this.loadFindings();
        const finding = findings.find(f => f.findingId === findingIdOrFingerprint || f.findingFingerprint === findingIdOrFingerprint);
        if (!finding) return false;

        finding.status = newStatus;
        if (metadata.remediationReport) finding.remediationReport = metadata.remediationReport;
        if (metadata.verificationStatus) finding.verificationStatus = metadata.verificationStatus;
        if (metadata.lastVerifiedAt) finding.lastVerifiedAt = metadata.lastVerifiedAt;

        this.saveFindings(findings);
        return true;
    }

    /**
     * Records a scan session into history with bounded retention
     * @param {object} session 
     */
    recordScanSession(session) {
        this._ensureStorageDir();
        let history = [];
        if (fs.existsSync(this.historyFile)) {
            try {
                history = JSON.parse(fs.readFileSync(this.historyFile, 'utf-8'));
                if (!Array.isArray(history)) history = [];
            } catch (e) {
                history = [];
            }
        }

        history.unshift(session);
        // Bounded retention: keep maximum MAX_HISTORY_SESSIONS
        if (history.length > MAX_HISTORY_SESSIONS) {
            history = history.slice(0, MAX_HISTORY_SESSIONS);
        }

        try {
            fs.writeFileSync(this.historyFile, JSON.stringify(history, null, 2), 'utf-8');
        } catch (e) {}
    }

    /**
     * Returns scan history records
     * @returns {object[]}
     */
    getScanHistory() {
        if (!fs.existsSync(this.historyFile)) return [];
        try {
            return JSON.parse(fs.readFileSync(this.historyFile, 'utf-8')) || [];
        } catch (e) {
            return [];
        }
    }

    /**
     * Converts stored findings into CSV-compatible records matching vulnerabilities.csv
     */
    toCsvCompatibleRecords(filter = null) {
        const findings = this.getFindings(filter);
        return findings.map(f => f.toCsvCompatibleRecord());
    }

    /**
     * Clears all stored findings and resets scan history
     */
    clearFindings() {
        this.saveFindings([]);
        try {
            if (fs.existsSync(this.historyFile)) {
                fs.writeFileSync(this.historyFile, '[]', 'utf-8');
            }
        } catch (e) {}
    }
}

module.exports = {
    FindingsStore,
    MAX_HISTORY_SESSIONS
};
