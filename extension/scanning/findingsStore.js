const fs = require('fs');
const path = require('path');
const { NormalizedFinding } = require('./findingModel');

const MAX_HISTORY_SESSIONS = 20;

/**
 * Local Workspace-Associated Findings Store for GCAC Remediation Hub
 * Pure local JSON persistence inside `output/scans/`. Zero external DB/SharePoint/telemetry.
 * Features bounded retention, fingerprint-based deduplication, and CSV row adapter.
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
        const tmpFile = `${this.findingsFile}.tmp`;
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
     * Deduplicates based on findingFingerprint.
     * Preserves existing remediation progress and human status updates.
     * 
     * @param {NormalizedFinding[]} newFindings 
     * @param {string} scanId 
     * @returns {{ added: number, updated: number, total: number, newCount: number, updatedCount: number }}
     */
    ingestScanFindings(newFindings, scanId) {
        const existing = this.loadFindings();
        const existingMap = new Map();

        for (const item of existing) {
            existingMap.set(item.findingFingerprint, item);
        }

        let added = 0;
        let updated = 0;

        for (const finding of newFindings) {
            if (existingMap.has(finding.findingFingerprint)) {
                // Deduplication match: update location/timestamp, but retain existing remediation status
                const match = existingMap.get(finding.findingFingerprint);
                match.line = finding.line || match.line;
                match.column = finding.column || match.column;
                match.timestamp = finding.timestamp;
                match.scanId = scanId;
                match.evidence = finding.evidence || match.evidence;
                if (match.status === 'Resolved') {
                    match.status = 'Detected';
                }
                updated++;
            } else {
                const scannerPrefix = (finding.scannerId || 'SEC').replace(/[^a-zA-Z0-9]/g, '').toUpperCase().substring(0, 6);
                const count = existing.length + added + 1;
                finding.findingId = `SCAN-${scannerPrefix}-${String(count).padStart(3, '0')}`;
                finding.scanId = scanId;
                existing.push(finding);
                existingMap.set(finding.findingFingerprint, finding);
                added++;
            }
        }

        this.saveFindings(existing);
        return { added, updated, total: existing.length, newCount: added, updatedCount: updated };
    }

    getFindings() {
        return this.loadFindings();
    }

    ingestFindings(newFindings, scanId = `scan-${Date.now()}`) {
        return this.ingestScanFindings(newFindings, scanId);
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
     * Converts all stored findings into CSV-compatible records matching vulnerabilities.csv
     * Allows seamless intake into Copilot Chat and existing remediation pipeline.
     */
    toCsvCompatibleRecords() {
        const findings = this.loadFindings();
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
