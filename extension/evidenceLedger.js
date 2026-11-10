'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { OUTCOME_STATUS } = require('./outcomeContract');

const EVIDENCE_SCHEMA_VERSION = 'GCAC-PH2-EVIDENCE-1.0';
const MANIFEST_SCHEMA_VERSION = 'GCAC-PH2-MANIFEST-1.0';

function canonicalJson(value) {
    if (value === null || value === undefined) return JSON.stringify(value);
    if (Array.isArray(value)) {
        return '[' + value.map(item => canonicalJson(item)).join(',') + ']';
    }
    if (typeof value === 'object') {
        const keys = Object.keys(value).sort();
        return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
    }
    return JSON.stringify(value);
}

function sha256Hex(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Abstract interface for future protected WORM / Enterprise Evidence Ledger writers.
 */
class EvidenceWriter {
    writeEvidenceBundle(_targetDir, _bundle) {
        throw new Error('EvidenceWriter.writeEvidenceBundle() must be implemented.');
    }
}

/**
 * Local tamper-detectable evidence writer producing structured records,
 * hash-chained JSONL events, and a SHA-256 artifact integrity manifest.
 *
 * Explicit Limitation Disclosure:
 * Local SHA-256 digests and hash chains provide tamper DETECTION against accidental
 * or partial local modification. They are NOT cryptographically signed and NOT
 * immutable WORM storage (Phase 4 Enterprise Ledger).
 */
class LocalTamperDetectableEvidenceWriter extends EvidenceWriter {
    constructor(options = {}) {
        super();
        this.writerType = 'LocalTamperDetectableEvidenceWriter';
    }

    buildHashChain(events = [], { runId, findingId }) {
        const chain = [];
        let prevHash = '0'.repeat(64);

        for (let i = 0; i < events.length; i++) {
            const evt = events[i] || {};
            const seq = i;
            const timestamp = evt.timestamp || new Date().toISOString();
            const stage = evt.stage || 'PIPELINE';
            const eventType = evt.eventType || 'EVENT';
            const payloadHash = sha256Hex(canonicalJson(evt.payload ?? {}));
            const eventCore = {
                seq,
                timestamp,
                runId: String(runId),
                findingId: String(findingId),
                stage,
                eventType,
                payloadHash,
                prevHash
            };
            const eventHash = sha256Hex(canonicalJson(eventCore));
            chain.push({
                ...eventCore,
                eventHash
            });
            prevHash = eventHash;
        }

        return {
            chain,
            summary: {
                eventCount: chain.length,
                headHash: chain.length > 0 ? chain[0].eventHash : null,
                tailHash: chain.length > 0 ? chain[chain.length - 1].eventHash : null
            }
        };
    }

    /**
     * Writes evidence-record.json, events-chain.jsonl, and integrity-manifest.json
     * covering all artifacts currently present in targetDir.
     */
    writeEvidenceBundle(targetDir, bundle = {}) {
        if (!targetDir) throw new Error('targetDir is required to persist evidence bundle.');
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

        const {
            runId,
            findingId,
            applicationId,
            evidenceRecord,
            chainEvents = []
        } = bundle;

        if (!runId || !findingId) {
            throw new Error('EvidenceLedger requires non-empty runId and findingId.');
        }

        const sanitizedRecord = {
            schemaVersion: EVIDENCE_SCHEMA_VERSION,
            ...evidenceRecord,
            runId: String(runId),
            findingId: String(findingId),
            applicationId: String(applicationId || ''),
            storageGuarantee: 'LOCAL_TAMPER_DETECTION_ONLY_NOT_IMMUTABLE_WORM',
            cryptographicallySigned: false,
            signingLimitationNotice:
                'Local SHA-256 digests and hash-chained logs detect partial/post-hoc file alteration on disk, ' +
                'but are not protected by hardware/PKI keys or immutable WORM storage (Phase 4).'
        };

        // Enforce honesty invariant: missing real test counts cannot yield PASSED test outcome
        if (sanitizedRecord.testResultCounts && Number(sanitizedRecord.testResultCounts.total || 0) <= 0) {
            if (sanitizedRecord.finalOutcome && sanitizedRecord.finalOutcome.testOutcome === OUTCOME_STATUS.PASSED) {
                sanitizedRecord.finalOutcome.testOutcome = OUTCOME_STATUS.UNTESTED;
            }
        }

        const recordPath = path.join(targetDir, 'evidence-record.json');
        fs.writeFileSync(recordPath, JSON.stringify(sanitizedRecord, null, 2), 'utf8');

        // Build and write deterministic hash-chained event log
        const { chain, summary } = this.buildHashChain(chainEvents, { runId, findingId });
        const chainPath = path.join(targetDir, 'events-chain.jsonl');
        const chainText = chain.map(e => JSON.stringify(e)).join('\n') + (chain.length > 0 ? '\n' : '');
        fs.writeFileSync(chainPath, chainText, 'utf8');

        // Hash all artifacts present in targetDir (excluding integrity-manifest.json itself)
        const artifactFiles = fs.readdirSync(targetDir)
            .filter(name => name !== 'integrity-manifest.json')
            .filter(name => {
                const full = path.join(targetDir, name);
                return fs.existsSync(full) && fs.statSync(full).isFile();
            })
            .sort();

        const artifacts = {};
        for (const name of artifactFiles) {
            const buf = fs.readFileSync(path.join(targetDir, name));
            artifacts[name] = {
                sha256: sha256Hex(buf),
                sizeBytes: buf.length
            };
        }

        const manifestCore = {
            schemaVersion: MANIFEST_SCHEMA_VERSION,
            runId: String(runId),
            findingId: String(findingId),
            applicationId: String(applicationId || ''),
            createdAt: new Date().toISOString(),
            evidenceWriterInterface: this.writerType,
            storageGuarantee: 'LOCAL_TAMPER_DETECTION_ONLY_NOT_IMMUTABLE_WORM',
            cryptographicallySigned: false,
            chainSummary: summary,
            artifacts
        };
        const manifestSha256 = sha256Hex(canonicalJson(manifestCore));
        const manifest = {
            ...manifestCore,
            manifestSha256
        };

        const manifestPath = path.join(targetDir, 'integrity-manifest.json');
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

        return {
            recordPath,
            chainPath,
            manifestPath,
            manifest,
            evidenceRecord: sanitizedRecord
        };
    }
}

/**
 * Verifies local integrity manifest, artifact SHA-256 digests, runId consistency,
 * and deterministic hash chain for a historical or active remediation directory.
 */
function verifyEvidencePackage(targetDir, expectedRunId = null) {
    if (!targetDir || !fs.existsSync(targetDir)) {
        return {
            hasManifest: false,
            verified: false,
            status: 'MISSING_DIRECTORY',
            mismatches: [],
            chainErrors: [],
            warning: 'Evidence directory does not exist.'
        };
    }

    const manifestPath = path.join(targetDir, 'integrity-manifest.json');
    if (!fs.existsSync(manifestPath)) {
        return {
            hasManifest: false,
            verified: false,
            status: 'LEGACY_NO_MANIFEST',
            mismatches: [],
            chainErrors: [],
            warning: 'Historical/legacy evidence package has no Phase 2 SHA-256 integrity manifest.'
        };
    }

    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (err) {
        return {
            hasManifest: true,
            verified: false,
            status: 'TAMPERING_DETECTED',
            mismatches: [`integrity-manifest.json is malformed JSON: ${err.message}`],
            chainErrors: [],
            warning: 'Evidence Integrity Mismatch Detected: integrity manifest is corrupted.'
        };
    }

    const mismatches = [];
    const chainErrors = [];

    if (!manifest.runId || !manifest.findingId || !manifest.artifacts || typeof manifest.artifacts !== 'object') {
        mismatches.push('integrity-manifest.json missing mandatory runId, findingId, or artifacts fields.');
    }

    if (expectedRunId && manifest.runId !== String(expectedRunId)) {
        mismatches.push(`Run ID mismatch: expected '${expectedRunId}', manifest records '${manifest.runId}'.`);
    }

    // Verify self-digest of manifest core
    if (manifest.manifestSha256) {
        const { manifestSha256, ...core } = manifest;
        const recomputedManifestSha = sha256Hex(canonicalJson(core));
        if (recomputedManifestSha !== manifestSha256) {
            mismatches.push('integrity-manifest.json self-digest mismatch (manifest was altered).');
        }
    }

    // Verify every recorded artifact hash
    for (const [relName, meta] of Object.entries(manifest.artifacts || {})) {
        const artifactPath = path.join(targetDir, relName);
        if (!fs.existsSync(artifactPath)) {
            mismatches.push(`Missing evidence artifact '${relName}'.`);
            continue;
        }
        const buf = fs.readFileSync(artifactPath);
        const actualSha = sha256Hex(buf);
        if (actualSha !== meta.sha256) {
            mismatches.push(`Modified evidence artifact '${relName}' (SHA-256 mismatch).`);
        }
    }

    // Verify structured evidence record consistency & outcome honesty
    const recordPath = path.join(targetDir, 'evidence-record.json');
    let evidenceRecord = null;
    if (fs.existsSync(recordPath)) {
        try {
            evidenceRecord = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
            if (evidenceRecord.runId !== manifest.runId) {
                mismatches.push(`evidence-record.json runId '${evidenceRecord.runId}' !== manifest runId '${manifest.runId}'.`);
            }
            if (evidenceRecord.findingId !== manifest.findingId) {
                mismatches.push(`evidence-record.json findingId '${evidenceRecord.findingId}' !== manifest findingId '${manifest.findingId}'.`);
            }
            if (evidenceRecord.testResultCounts &&
                Number(evidenceRecord.testResultCounts.total || 0) <= 0 &&
                evidenceRecord.finalOutcome?.testOutcome === OUTCOME_STATUS.PASSED) {
                mismatches.push('evidence-record.json reports PASSED testOutcome with 0 tests executed.');
            }
        } catch (err) {
            mismatches.push(`evidence-record.json parse error: ${err.message}`);
        }
    }

    // Verify deterministic hash chain in events-chain.jsonl
    const chainPath = path.join(targetDir, 'events-chain.jsonl');
    if (fs.existsSync(chainPath)) {
        const rawLines = fs.readFileSync(chainPath, 'utf8').split(/\r?\n/).filter(Boolean);
        const expectedCount = manifest.chainSummary ? manifest.chainSummary.eventCount : rawLines.length;
        if (rawLines.length !== expectedCount) {
            chainErrors.push(`Event count mismatch: expected ${expectedCount} events, found ${rawLines.length} (event deletion/addition detected).`);
        }

        let expectedPrevHash = '0'.repeat(64);
        let lastHash = null;
        for (let i = 0; i < rawLines.length; i++) {
            let evt;
            try {
                evt = JSON.parse(rawLines[i]);
            } catch (err) {
                chainErrors.push(`Malformed JSON in events-chain.jsonl at index ${i}.`);
                break;
            }
            if (evt.seq !== i) {
                chainErrors.push(`Event sequence mismatch at index ${i}: found seq=${evt.seq} (reordering or deletion detected).`);
            }
            if (evt.runId !== manifest.runId) {
                chainErrors.push(`Event runId mismatch at seq=${evt.seq}: '${evt.runId}' !== '${manifest.runId}'.`);
            }
            if (evt.prevHash !== expectedPrevHash) {
                chainErrors.push(`Hash chain break at seq=${evt.seq}: prevHash does not match preceding eventHash.`);
            }
            const core = {
                seq: evt.seq,
                timestamp: evt.timestamp,
                runId: evt.runId,
                findingId: evt.findingId,
                stage: evt.stage,
                eventType: evt.eventType,
                payloadHash: evt.payloadHash,
                prevHash: evt.prevHash
            };
            const recomputedHash = sha256Hex(canonicalJson(core));
            if (recomputedHash !== evt.eventHash) {
                chainErrors.push(`Event hash mismatch at seq=${evt.seq} (event payload or metadata modified).`);
            }
            expectedPrevHash = evt.eventHash;
            lastHash = evt.eventHash;
        }

        if (manifest.chainSummary && manifest.chainSummary.tailHash && lastHash !== manifest.chainSummary.tailHash) {
            chainErrors.push('Tail eventHash does not match manifest chainSummary.tailHash.');
        }
    } else if (manifest.chainSummary && manifest.chainSummary.eventCount > 0) {
        chainErrors.push('events-chain.jsonl is missing.');
    }

    const verified = mismatches.length === 0 && chainErrors.length === 0;
    return {
        hasManifest: true,
        verified,
        status: verified ? 'VERIFIED_LOCAL_DIGESTS' : 'TAMPERING_DETECTED',
        runId: manifest.runId,
        findingId: manifest.findingId,
        storageGuarantee: manifest.storageGuarantee || 'LOCAL_TAMPER_DETECTION_ONLY_NOT_IMMUTABLE_WORM',
        cryptographicallySigned: false,
        mismatches,
        chainErrors,
        warning: verified
            ? 'Local SHA-256 manifest and hash chain verified (tamper detection only; not immutable WORM storage).'
            : `Evidence Integrity Mismatch Detected: ${[...mismatches, ...chainErrors].join(' | ')}`
    };
}

module.exports = {
    EVIDENCE_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    canonicalJson,
    sha256Hex,
    EvidenceWriter,
    LocalTamperDetectableEvidenceWriter,
    verifyEvidencePackage
};

