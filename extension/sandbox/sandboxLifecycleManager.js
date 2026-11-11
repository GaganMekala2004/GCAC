'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SANDBOX_LIFECYCLE_STATES } = require('./executionBackend');

/**
 * Manages safe sandbox instance lifecycle states, crash/reload recovery,
 * and owned-only cleanup tracking.
 */
class SandboxLifecycleManager {
    constructor(options = {}) {
        this.stateDir = options.stateDir || null;
        this.instances = new Map();
    }

    createInstance({ runId, vulnerabilityId, applicationId, operation, backendType, toolchainProfileId }) {
        const instanceId = `gcac-${crypto.randomBytes(6).toString('hex')}`;
        const record = {
            instanceId,
            runId: String(runId || ''),
            vulnerabilityId: String(vulnerabilityId || ''),
            applicationId: String(applicationId || ''),
            operation: String(operation || ''),
            backendType: String(backendType || 'NONE'),
            toolchainProfileId: String(toolchainProfileId || ''),
            state: SANDBOX_LIFECYCLE_STATES.PENDING,
            history: [
                { state: SANDBOX_LIFECYCLE_STATES.PENDING, timestamp: new Date().toISOString(), detail: 'Instance registered.' }
            ],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            stagingDir: null,
            containerName: null
        };
        this.instances.set(instanceId, record);
        this._persistInstance(record);
        return record;
    }

    transition(instanceId, nextState, detail = '', extra = {}) {
        const record = this.instances.get(instanceId);
        if (!record) {
            throw new Error(`Unknown sandbox instanceId '${instanceId}'.`);
        }
        record.state = nextState;
        record.updatedAt = new Date().toISOString();
        if (extra.stagingDir) record.stagingDir = extra.stagingDir;
        if (extra.containerName) record.containerName = extra.containerName;
        if (extra.reasonCode) record.reasonCode = extra.reasonCode;
        record.history.push({
            state: nextState,
            timestamp: record.updatedAt,
            detail
        });
        this._persistInstance(record);
        return record;
    }

    getInstance(instanceId) {
        return this.instances.get(instanceId) || null;
    }

    /**
     * Inspects persisted sandbox instances on extension reload / runner recovery.
     * Any stale PREPARING or RUNNING instance is marked FAILED (never restarted automatically)
     * and only owned staging resources are safely removed.
     */
    async recoverOrphanedInstances(backend = null) {
        const recovered = [];
        if (!this.stateDir || !fs.existsSync(this.stateDir)) {
            return { recovered, orphanedContainerCleanup: null };
        }

        const files = fs.readdirSync(this.stateDir).filter(f => f.endsWith('.json'));
        for (const f of files) {
            const full = path.join(this.stateDir, f);
            try {
                const rec = JSON.parse(fs.readFileSync(full, 'utf8'));
                if (rec.state === SANDBOX_LIFECYCLE_STATES.PREPARING || rec.state === SANDBOX_LIFECYCLE_STATES.RUNNING || rec.state === SANDBOX_LIFECYCLE_STATES.PENDING) {
                    rec.state = SANDBOX_LIFECYCLE_STATES.FAILED;
                    rec.updatedAt = new Date().toISOString();
                    rec.crashRecovered = true;
                    rec.history = Array.isArray(rec.history) ? rec.history : [];
                    rec.history.push({
                        state: SANDBOX_LIFECYCLE_STATES.FAILED,
                        timestamp: rec.updatedAt,
                        detail: 'Interrupted by extension reload or runner crash; marked FAILED (no automatic mutating restart).'
                    });

                    if (rec.stagingDir && backend && backend.stagingManager) {
                        try {
                            backend.stagingManager.cleanupStaging(rec.stagingDir);
                        } catch (cleanErr) {
                            rec.state = SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED;
                            rec.history.push({
                                state: SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED,
                                timestamp: new Date().toISOString(),
                                detail: `Orphaned staging cleanup failed: ${cleanErr.message}`
                            });
                        }
                    }

                    fs.writeFileSync(full, JSON.stringify(rec, null, 2), 'utf8');
                    recovered.push(rec);
                }
            } catch {}
        }

        let orphanedContainerCleanup = null;
        if (backend && typeof backend.cleanupOrphanedContainers === 'function') {
            orphanedContainerCleanup = await backend.cleanupOrphanedContainers();
        }

        return { recovered, orphanedContainerCleanup };
    }

    _persistInstance(record) {
        if (!this.stateDir) return;
        try {
            fs.mkdirSync(this.stateDir, { recursive: true });
            fs.writeFileSync(
                path.join(this.stateDir, `${record.instanceId}.json`),
                JSON.stringify(record, null, 2),
                'utf8'
            );
        } catch {}
    }
}

module.exports = {
    SandboxLifecycleManager
};

