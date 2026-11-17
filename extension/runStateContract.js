const { isBaselineEligible } = require('./baselineEligibility');
'use strict';

const fs = require('fs');
const path = require('path');

const RUN_STATE_SCHEMA_VERSION = 'GCAC-RUN-STATE-2.0';
const RUN_EVENT_SCHEMA_VERSION = 'GCAC-RUN-EVENT-2.0';

const CANONICAL_STAGES = Object.freeze([
    { stageNumber: 1, id: 'intake', label: 'Intake & Mapping', shortLabel: 'Intake' },
    { stageNumber: 2, id: 'classification', label: 'Classification', shortLabel: 'Classification' },
    { stageNumber: 3, id: 'analysis', label: 'Source Analysis', shortLabel: 'Source Analysis' },
    { stageNumber: 4, id: 'human-gate', label: 'Human Approval', shortLabel: 'Human Gate' },
    { stageNumber: 5, id: 'remediation', label: 'Code Remediation', shortLabel: 'Remediation' },
    { stageNumber: 6, id: 'bench-test', label: 'Bench Test & Re-Scan', shortLabel: 'Bench Test' },
    { stageNumber: 7, id: 'security-review', label: 'Security Review', shortLabel: 'Security Review' },
    { stageNumber: 8, id: 'final-human-gate', label: 'Final Sign-Off', shortLabel: 'Final Sign-Off' },
    { stageNumber: 9, id: 'manual-validations', label: 'Workflow Closure', shortLabel: 'Closure' }
]);

const STAGE_ID_TO_NUMBER = Object.freeze(
    CANONICAL_STAGES.reduce((acc, s) => {
        acc[s.id] = s.stageNumber;
        return acc;
    }, { context: 0 })
);

const WORKFLOW_LIFECYCLE = Object.freeze({
    NOT_STARTED: 'NOT_STARTED',
    HANDED_OFF_TO_COPILOT: 'HANDED_OFF_TO_COPILOT',
    AWAITING_VERIFIED_RESULT: 'AWAITING_VERIFIED_RESULT',
    IN_PROGRESS: 'IN_PROGRESS',
    WAITING_APPROVAL: 'WAITING_APPROVAL',
    COMPLETED: 'COMPLETED',
    CANCELLED: 'CANCELLED',
    BLOCKED: 'BLOCKED',
    ERROR: 'ERROR'
});

const VALIDATION_OUTCOME = Object.freeze({
    NOT_EXECUTED: 'NOT_EXECUTED',
    PASSED: 'PASSED',
    FAILED: 'FAILED',
    COULD_NOT_RUN: 'COULD_NOT_RUN',
    REGRESSION_DETECTED: 'REGRESSION_DETECTED',
    NOT_VERIFIED: 'NOT_VERIFIED',
    BLOCKED: 'BLOCKED'
});

const APPROVAL_DECISION = Object.freeze({
    NOT_REQUESTED: 'NOT_REQUESTED',
    PENDING_STAGE4: 'PENDING_STAGE4',
    APPROVED_STAGE4: 'APPROVED_STAGE4',
    REJECTED_STAGE4: 'REJECTED_STAGE4',
    PENDING_STAGE8: 'PENDING_STAGE8',
    APPROVED_STAGE8: 'APPROVED_STAGE8',
    BLOCKED_STAGE8: 'BLOCKED_STAGE8',
    REJECTED_STAGE8: 'REJECTED_STAGE8'
});

const FORMAL_CLOSURE = Object.freeze({
    OPEN: 'OPEN',
    HANDED_OFF_TO_COPILOT: 'HANDED_OFF_TO_COPILOT',
    IN_REMEDIATION: 'IN_REMEDIATION',
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    COULD_NOT_RUN: 'COULD_NOT_RUN',
    AWAITING_FINAL_SIGN_OFF: 'AWAITING_FINAL_SIGN_OFF',
    RESOLVED_CLOSED: 'RESOLVED_CLOSED',
    ROLLED_BACK: 'ROLLED_BACK'
});

const FINDING_STATE = Object.freeze({
    OPEN: 'OPEN',
    HANDED_OFF_TO_COPILOT: 'HANDED_OFF_TO_COPILOT',
    AWAITING_VERIFIED_RESULT: 'AWAITING_VERIFIED_RESULT',
    AWAITING_STAGE4_APPROVAL: 'AWAITING_STAGE4_APPROVAL',
    IN_REMEDIATION: 'IN_REMEDIATION',
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    COULD_NOT_RUN: 'COULD_NOT_RUN',
    AWAITING_FINAL_SIGN_OFF: 'AWAITING_FINAL_SIGN_OFF',
    RESOLVED: 'RESOLVED',
    ROLLED_BACK: 'ROLLED_BACK'
});

function createCanonicalStages() {
    return CANONICAL_STAGES.map(s => ({
        stageNumber: s.stageNumber,
        id: s.id,
        name: `Stage ${s.stageNumber}: ${s.label}`,
        label: s.label,
        shortLabel: s.shortLabel,
        status: 'pending',
        summary: '',
        durationSec: null,
        attemptId: null,
        failureCategory: null,
        evidenceRef: null,
        updatedAt: null
    }));
}

function resolveCanonicalStageIndex(stageIdOrNumber) {
    if (typeof stageIdOrNumber === 'number' && stageIdOrNumber >= 1 && stageIdOrNumber <= CANONICAL_STAGES.length) {
        return stageIdOrNumber - 1;
    }
    if (typeof stageIdOrNumber === 'string') {
        const lower = stageIdOrNumber.toLowerCase().trim();
        const idx = CANONICAL_STAGES.findIndex(s => s.id === lower);
        if (idx >= 0) return idx;
    }
    return -1;
}

function mapLegacyStatusToLifecycle(state = {}) {
    const rawStatus = String(state.status || '').toUpperCase();
    const valOutcome = String(state.securityValidationOutcome || state.testValidation?.outcome || state.validation?.outcome || '').toUpperCase();

    let workflowLifecycle = state.workflowLifecycle || WORKFLOW_LIFECYCLE.NOT_STARTED;
    let securityValidationOutcome = state.securityValidationOutcome || VALIDATION_OUTCOME.NOT_EXECUTED;
    let approvalDecision = state.approvalDecision || APPROVAL_DECISION.NOT_REQUESTED;
    let formalClosure = state.formalClosure || FORMAL_CLOSURE.OPEN;
    let findingState = state.findingState || FINDING_STATE.OPEN;

    if (valOutcome === 'PASSED' || valOutcome === 'PASS') {
        securityValidationOutcome = VALIDATION_OUTCOME.PASSED;
    } else if (valOutcome === 'FAILED' || valOutcome === 'FAIL') {
        securityValidationOutcome = VALIDATION_OUTCOME.FAILED;
    } else if (valOutcome === 'REGRESSION_DETECTED') {
        securityValidationOutcome = VALIDATION_OUTCOME.REGRESSION_DETECTED;
    } else if (valOutcome === 'COULD_NOT_RUN' || valOutcome === 'BLOCKED') {
        securityValidationOutcome = valOutcome === 'BLOCKED' ? VALIDATION_OUTCOME.BLOCKED : VALIDATION_OUTCOME.COULD_NOT_RUN;
    } else if (valOutcome === 'NOT_VERIFIED') {
        securityValidationOutcome = VALIDATION_OUTCOME.NOT_VERIFIED;
    }

    if (rawStatus === 'MANUAL_REVIEW' || state.isManualReview) {
        return { workflowLifecycle: WORKFLOW_LIFECYCLE.BLOCKED, securityValidationOutcome: VALIDATION_OUTCOME.NOT_EXECUTED,
            approvalDecision: APPROVAL_DECISION.NOT_REQUESTED, formalClosure: FORMAL_CLOSURE.OPEN, findingState: FINDING_STATE.OPEN };
    }

    if (rawStatus === 'BLOCKED' || state.failureCategory === 'TOOLCHAIN_IMAGE_UNAVAILABLE') {
        workflowLifecycle = WORKFLOW_LIFECYCLE.BLOCKED;
        securityValidationOutcome = VALIDATION_OUTCOME.NOT_EXECUTED;
        approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE4;
        formalClosure = FORMAL_CLOSURE.COULD_NOT_RUN;
        findingState = FINDING_STATE.COULD_NOT_RUN;
        return {
            workflowLifecycle,
            securityValidationOutcome,
            approvalDecision,
            formalClosure,
            findingState
        };
    }

    if (!state.workflowLifecycle) {
        if (rawStatus === 'HANDED_OFF_TO_COPILOT' || rawStatus === 'AWAITING_VERIFIED_RESULT') {
            workflowLifecycle = WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT;
        } else if (rawStatus === 'AWAITING_HUMAN_APPROVAL') {
            workflowLifecycle = WORKFLOW_LIFECYCLE.WAITING_APPROVAL;
        } else if (rawStatus === 'AWAITING_FINAL_APPROVAL') {
            workflowLifecycle = WORKFLOW_LIFECYCLE.WAITING_APPROVAL;
        } else if (rawStatus === 'COMPLETED' || rawStatus === 'RESOLVED' || rawStatus === 'VALIDATION_FAILED' || rawStatus === 'COULD_NOT_RUN') {
            workflowLifecycle = WORKFLOW_LIFECYCLE.COMPLETED;
        } else if (rawStatus === 'ERROR') {
            workflowLifecycle = WORKFLOW_LIFECYCLE.ERROR;
        } else if (rawStatus) {
            workflowLifecycle = WORKFLOW_LIFECYCLE.IN_PROGRESS;
        }
    }

    if (!state.approvalDecision) {
        if (rawStatus === 'AWAITING_HUMAN_APPROVAL') {
            approvalDecision = APPROVAL_DECISION.PENDING_STAGE4;
        } else if (rawStatus === 'REJECTED' || rawStatus === 'ROLLED_BACK') {
            approvalDecision = APPROVAL_DECISION.REJECTED_STAGE4;
        } else if (rawStatus === 'COMPLETED' && securityValidationOutcome === VALIDATION_OUTCOME.PASSED) {
            approvalDecision = APPROVAL_DECISION.APPROVED_STAGE8;
        } else if (state.isApproved || state.approvalRecordId) {
            if (securityValidationOutcome && securityValidationOutcome !== VALIDATION_OUTCOME.NOT_EXECUTED && securityValidationOutcome !== VALIDATION_OUTCOME.PASSED) {
                approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
            } else if (rawStatus === 'AWAITING_FINAL_APPROVAL') {
                approvalDecision = APPROVAL_DECISION.PENDING_STAGE8;
            } else {
                approvalDecision = APPROVAL_DECISION.APPROVED_STAGE4;
            }
        }
    }

    if (!state.formalClosure) {
        if (rawStatus === 'COMPLETED' && securityValidationOutcome === VALIDATION_OUTCOME.PASSED) {
            formalClosure = FORMAL_CLOSURE.RESOLVED_CLOSED;
        } else if (rawStatus === 'ROLLED_BACK' || rawStatus === 'REJECTED') {
            formalClosure = FORMAL_CLOSURE.ROLLED_BACK;
        } else if (securityValidationOutcome === VALIDATION_OUTCOME.FAILED || securityValidationOutcome === VALIDATION_OUTCOME.REGRESSION_DETECTED) {
            formalClosure = FORMAL_CLOSURE.VALIDATION_FAILED;
        } else if (securityValidationOutcome === VALIDATION_OUTCOME.COULD_NOT_RUN || securityValidationOutcome === VALIDATION_OUTCOME.BLOCKED || securityValidationOutcome === VALIDATION_OUTCOME.NOT_VERIFIED) {
            formalClosure = FORMAL_CLOSURE.COULD_NOT_RUN;
        } else if (rawStatus === 'AWAITING_FINAL_APPROVAL' && securityValidationOutcome === VALIDATION_OUTCOME.PASSED) {
            formalClosure = FORMAL_CLOSURE.AWAITING_FINAL_SIGN_OFF;
        } else if (workflowLifecycle === WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT) {
            formalClosure = FORMAL_CLOSURE.HANDED_OFF_TO_COPILOT;
        } else if (workflowLifecycle !== WORKFLOW_LIFECYCLE.NOT_STARTED) {
            formalClosure = FORMAL_CLOSURE.IN_REMEDIATION;
        }
    }

    if (!state.findingState) {
        if (formalClosure === FORMAL_CLOSURE.RESOLVED_CLOSED) {
            findingState = FINDING_STATE.RESOLVED;
        } else if (formalClosure === FORMAL_CLOSURE.ROLLED_BACK) {
            findingState = FINDING_STATE.ROLLED_BACK;
        } else if (formalClosure === FORMAL_CLOSURE.VALIDATION_FAILED) {
            findingState = FINDING_STATE.VALIDATION_FAILED;
        } else if (formalClosure === FORMAL_CLOSURE.COULD_NOT_RUN) {
            findingState = FINDING_STATE.COULD_NOT_RUN;
        } else if (formalClosure === FORMAL_CLOSURE.AWAITING_FINAL_SIGN_OFF) {
            findingState = FINDING_STATE.AWAITING_FINAL_SIGN_OFF;
        } else if (workflowLifecycle === WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT) {
            findingState = FINDING_STATE.AWAITING_VERIFIED_RESULT;
        } else if (approvalDecision === APPROVAL_DECISION.PENDING_STAGE4) {
            findingState = FINDING_STATE.AWAITING_STAGE4_APPROVAL;
        } else if (workflowLifecycle !== WORKFLOW_LIFECYCLE.NOT_STARTED) {
            findingState = FINDING_STATE.IN_REMEDIATION;
        }
    }

    return {
        workflowLifecycle,
        securityValidationOutcome,
        approvalDecision,
        formalClosure,
        findingState
    };
}

function deriveTerminalBanner(state = {}) {
    if (state.executionMode === 'LOCAL_DEVELOPMENT' && state.localOutcome) return `LOCAL_DEVELOPMENT — ${state.localOutcome}`;
    const wf = state.workflowLifecycle;
    const val = state.securityValidationOutcome;
    const closure = state.formalClosure;
    const finding = state.findingState;

    if (state.isManualReview || state.status === 'MANUAL_REVIEW') return 'Manual Architectural / Security Review Required';
    if (state.failureCategory === 'TOOLCHAIN_IMAGE_UNAVAILABLE') {
        return 'Workflow Blocked — Toolchain Image Unavailable';
    }
    if (wf === WORKFLOW_LIFECYCLE.BLOCKED) return 'Workflow Blocked — Prerequisites Not Satisfied';
    if (wf === WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT || finding === FINDING_STATE.AWAITING_VERIFIED_RESULT) {
        return 'Handed Off to Copilot — Awaiting Verified Result';
    }
    if (finding === FINDING_STATE.VALIDATION_FAILED || val === VALIDATION_OUTCOME.FAILED || val === VALIDATION_OUTCOME.REGRESSION_DETECTED) {
        return 'Workflow Ended — Validation Failed';
    }
    if (finding === FINDING_STATE.COULD_NOT_RUN || val === VALIDATION_OUTCOME.COULD_NOT_RUN || val === VALIDATION_OUTCOME.BLOCKED || val === VALIDATION_OUTCOME.NOT_VERIFIED) {
        return 'Workflow Ended — Validation Could Not Run';
    }
    if (closure === FORMAL_CLOSURE.RESOLVED_CLOSED && val === VALIDATION_OUTCOME.PASSED && state.approvalDecision === APPROVAL_DECISION.APPROVED_STAGE8) {
        return 'Workflow Completed — Remediation Verified & Signed Off';
    }
    if (finding === FINDING_STATE.AWAITING_FINAL_SIGN_OFF && val === VALIDATION_OUTCOME.PASSED) {
        return 'Awaiting Final Human Sign-Off (Validation Passed)';
    }
    if (finding === FINDING_STATE.AWAITING_STAGE4_APPROVAL) {
        return 'Awaiting Human Approval (Stage 4 Proposal Gate)';
    }
    if (closure === FORMAL_CLOSURE.ROLLED_BACK) {
        return 'Workflow Rolled Back';
    }
    if (wf === WORKFLOW_LIFECYCLE.ERROR) {
        return 'Workflow Stopped — Execution Error';
    }
    if (wf === WORKFLOW_LIFECYCLE.IN_PROGRESS) {
        return 'Remediation Workflow In Progress';
    }
    return '';
}

function buildRunEvent(fields = {}) {
    const stageId = fields.stageId || (fields.stageNumber ? CANONICAL_STAGES[fields.stageNumber - 1]?.id : 'context') || 'context';
    const stageNumber = fields.stageNumber !== undefined ? fields.stageNumber : (STAGE_ID_TO_NUMBER[stageId] ?? 0);
    const attemptNumber = Number(fields.attemptNumber || 1);
    const seq = Number(fields.seq || 0);
    const runId = String(fields.runId || 'RUN-UNSCOPED');

    return {
        schemaVersion: RUN_EVENT_SCHEMA_VERSION,
        eventId: fields.eventId || `EVT-${runId}-A${attemptNumber}-S${seq}`,
        runId,
        findingId: String(fields.findingId || ''),
        repositoryId: String(fields.repositoryId || ''),
        stageId,
        stageNumber,
        attemptId: String(fields.attemptId || `ATT-${String(attemptNumber).padStart(3, '0')}`),
        attemptNumber,
        seq,
        timestamp: fields.timestamp || new Date().toISOString(),
        eventType: String(fields.eventType || 'LOG'),
        executionState: String(fields.executionState || 'IN_PROGRESS'),
        validationOutcome: String(fields.validationOutcome || VALIDATION_OUTCOME.NOT_EXECUTED),
        evidenceRef: fields.evidenceRef || null,
        origin: String(fields.origin || 'EXTENSION_RUN_STATE_MANAGER'),
        summary: fields.summary || '',
        failureCategory: fields.failureCategory || null,
        durationSec: fields.durationSec !== undefined ? fields.durationSec : null
    };
}

function normalizeCanonicalRunState(raw = {}, findingId = '') {
    const effectiveFindingId = raw.findingId || raw.vulnerabilityId || findingId || '';
    const lifecycle = mapLegacyStatusToLifecycle(raw);
    const stages = Array.isArray(raw.stages) && raw.stages.length === CANONICAL_STAGES.length
        ? raw.stages.map((s, idx) => ({
            ...createCanonicalStages()[idx],
            ...s,
            stageNumber: CANONICAL_STAGES[idx].stageNumber,
            id: CANONICAL_STAGES[idx].id
        }))
        : createCanonicalStages();

    const normalized = {
        ...raw,
        schemaVersion: RUN_STATE_SCHEMA_VERSION,
        findingId: effectiveFindingId,
        vulnerabilityId: effectiveFindingId,
        runId: raw.runId || null,
        repositoryId: raw.repositoryId || raw.canonicalRepositoryId || raw.findingSnapshot?.canonicalRepositoryId || '',
        attemptId: raw.attemptId || `ATT-${String(Math.max(1, Number(raw.retryAttempts || 0) + 1)).padStart(3, '0')}`,
        attemptNumber: Number(raw.attemptNumber || (Number(raw.retryAttempts || 0) + 1)),
        lastAppliedSeq: Number(raw.lastAppliedSeq || 0),
        processedEventIds: Array.isArray(raw.processedEventIds) ? raw.processedEventIds.slice(-200) : [],
        workflowLifecycle: lifecycle.workflowLifecycle,
        stageExecutionLifecycle: stages,
        stages,
        securityValidationOutcome: lifecycle.securityValidationOutcome,
        approvalDecision: lifecycle.approvalDecision,
        formalClosure: lifecycle.formalClosure,
        findingState: lifecycle.findingState,
        handoff: raw.handoff || null,
        updatedAt: raw.updatedAt || new Date().toISOString()
    };
    if (raw.baselineValidation && !isBaselineEligible(raw.baselineValidation) &&
        !raw.stage4Approved && (normalized.stages[3].status === 'active' ||
        normalized.approvalDecision === APPROVAL_DECISION.PENDING_STAGE4)) {
        normalized.workflowLifecycle = WORKFLOW_LIFECYCLE.BLOCKED;
        normalized.status = 'BLOCKED';
        normalized.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE4;
        normalized.securityValidationOutcome = VALIDATION_OUTCOME.NOT_EXECUTED;
        normalized.stages[2].status = 'blocked';
        normalized.stages[3].status = 'blocked_by_prerequisite';
        for (let i = 4; i < normalized.stages.length; i++) normalized.stages[i].status = 'not_started';
    }
    // Recover the missing display marker on older verified Stage 8 pauses.
    // This does not grant approval or change any validation evidence.
    if (normalized.approvalDecision === APPROVAL_DECISION.PENDING_STAGE8 &&
        normalized.securityValidationOutcome === VALIDATION_OUTCOME.PASSED &&
        raw.stage4Approved && raw.patchAppliedAtStage5 && raw.evidenceChecklist?.finalSignOffAllowed === true) {
        normalized.stages[7].status = 'awaiting_review';
        normalized.stages[7].summary = 'Validation passed. Final human sign-off required.';
        normalized.stages[8].status = 'not_started';
    }
    if (normalized.workflowLifecycle === WORKFLOW_LIFECYCLE.COMPLETED &&
        normalized.formalClosure === FORMAL_CLOSURE.RESOLVED_CLOSED &&
        normalized.approvalDecision === APPROVAL_DECISION.APPROVED_STAGE8 &&
        normalized.securityValidationOutcome === VALIDATION_OUTCOME.PASSED && normalized.stages[7].status === 'completed') {
        normalized.stages[8].status = 'completed';
        normalized.stages[8].summary = 'Local verification evidence finalized. Remote publication is recorded separately.';
    }
    normalized.terminalBanner = deriveTerminalBanner(normalized);
    return normalized;
}

class RunStateManager {
    constructor(workspaceRoot, options = {}) {
        this.workspaceRoot = workspaceRoot;
        this.outputBaseDir = options.outputBaseDir || path.join(workspaceRoot, 'remediation-output');
    }

    _stateFilePath(findingId) {
        return path.join(this.outputBaseDir, String(findingId || '').trim(), 'run-state.json');
    }

    loadState(findingId) {
        if (!findingId) return null;
        const p = this._stateFilePath(findingId);
        if (!fs.existsSync(p)) return null;
        try {
            const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
            return normalizeCanonicalRunState(raw, findingId);
        } catch {
            return null;
        }
    }

    saveState(findingId, stateObj) {
        if (!findingId) return null;
        const p = this._stateFilePath(findingId);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        const canonical = normalizeCanonicalRunState(stateObj, findingId);
        canonical.updatedAt = new Date().toISOString();
        canonical.terminalBanner = deriveTerminalBanner(canonical);

        const tmp = `${p}.${process.pid}.${Date.now()}.tmp`;
        require('./evidenceLedger').writeStateWithIntegrity(path.dirname(p), () => {
            fs.writeFileSync(tmp, JSON.stringify(canonical, null, 2), 'utf8');
            fs.renameSync(tmp, p);
        });
        return canonical;
    }

    recordCopilotHandoff(findingId, metadata = {}) {
        const existing = this.loadState(findingId) || {};
        const runId = metadata.runId || existing.runId || `RUN-HANDOFF-${Date.now()}`;
        const now = new Date().toISOString();
        const attemptNumber = Number(metadata.attemptNumber || existing.attemptNumber || 1);
        const attemptId = metadata.attemptId || existing.attemptId || `ATT-${String(attemptNumber).padStart(3, '0')}`;
        const seq = existing.runId === runId ? Number(existing.lastAppliedSeq || 0) + 1 : 1;

        const stages = Array.isArray(existing.stages) && existing.stages.length === CANONICAL_STAGES.length
            ? existing.stages
            : createCanonicalStages();

        // Mark Stage 1 complete (finding mapped) without fabricating Stages 2-9!
        if (stages[0].status === 'pending') {
            stages[0].status = 'completed';
            stages[0].summary = 'Finding mapped and handed off to Copilot Chat.';
            stages[0].updatedAt = now;
        }

        const nextState = normalizeCanonicalRunState({
            ...existing,
            findingId,
            runId,
            repositoryId: metadata.repositoryId || existing.repositoryId || '',
            attemptId,
            attemptNumber,
            lastAppliedSeq: seq,
            status: WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT,
            workflowLifecycle: WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT,
            securityValidationOutcome: existing.securityValidationOutcome || VALIDATION_OUTCOME.NOT_EXECUTED,
            approvalDecision: existing.approvalDecision || APPROVAL_DECISION.NOT_REQUESTED,
            formalClosure: FORMAL_CLOSURE.HANDED_OFF_TO_COPILOT,
            findingState: FINDING_STATE.AWAITING_VERIFIED_RESULT,
            stages,
            handoff: {
                state: 'HANDED_OFF_TO_COPILOT',
                displayState: 'AWAITING_VERIFIED_RESULT',
                handedOffAt: now,
                lastSyncedAt: now,
                nativeTelemetryAvailable: false,
                queryIssued: Boolean(metadata.queryIssued),
                origin: 'EXTENSION_COPILOT_HANDOFF',
                note: 'Copilot Chat prompt dispatched. Native Copilot turns are unobservable until @vulnerability-orchestrator or verified machine execution emits canonical run-state events.'
            }
        }, findingId);

        const evt = buildRunEvent({
            runId,
            findingId,
            repositoryId: nextState.repositoryId,
            stageId: 'intake',
            stageNumber: 1,
            attemptId,
            attemptNumber,
            seq,
            timestamp: now,
            eventType: 'COPILOT_HANDOFF',
            executionState: 'HANDED_OFF_TO_COPILOT',
            validationOutcome: nextState.securityValidationOutcome,
            origin: 'EXTENSION_COPILOT_HANDOFF',
            summary: 'Handed off to Copilot Chat; awaiting verified result.'
        });
        nextState.processedEventIds = [...(existing.processedEventIds || []).slice(-199), evt.eventId];
        return { state: this.saveState(findingId, nextState), event: evt };
    }

    /**
     * Applies a structured GCAC-RUN-EVENT-2.0 event strictly validating runId,
     * attemptNumber/attemptId, monotonic seq, and duplicate eventId protection.
     */
    applyEvent(findingId, rawEvent) {
        if (!findingId || !rawEvent || typeof rawEvent !== 'object') {
            return { accepted: false, reason: 'INVALID_EVENT_PAYLOAD', state: null };
        }

        const evt = buildRunEvent({ ...rawEvent, findingId });
        const current = this.loadState(findingId) || normalizeCanonicalRunState({ findingId }, findingId);

        // 1. Run ID check: reject stale events from older/other runs (except explicit new RUN_STARTED)
        const startsNewRun = evt.eventType === 'RUN_STARTED' || evt.eventType === 'COPILOT_HANDOFF';
        if (current.runId && !startsNewRun && evt.runId !== current.runId) {
            return { accepted: false, reason: 'STALE_OR_MISMATCHED_RUN_ID', currentState: current };
        }

        // 2. Duplicate event protection
        if (current.runId === evt.runId && current.processedEventIds.includes(evt.eventId)) {
            return { accepted: false, reason: 'DUPLICATE_EVENT', currentState: current };
        }

        // 3. Attempt ordering guard: delayed event from older attempt must never overwrite newer attempt
        if (current.runId === evt.runId) {
            if (evt.attemptNumber < current.attemptNumber) {
                return { accepted: false, reason: 'STALE_ATTEMPT_EVENT', currentState: current };
            }
            // 4. Sequence ordering guard within same run & attempt
            if (evt.attemptNumber === current.attemptNumber && evt.seq > 0 && evt.seq <= current.lastAppliedSeq) {
                return { accepted: false, reason: 'OUT_OF_ORDER_SEQUENCE', currentState: current };
            }
        }

        const next = normalizeCanonicalRunState(current, findingId);
        const isNewRun = startsNewRun && current.runId !== evt.runId;
        if (isNewRun) {
            next.stages = createCanonicalStages();
            next.stageExecutionLifecycle = next.stages;
            next.processedEventIds = [];
            next.lastAppliedSeq = 0;
            next.securityValidationOutcome = VALIDATION_OUTCOME.NOT_EXECUTED;
            next.approvalDecision = APPROVAL_DECISION.NOT_REQUESTED;
            next.formalClosure = FORMAL_CLOSURE.IN_REMEDIATION;
            next.findingState = FINDING_STATE.IN_REMEDIATION;
        }

        next.runId = evt.runId;
        if (evt.repositoryId) next.repositoryId = evt.repositoryId;
        next.attemptNumber = evt.attemptNumber;
        next.attemptId = evt.attemptId;
        if (evt.seq > next.lastAppliedSeq) next.lastAppliedSeq = evt.seq;
        next.processedEventIds = [...next.processedEventIds.slice(-199), evt.eventId];
        if (next.handoff && evt.origin === 'COPILOT_CHAT_PARTICIPANT') {
            next.handoff.state = 'SYNCED';
            next.handoff.displayState = 'SYNCED';
            next.handoff.lastSyncedAt = evt.timestamp;
        }

        const stageIdx = resolveCanonicalStageIndex(evt.stageNumber || evt.stageId);
        const stage = stageIdx >= 0 ? next.stages[stageIdx] : null;

        if (evt.eventType === 'STAGE_START' && stage) {
            stage.status = 'active';
            stage.attemptId = evt.attemptId;
            stage.summary = evt.summary || stage.summary;
            stage.updatedAt = evt.timestamp;
            next.workflowLifecycle = WORKFLOW_LIFECYCLE.IN_PROGRESS;
            next.findingState = FINDING_STATE.IN_REMEDIATION;
        } else if (evt.eventType === 'STAGE_COMPLETE' && stage) {
            stage.status = 'completed';
            stage.attemptId = evt.attemptId;
            stage.summary = evt.summary || stage.summary;
            stage.durationSec = evt.durationSec !== null ? evt.durationSec : stage.durationSec;
            stage.evidenceRef = evt.evidenceRef || stage.evidenceRef;
            stage.updatedAt = evt.timestamp;
        } else if (evt.eventType === 'STAGE_FAILED' && stage) {
            // Terminal failed stage, NEVER left active
            stage.status = 'failed';
            stage.attemptId = evt.attemptId;
            stage.summary = evt.summary || stage.summary;
            stage.failureCategory = evt.failureCategory || stage.failureCategory;
            stage.durationSec = evt.durationSec !== null ? evt.durationSec : stage.durationSec;
            stage.evidenceRef = evt.evidenceRef || stage.evidenceRef;
            stage.updatedAt = evt.timestamp;
        } else if (evt.eventType === 'STAGE_BLOCKED' && stage) {
            stage.status = 'blocked';
            stage.attemptId = evt.attemptId;
            stage.summary = evt.summary || stage.summary;
            stage.updatedAt = evt.timestamp;
        } else if (evt.eventType === 'APPROVAL_REQUIRED' && stage) {
            stage.status = 'waiting';
            next.workflowLifecycle = WORKFLOW_LIFECYCLE.WAITING_APPROVAL;
            next.approvalDecision = stage.stageNumber === 4 ? APPROVAL_DECISION.PENDING_STAGE4 : APPROVAL_DECISION.PENDING_STAGE8;
            next.findingState = stage.stageNumber === 4 ? FINDING_STATE.AWAITING_STAGE4_APPROVAL : FINDING_STATE.AWAITING_FINAL_SIGN_OFF;
        } else if (evt.eventType === 'FINAL_GATE_REQUIRED') {
            if (next.stages[7]) {
                next.stages[7].status = 'waiting';
                next.stages[7].updatedAt = evt.timestamp;
            }
            next.workflowLifecycle = WORKFLOW_LIFECYCLE.WAITING_APPROVAL;
            next.approvalDecision = APPROVAL_DECISION.PENDING_STAGE8;
            next.formalClosure = FORMAL_CLOSURE.AWAITING_FINAL_SIGN_OFF;
            next.findingState = FINDING_STATE.AWAITING_FINAL_SIGN_OFF;
        } else if (evt.eventType === 'FINAL_GATE_BLOCKED') {
            if (next.stages[7]) {
                next.stages[7].status = 'blocked';
                next.stages[7].summary = evt.summary || 'Final sign-off blocked because post-fix validation failed or was incomplete.';
                next.stages[7].updatedAt = evt.timestamp;
            }
            next.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
        } else if (evt.eventType === 'WORKFLOW_CONCLUDED' || evt.eventType === 'WORKFLOW_COMPLETE') {
            next.workflowLifecycle = WORKFLOW_LIFECYCLE.COMPLETED;
        } else if (evt.eventType === 'WORKFLOW_ERROR') {
            next.workflowLifecycle = WORKFLOW_LIFECYCLE.ERROR;
        }

        // Security validation outcome & honest terminal state derivation
        if (evt.validationOutcome && evt.validationOutcome !== VALIDATION_OUTCOME.NOT_EXECUTED) {
            next.securityValidationOutcome = evt.validationOutcome;
            if (evt.validationOutcome === VALIDATION_OUTCOME.FAILED || evt.validationOutcome === VALIDATION_OUTCOME.REGRESSION_DETECTED) {
                if (next.stages[5] && next.stages[5].status === 'active') {
                    next.stages[5].status = 'failed';
                }
                if (next.stages[7] && next.stages[7].status !== 'failed') {
                    next.stages[7].status = 'blocked';
                }
                next.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
                next.formalClosure = FORMAL_CLOSURE.VALIDATION_FAILED;
                next.findingState = FINDING_STATE.VALIDATION_FAILED;
            } else if (evt.validationOutcome === VALIDATION_OUTCOME.COULD_NOT_RUN || evt.validationOutcome === VALIDATION_OUTCOME.BLOCKED || evt.validationOutcome === VALIDATION_OUTCOME.NOT_VERIFIED) {
                if (next.stages[7]) next.stages[7].status = 'blocked';
                next.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
                next.formalClosure = FORMAL_CLOSURE.COULD_NOT_RUN;
                next.findingState = FINDING_STATE.COULD_NOT_RUN;
            }
        }

        if (next.stages[8] && next.stages[8].status === 'completed' && next.securityValidationOutcome === VALIDATION_OUTCOME.PASSED && next.approvalDecision === APPROVAL_DECISION.APPROVED_STAGE8) {
            next.formalClosure = FORMAL_CLOSURE.RESOLVED_CLOSED;
            next.findingState = FINDING_STATE.RESOLVED;
        }

        const saved = this.saveState(findingId, next);
        return { accepted: true, event: evt, state: saved };
    }
}

module.exports = {
    RUN_STATE_SCHEMA_VERSION,
    RUN_EVENT_SCHEMA_VERSION,
    CANONICAL_STAGES,
    STAGE_ID_TO_NUMBER,
    WORKFLOW_LIFECYCLE,
    VALIDATION_OUTCOME,
    APPROVAL_DECISION,
    FORMAL_CLOSURE,
    FINDING_STATE,
    createCanonicalStages,
    resolveCanonicalStageIndex,
    mapLegacyStatusToLifecycle,
    deriveTerminalBanner,
    buildRunEvent,
    normalizeCanonicalRunState,
    RunStateManager
};

