'use strict';
function isBaselineEligible(baseline) {
    if (!baseline) return false;
    const outcome = baseline.machineStatus || baseline.status;
    if (baseline.baselineExceptionAuthorized === true &&
        typeof baseline.baselineExceptionRationale === 'string' && baseline.baselineExceptionRationale.trim() &&
        outcome === 'UNTESTED') return true;
    if (baseline.executed !== true || baseline.countsKnown !== true || !(baseline.testsTotal > 0) ||
        !((baseline.testsPassed || 0) + (baseline.testsFailed || 0) > 0) || baseline.timedOut || baseline.cancelled) return false;
    if (outcome === 'PASSED' || outcome === 'PASS') return baseline.exitCode === 0 && !baseline.testsFailed;
    return (outcome === 'FAILED' || outcome === 'FAIL') && baseline.testsFailed > 0 &&
        baseline.failureCategory === 'TESTS_FAILED';
}
const { computeDiffSha256, extractDiffFilePaths } = require('./approvalGovernance');

function hasPendingStage4Proposal(state) {
    const request = state?.pendingApprovalRequest;
    if (!request || state.stage !== 4 || state.status !== 'AWAITING_HUMAN_APPROVAL' ||
        state.approvalDecision !== 'PENDING_STAGE4' || state.workflowLifecycle === 'BLOCKED' ||
        state.stage4Approved || state.patchAppliedAtStage5 || !isBaselineEligible(state.baselineValidation)) return false;
    if (request.decision !== 'PENDING' || request.consumedAtStage5 !== false || !(Date.parse(request.expiresAt) > Date.now()) ||
        !state.runId || request.runId !== state.runId || !state.vulnerabilityId || request.vulnerabilityId !== state.vulnerabilityId ||
        !state.applicationNumber || request.applicationId !== state.applicationNumber ||
        !state.baseCommitHash || request.baseCommitHash !== state.baseCommitHash ||
        !state.patchDiff || request.proposedDiffSha256 !== state.proposedDiffSha256 ||
        computeDiffSha256(state.patchDiff) !== state.proposedDiffSha256) return false;
    const files = extractDiffFilePaths(state.patchDiff);
    return files.length > 0 && [request.approvedFilePaths, state.approvedFilePaths].every(paths =>
        Array.isArray(paths) && paths.length === files.length && [...paths].sort().every((file, i) => file === files[i]));
}

// Older releases copied a previous generation's approval into a new pending run.
// Discard it in memory only when an independently bound current request exists.
function reconcileStage4Approval(state) {
    const record = state?.approvalRecord;
    if (record?.consumedAtStage5 && record.runId && record.runId !== state.runId &&
        record.vulnerabilityId === state.vulnerabilityId && hasPendingStage4Proposal(state)) {
        return { ...state, approvalRecord: null };
    }
    return state;
}

function isStage4ConsentEligible(state) {
    return hasPendingStage4Proposal(state) && !reconcileStage4Approval(state).approvalRecord?.consumedAtStage5;
}
module.exports = { isBaselineEligible, isStage4ConsentEligible, reconcileStage4Approval };
