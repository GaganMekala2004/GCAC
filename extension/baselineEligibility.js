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
function isStage4ConsentEligible(state) {
    if (!state || state.workflowLifecycle === 'BLOCKED' || state.status === 'BLOCKED' || !isBaselineEligible(state.baselineValidation)) return false;
    if (state.approvalDecision !== 'PENDING_STAGE4' && state.status !== 'AWAITING_HUMAN_APPROVAL') return false;
    if (typeof state.patchDiff !== 'string' || !state.patchDiff.trim() || !/^[a-f0-9]{64}$/i.test(state.proposedDiffSha256 || '')) return false;
    return require('crypto').createHash('sha256').update(state.patchDiff, 'utf8').digest('hex') === state.proposedDiffSha256;
}
module.exports = { isBaselineEligible, isStage4ConsentEligible };
