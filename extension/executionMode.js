'use strict';
const { canonicalizePath } = require('./repositoryContext');
const EXECUTION_MODE = Object.freeze({ ENTERPRISE: 'ENTERPRISE', LOCAL_DEVELOPMENT: 'LOCAL_DEVELOPMENT' });
function resolveExecutionMode(env = process.env) {
    const mode = env.GCAC_EXECUTION_MODE || EXECUTION_MODE.ENTERPRISE;
    if (!Object.values(EXECUTION_MODE).includes(mode)) throw new Error('EXECUTION_MODE_INVALID: Expected ENTERPRISE or LOCAL_DEVELOPMENT.');
    if (mode === EXECUTION_MODE.LOCAL_DEVELOPMENT &&
        [env.NODE_ENV, env.GCAC_DEPLOYMENT_ENV].some(value => /^(production|prod)$/i.test(value || ''))) {
        throw new Error('LOCAL_DEVELOPMENT_FORBIDDEN_IN_PRODUCTION');
    }
    return mode;
}
function assertDevelopmentRepository(registry, repoPath, workspaceTrusted) {
    if (workspaceTrusted !== true) throw new Error('LOCAL_DEVELOPMENT_REQUIRES_WORKSPACE_TRUST');
    registry.reload();
    const entry = registry.localMappings.get(canonicalizePath(repoPath).toLowerCase());
    if (!entry || entry.development?.trusted !== true || entry.development?.disposable !== true || !entry.development?.acknowledgedAt) {
        throw new Error('LOCAL_DEVELOPMENT_REPOSITORY_NOT_ENROLLED: Explicitly register this trusted disposable development repository.');
    }
    return entry;
}
function canAcknowledgeMissingBaseline(baseline) {
    return Boolean(baseline && ['UNTESTED', 'COULD_NOT_RUN'].includes(baseline.machineStatus) &&
        ['NO_TESTS_DISCOVERED', 'TEST_PROJECT_NOT_FOUND', 'TEST_RESULTS_MISSING', 'RESTORE_FAILED'].includes(baseline.failureCategory) &&
        !baseline.testsFailed && !baseline.timedOut && !baseline.cancelled);
}
function developmentConclusion({ evaluation, baseline, tests, reScan, review }) {
    const technicalFailure = tests?.testsFailed > 0 || ['FAILED', 'TIMED_OUT', 'CANCELLED'].includes(tests?.machineStatus) ||
        ['STILL_PRESENT', 'REGRESSION_DETECTED'].includes(reScan?.machineStatus) || review?.rating === 'FAIL';
    if (technicalFailure) return { localOutcome: 'FAILED', verifiedRemediation: false };
    if (tests?.machineStatus === 'BLOCKED') return { localOutcome: 'BLOCKED', verifiedRemediation: false };
    const verified = evaluation?.isResolved === true && baseline?.baselineExceptionAuthorized !== true;
    return { localOutcome: verified ? 'COMPLETED_VERIFIED' : 'COMPLETED_WITH_LIMITATIONS', verifiedRemediation: verified };
}
module.exports = { EXECUTION_MODE, resolveExecutionMode, assertDevelopmentRepository, canAcknowledgeMissingBaseline, developmentConclusion };
