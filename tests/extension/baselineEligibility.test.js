'use strict';
const assert = require('assert');
const { isBaselineEligible } = require('../../extension/baselineEligibility');
const { normalizeCanonicalRunState, createCanonicalStages } = require('../../extension/runStateContract');
async function run() {
    const passed = { executed: true, countsKnown: true, testsTotal: 2, testsPassed: 2, testsFailed: 0, machineStatus: 'PASSED', exitCode: 0 };
    assert(isBaselineEligible(passed));
    assert(isBaselineEligible({ ...passed, testsPassed: 1, testsFailed: 1, machineStatus: 'FAILED', exitCode: 1, failureCategory: 'TESTS_FAILED' }));
    for (const baseline of [null, {}, { ...passed, executed: false }, { ...passed, countsKnown: false }, { ...passed, testsTotal: 0 }, { ...passed, testsPassed: 0 }, { ...passed, machineStatus: 'TIMED_OUT' }, { ...passed, machineStatus: 'FAILED', failureCategory: 'BUILD_FAILED' }, { machineStatus: 'UNTESTED', baselineExceptionAuthorized: true }]) assert(!isBaselineEligible(baseline));
    const stages = createCanonicalStages();
    stages[3].status = 'active';
    const state = normalizeCanonicalRunState({ stages, status: 'AWAITING_HUMAN_APPROVAL', baselineValidation: { machineStatus: 'UNTESTED', testsTotal: 0 } }, 'REGRESSION');
    assert.strictEqual(state.workflowLifecycle, 'BLOCKED');
    assert.strictEqual(state.stages[3].status, 'blocked_by_prerequisite');
    assert.strictEqual(state.securityValidationOutcome, 'NOT_EXECUTED');
    console.log('Baseline eligibility: executed pass/fail evidence accepted; unavailable validation blocks Stage 4.');
}
module.exports = { run };
if (require.main === module) run().catch(e => { console.error(e); process.exitCode = 1; });
