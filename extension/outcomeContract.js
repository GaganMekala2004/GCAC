'use strict';

/**
 * Authoritative Outcome Contract for GCAC Vulnerability Remediation Hub.
 *
 * Strictly separates:
 *  1. Scanner result (`scannerOutcome`)
 *  2. Test execution result (`testOutcome`)
 *  3. Remediation workflow status (`workflowOutcome`)
 *  4. Final validation decision (`finalValidationOutcome`)
 *  5. Formal vulnerability closure status (`closureOutcome`)
 *
 * Ensures that unavailable tools, missing scanners, zero-test runs, skipped
 * execution, or model self-assertions can NEVER silently become PASS/RESOLVED.
 */

const OUTCOME_STATUS = Object.freeze({
    PASSED: 'PASSED',
    FAILED: 'FAILED',
    BLOCKED: 'BLOCKED',
    UNTESTED: 'UNTESTED',
    COULD_NOT_RUN: 'COULD_NOT_RUN',
    NOT_VERIFIED: 'NOT_VERIFIED',
    CANCELLED: 'CANCELLED',
    TIMED_OUT: 'TIMED_OUT',
    PARTIAL: 'PARTIAL',
    RESOLVED: 'RESOLVED',
    STILL_PRESENT: 'STILL_PRESENT',
    INCONCLUSIVE: 'INCONCLUSIVE',
    REGRESSION_DETECTED: 'REGRESSION_DETECTED'
});

const LEGACY_VERIFICATION_DISPLAY = Object.freeze({
    [OUTCOME_STATUS.RESOLVED]: 'RESOLVED',
    [OUTCOME_STATUS.STILL_PRESENT]: 'STILL PRESENT',
    [OUTCOME_STATUS.INCONCLUSIVE]: 'INCONCLUSIVE',
    [OUTCOME_STATUS.NOT_VERIFIED]: 'NOT VERIFIED',
    [OUTCOME_STATUS.REGRESSION_DETECTED]: 'REGRESSION DETECTED',
    [OUTCOME_STATUS.BLOCKED]: 'BLOCKED',
    [OUTCOME_STATUS.UNTESTED]: 'UNTESTED',
    [OUTCOME_STATUS.COULD_NOT_RUN]: 'COULD NOT RUN',
    [OUTCOME_STATUS.CANCELLED]: 'CANCELLED',
    [OUTCOME_STATUS.TIMED_OUT]: 'TIMED OUT',
    [OUTCOME_STATUS.FAILED]: 'FAILED',
    [OUTCOME_STATUS.PARTIAL]: 'PARTIAL',
    [OUTCOME_STATUS.PASSED]: 'PASSED'
});

const CLOSURE_STATUS = Object.freeze({
    OPEN: 'OPEN',
    PENDING_FORMAL_CLOSURE: 'PENDING_FORMAL_CLOSURE',
    NOT_CLOSED: 'NOT_CLOSED'
});

const APPROVED_SCANNER_IDS = Object.freeze(new Set([
    'dotnet-security',
    'nuget-audit',
    'secrets-config',
    'codeql'
]));

const SCANNER_ALIAS_MAP = Object.freeze({
    'dotnet-security': 'dotnet-security',
    'dotnet-security-scanner': 'dotnet-security',
    'roslyn': 'dotnet-security',
    'nuget-audit': 'nuget-audit',
    'nuget-audit-scanner': 'nuget-audit',
    'secrets-config': 'secrets-config',
    'secrets-config-scanner': 'secrets-config',
    'codeql': 'codeql',
    'codeql-scanner': 'codeql'
});

/**
 * Normalizes any legacy or machine outcome string into an authoritative OUTCOME_STATUS.
 * Unrecognized strings fail closed to NOT_VERIFIED.
 *
 * @param {string} rawStatus
 * @returns {string}
 */
function normalizeMachineOutcome(rawStatus) {
    if (!rawStatus || typeof rawStatus !== 'string') {
        return OUTCOME_STATUS.NOT_VERIFIED;
    }

    const token = rawStatus.trim().toUpperCase().replace(/[\s-]+/g, '_');

    switch (token) {
        case 'PASS':
        case 'PASSED':
            return OUTCOME_STATUS.PASSED;
        case 'FAIL':
        case 'FAILED':
        case 'VALIDATION_FAILED':
            return OUTCOME_STATUS.FAILED;
        case 'BLOCKED':
        case 'POLICY_BLOCKED':
        case 'SANDBOX_UNAVAILABLE':
            return OUTCOME_STATUS.BLOCKED;
        case 'CANCELLED':
        case 'CANCELED':
            return OUTCOME_STATUS.CANCELLED;
        case 'TIMED_OUT':
        case 'TIMEOUT':
            return OUTCOME_STATUS.TIMED_OUT;
        case 'UNTESTED':
        case 'NOT_EXECUTED':
        case 'SKIPPED':
            return OUTCOME_STATUS.UNTESTED;
        case 'COULD_NOT_RUN':
        case 'UNAVAILABLE':
        case 'NOT_INSTALLED':
            return OUTCOME_STATUS.COULD_NOT_RUN;
        case 'NOT_VERIFIED':
            return OUTCOME_STATUS.NOT_VERIFIED;
        case 'PARTIAL':
            return OUTCOME_STATUS.PARTIAL;
        case 'RESOLVED':
            return OUTCOME_STATUS.RESOLVED;
        case 'STILL_PRESENT':
            return OUTCOME_STATUS.STILL_PRESENT;
        case 'INCONCLUSIVE':
            return OUTCOME_STATUS.INCONCLUSIVE;
        case 'REGRESSION_DETECTED':
            return OUTCOME_STATUS.REGRESSION_DETECTED;
        default:
            return OUTCOME_STATUS.NOT_VERIFIED;
    }
}

/**
 * Converts a machine-readable outcome into its explicit legacy UI/test display form
 * without altering the underlying semantic meaning.
 *
 * @param {string} machineStatus
 * @returns {string}
 */
function toLegacyVerificationDisplay(machineStatus) {
    const normalized = normalizeMachineOutcome(machineStatus);
    return LEGACY_VERIFICATION_DISPLAY[normalized] || 'NOT VERIFIED';
}

/**
 * Maps a normalized machine test outcome to legacy CSV Test_Status text.
 *
 * @param {string} machineTestOutcome
 * @returns {string}
 */
function toLegacyCsvTestDisplay(machineTestOutcome) {
    const norm = normalizeMachineOutcome(machineTestOutcome);
    if (norm === OUTCOME_STATUS.PASSED) return 'PASS';
    if (norm === OUTCOME_STATUS.FAILED || norm === OUTCOME_STATUS.REGRESSION_DETECTED) return 'FAIL';
    if (norm === OUTCOME_STATUS.BLOCKED) return 'BLOCKED';
    if (norm === OUTCOME_STATUS.CANCELLED) return 'CANCELLED';
    if (norm === OUTCOME_STATUS.TIMED_OUT) return 'TIMED OUT';
    if (norm === OUTCOME_STATUS.COULD_NOT_RUN || norm === OUTCOME_STATUS.UNTESTED) return 'NOT EXECUTED';
    if (norm === OUTCOME_STATUS.PARTIAL) return 'PARTIAL';
    return 'NOT VERIFIED';
}

/**
 * Explicitly resolves the originating scanner ID for a finding.
 * Never defaults silently to an unrelated scanner such as secrets-config.
 *
 * @param {object} finding
 * @returns {{ resolved: boolean, scannerId: string|null, rawScannerId: string|null }}
 */
function resolveOriginatingScannerId(finding) {
    if (!finding || typeof finding !== 'object') {
        return { resolved: false, scannerId: null, rawScannerId: null };
    }

    const candidates = [
        finding.scannerId,
        finding.Scanner_ID,
        finding.scanner_id,
        finding.properties && finding.properties.scannerId
    ];

    let raw = null;
    for (const c of candidates) {
        if (typeof c === 'string' && c.trim().length > 0) {
            raw = c.trim();
            break;
        }
    }

    if (!raw) {
        return { resolved: false, scannerId: null, rawScannerId: null };
    }

    const canonical = SCANNER_ALIAS_MAP[raw.toLowerCase()] || raw.toLowerCase();
    if (!APPROVED_SCANNER_IDS.has(canonical)) {
        return { resolved: false, scannerId: canonical, rawScannerId: raw };
    }

    return { resolved: true, scannerId: canonical, rawScannerId: raw };
}

/**
 * Computes machine test outcome from a raw test runner result object.
 * Guarantees zero-test runs (when tests are required) never map to PASSED.
 *
 * @param {object|null} testResult
 * @param {object} [opts]
 * @param {boolean} [opts.allowZeroTests=false]
 * @returns {string}
 */
function classifyTestOutcome(testResult, opts = {}) {
    if (!testResult || typeof testResult !== 'object') {
        return OUTCOME_STATUS.UNTESTED;
    }

    if (testResult.machineStatus) {
        const explicit = normalizeMachineOutcome(testResult.machineStatus);
        if (explicit === OUTCOME_STATUS.BLOCKED ||
            explicit === OUTCOME_STATUS.COULD_NOT_RUN ||
            explicit === OUTCOME_STATUS.CANCELLED ||
            explicit === OUTCOME_STATUS.TIMED_OUT) {
            return explicit;
        }
    }

    if (testResult.cancelled === true) {
        return OUTCOME_STATUS.CANCELLED;
    }
    if (testResult.timedOut === true) {
        return OUTCOME_STATUS.TIMED_OUT;
    }

    if (testResult.executed === false) {
        const reason = (testResult.reason || '').toLowerCase();
        if (reason.includes('unauthorized') || reason.includes('blocked') || reason.includes('sandbox_unavailable')) {
            return OUTCOME_STATUS.BLOCKED;
        }
        return OUTCOME_STATUS.COULD_NOT_RUN;
    }

    const rawStatus = (testResult.status || '').toString().toUpperCase();
    if (rawStatus === 'NOT EXECUTED') {
        return OUTCOME_STATUS.COULD_NOT_RUN;
    }
    if (rawStatus === 'SANDBOX_UNAVAILABLE') {
        return OUTCOME_STATUS.BLOCKED;
    }
    if (rawStatus === 'CANCELLED' || rawStatus === 'CANCELED') {
        return OUTCOME_STATUS.CANCELLED;
    }
    if (rawStatus === 'TIMED_OUT' || rawStatus === 'TIMED OUT') {
        return OUTCOME_STATUS.TIMED_OUT;
    }
    if (rawStatus === 'BLOCKED') {
        return OUTCOME_STATUS.BLOCKED;
    }
    if (rawStatus === 'UNTESTED') {
        return OUTCOME_STATUS.UNTESTED;
    }

    const failed = Number(testResult.testsFailed ?? testResult.failedTests ?? testResult.failed ?? 0);
    const total = Number(testResult.testsTotal ?? testResult.totalTests ?? testResult.total ?? 0);
    const passedFlag = testResult.passed;

    if (rawStatus === 'FAIL' || rawStatus === 'FAILED' || passedFlag === false || failed > 0 || (typeof testResult.exitCode === 'number' && testResult.exitCode !== 0)) {
        return OUTCOME_STATUS.FAILED;
    }

    if (!opts.allowZeroTests && total <= 0) {
        return OUTCOME_STATUS.UNTESTED;
    }

    if (rawStatus === 'PASS' || rawStatus === 'PASSED' || passedFlag === true) {
        return OUTCOME_STATUS.PASSED;
    }

    return OUTCOME_STATUS.NOT_VERIFIED;
}

/**
 * Evaluates authoritative separated remediation outcomes across all 5 planes.
 * Enforces fail-closed guarantees: incomplete/untested/blocked/unverified checks
 * can NEVER yield Remediated, PASSED validation, or RESOLVED closure.
 *
 * @param {object} params
 * @returns {{
 *   scannerOutcome: string,
 *   testOutcome: string,
 *   workflowOutcome: string,
 *   finalValidationOutcome: string,
 *   closureOutcome: string,
 *   legacyRemediationStatus: string,
 *   legacyFinalValidationStatus: string,
 *   isResolved: boolean,
 *   blockingReasons: string[]
 * }}
 */
function evaluateFinalRemediationOutcome(params = {}) {
    const {
        finding = {},
        postFixValidation = null,
        reScanVerification = null,
        securityReview = null,
        isManualActionRequired = false,
        requiresScannerReScan = false,
        suppressionDetected = false
    } = params;

    const blockingReasons = [];

    // 1. Test Execution Outcome
    const allowZeroTests = isManualActionRequired === true;
    const testOutcome = classifyTestOutcome(postFixValidation, { allowZeroTests });
    if (!allowZeroTests && testOutcome !== OUTCOME_STATUS.PASSED) {
        blockingReasons.push(`Post-fix validation test outcome is ${testOutcome}, not ${OUTCOME_STATUS.PASSED}.`);
    }

    // 2. Scanner Verification Outcome
    let scannerOutcome = OUTCOME_STATUS.NOT_VERIFIED;
    const origin = resolveOriginatingScannerId(finding);
    const hasScannerExpectation = requiresScannerReScan || origin.rawScannerId !== null || finding.Source_Type === 'SCANNER';

    if (reScanVerification) {
        scannerOutcome = normalizeMachineOutcome(reScanVerification.machineStatus || reScanVerification.status);
        if (scannerOutcome !== OUTCOME_STATUS.RESOLVED) {
            blockingReasons.push(`Scanner re-scan verification outcome is ${scannerOutcome}.`);
        }
    } else if (hasScannerExpectation) {
        scannerOutcome = OUTCOME_STATUS.NOT_VERIFIED;
        blockingReasons.push('Originating scanner re-scan was not executed for a scanner-sourced finding.');
    }

    // 3. Suppression or Security Review Outcome
    if (suppressionDetected) {
        blockingReasons.push('Security diagnostic suppression directives detected in proposed change.');
    }

    const rawReviewRating = (securityReview && securityReview.rating ? securityReview.rating : '').toString().toUpperCase();
    let finalValidationOutcome = OUTCOME_STATUS.NOT_VERIFIED;

    if (suppressionDetected ||
        rawReviewRating === 'FAIL' ||
        rawReviewRating === 'FAILED' ||
        testOutcome === OUTCOME_STATUS.FAILED ||
        scannerOutcome === OUTCOME_STATUS.STILL_PRESENT ||
        scannerOutcome === OUTCOME_STATUS.REGRESSION_DETECTED) {
        finalValidationOutcome = OUTCOME_STATUS.FAILED;
        if (rawReviewRating === 'FAIL') {
            blockingReasons.push('Independent security review rated FAIL.');
        }
    } else if (isManualActionRequired || rawReviewRating === 'NEEDS_HUMAN_REVIEW' || rawReviewRating === 'BLOCKED' || testOutcome === OUTCOME_STATUS.BLOCKED) {
        finalValidationOutcome = OUTCOME_STATUS.BLOCKED;
        blockingReasons.push(testOutcome === OUTCOME_STATUS.BLOCKED
            ? 'Test/build execution was blocked by security or sandbox availability policy.'
            : 'Finding requires manual remediation / governance review; cannot auto-resolve.');
    } else if (testOutcome === OUTCOME_STATUS.CANCELLED || testOutcome === OUTCOME_STATUS.TIMED_OUT) {
        finalValidationOutcome = testOutcome;
        blockingReasons.push(`Test execution ended in ${testOutcome}; cannot auto-resolve.`);
    } else if (testOutcome !== OUTCOME_STATUS.PASSED) {
        finalValidationOutcome = testOutcome === OUTCOME_STATUS.COULD_NOT_RUN
            ? OUTCOME_STATUS.COULD_NOT_RUN
            : OUTCOME_STATUS.UNTESTED;
    } else if (hasScannerExpectation && scannerOutcome !== OUTCOME_STATUS.RESOLVED) {
        finalValidationOutcome = scannerOutcome === OUTCOME_STATUS.INCONCLUSIVE
            ? OUTCOME_STATUS.INCONCLUSIVE
            : OUTCOME_STATUS.NOT_VERIFIED;
    } else if (rawReviewRating === 'PASS' || rawReviewRating === 'PASSED') {
        finalValidationOutcome = OUTCOME_STATUS.PASSED;
    } else if (rawReviewRating === 'PARTIAL') {
        finalValidationOutcome = OUTCOME_STATUS.PARTIAL;
        blockingReasons.push('Security review rating is PARTIAL; partial validation cannot certify remediation.');
    } else {
        finalValidationOutcome = OUTCOME_STATUS.NOT_VERIFIED;
        blockingReasons.push('Security review did not produce PASS.');
    }

    // 4. Workflow & Closure Separation
    // Formal vulnerability closure NEVER occurs in automated local remediation tools.
    const isResolved =
        finalValidationOutcome === OUTCOME_STATUS.PASSED &&
        testOutcome === OUTCOME_STATUS.PASSED &&
        (!hasScannerExpectation || scannerOutcome === OUTCOME_STATUS.RESOLVED) &&
        !suppressionDetected &&
        !isManualActionRequired;

    const workflowOutcome = isResolved
        ? 'VerifiedLocally_PendingPR'
        : (finalValidationOutcome === OUTCOME_STATUS.BLOCKED ? OUTCOME_STATUS.BLOCKED : OUTCOME_STATUS.FAILED);

    const legacyRemediationStatus = isResolved
        ? 'Remediated'
        : (finalValidationOutcome === OUTCOME_STATUS.BLOCKED
            ? 'Blocked - Manual Review Required'
            : (testOutcome === OUTCOME_STATUS.COULD_NOT_RUN || testOutcome === OUTCOME_STATUS.UNTESTED
                ? 'Validation Incomplete'
                : 'Validation Failed'));

    let legacyFinalValidationStatus = finalValidationOutcome;
    if (finalValidationOutcome === OUTCOME_STATUS.PASSED) legacyFinalValidationStatus = 'PASS';
    else if (finalValidationOutcome === OUTCOME_STATUS.FAILED) legacyFinalValidationStatus = 'FAIL';
    else if (finalValidationOutcome === OUTCOME_STATUS.UNTESTED) legacyFinalValidationStatus = 'NOT EXECUTED';

    return {
        scannerOutcome,
        testOutcome,
        workflowOutcome,
        finalValidationOutcome,
        closureOutcome: CLOSURE_STATUS.PENDING_FORMAL_CLOSURE,
        legacyRemediationStatus,
        legacyFinalValidationStatus,
        isResolved,
        blockingReasons
    };
}

module.exports = {
    OUTCOME_STATUS,
    LEGACY_VERIFICATION_DISPLAY,
    CLOSURE_STATUS,
    APPROVED_SCANNER_IDS,
    SCANNER_ALIAS_MAP,
    normalizeMachineOutcome,
    toLegacyVerificationDisplay,
    toLegacyCsvTestDisplay,
    resolveOriginatingScannerId,
    classifyTestOutcome,
    evaluateFinalRemediationOutcome
};

