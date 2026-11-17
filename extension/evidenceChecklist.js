'use strict';

const CHECK_STATUS = Object.freeze({
    PASS: 'PASS',
    FAIL: 'FAIL',
    MISSING: 'MISSING',
    NOT_APPLICABLE: 'NOT_APPLICABLE'
});

const REVIEW_RECOMMENDATION = Object.freeze({
    READY_FOR_REVIEW: 'READY_FOR_REVIEW',
    REVIEW_REQUIRED: 'REVIEW_REQUIRED',
    BLOCKED: 'BLOCKED'
});

const SECRET_DETECTION_REGEX = /(secret|credential|api[_\s-]?key|password|passwd|private[_\s-]?key|bearer|token|connection[_\s-]?string|cwe-798|cwe-321|cwe-259|cwe-522|sec-001|sec-002|sec-006)/i;

function isSecretOrCredentialFinding(finding = {}, classification = {}) {
    const cweText = String(classification?.cwe || finding.CVE_ID || finding.cveId || '').toUpperCase();
    const ruleText = String(finding.Rule_ID || finding.ruleId || '').toUpperCase();
    const titleText = String(finding.Title || finding.title || finding.Detailed_Name || finding.detailedName || '');

    // Pure SQL injection, OS command injection, risky crypto, XSS, or path traversal findings
    // must never produce credential rotation or secret revocation requirements.
    const nonSecretCwes = /CWE-89|CWE-78|CWE-327|CWE-328|CWE-22|CWE-79\b/;
    if (nonSecretCwes.test(cweText) || /^SEC-00[345]$/.test(ruleText) || /SQL Injection|Command Injection|Cryptographic/i.test(titleText)) {
        return false;
    }

    const tokens = [
        ruleText,
        titleText,
        finding.Detailed_Name,
        finding.detailedName,
        finding.Source_Classification,
        cweText,
        classification?.summary
    ].filter(Boolean).join(' ');
    return SECRET_DETECTION_REGEX.test(tokens);
}

function buildSecretRemediationActions(finding = {}) {
    const fileLoc = finding.Location_Path || finding.filePath || 'affected configuration/source file';
    return [
        {
            id: 'REVOKE_SECRET',
            action: 'Revoke exposed credential immediately at the issuing provider or identity system.',
            target: finding.Vulnerability_ID || 'Finding credential'
        },
        {
            id: 'ROTATE_SECRET',
            action: 'Generate a replacement secret and provision it in the target runtime environment.',
            target: fileLoc
        },
        {
            id: 'EXTERNALIZE_SECRET',
            action: 'Verify application code loads the credential strictly from an approved secret manager or environment variable (no hardcoded fallback).',
            target: fileLoc
        },
        {
            id: 'INVALIDATE_EXPOSED_HISTORY',
            action: 'Confirm the prior value in Git commit history and historical logs is invalidated and cannot be replayed.',
            target: 'Repository Git history & telemetry logs'
        }
    ];
}

function detectSecretManagerExternalization(patchDiff = '', sourceCode = '') {
    const addedLines = String(patchDiff || '')
        .split('\n')
        .filter(l => l.startsWith('+') && !l.startsWith('+++'))
        .join('\n');
    if (!addedLines.trim()) {
        return { verified: false, reason: 'No code diff available to verify secret externalization.' };
    }
    const usesSecretStore = /Environment\.GetEnvironmentVariable|IConfiguration|Configuration\[|GetConnectionString|SecretClient|SecretsManager|process\.env\.|System\.getenv|KeyVault|user-secrets|__SET_VIA_/i.test(addedLines);
    const reintroducesLiteral = /(["'])[A-Za-z0-9_\/+=-]{12,}\1/.test(addedLines) &&
        !/(placeholder|example|replace|configure|env)/i.test(addedLines);
    if (reintroducesLiteral && !usesSecretStore) {
        return { verified: false, reason: 'Added diff lines may still contain a literal value without secret-manager / env lookup.' };
    }
    if (usesSecretStore) {
        return { verified: true, reason: 'Patch externalizes credential retrieval to configuration / environment / secret store.' };
    }
    return { verified: false, reason: 'Diff removed secret pattern cleanly, but explicit secret-manager / env injection could not be verified automatically.' };
}

/**
 * Computes a deterministic, evidence-based reviewer verification checklist.
 * Eliminates arbitrary numeric confidence scores in favor of explicit PASS / FAIL / MISSING / NOT_APPLICABLE checks.
 */
function buildEvidenceChecklist(params = {}) {
    const {
        finding = {},
        classification = null,
        rca = null,
        sourceToSinkEvidence = null,
        baselineValidation = null,
        patchDiff = '',
        proposedDiffSha256 = null,
        approvalRecord = null,
        scopeVerification = null,
        validation = null,
        reScanVerification = null,
        requiresScannerReScan = false,
        securityReview = null,
        outcomeEvaluation = null,
        integrityVerification = null,
        suppressionDetected = false,
        secretRemediation = null
    } = params;

    const isSecretFinding = isSecretOrCredentialFinding(finding, classification);
    const checks = [];

    // 1. Root Cause Analysis
    const hasRca = Boolean(rca && (rca.rootCause || rca.summary));
    checks.push({
        id: 'ROOT_CAUSE_ANALYSIS',
        label: 'Root cause analysis documented',
        status: hasRca ? CHECK_STATUS.PASS : CHECK_STATUS.MISSING,
        required: true,
        detail: hasRca ? (rca.summary || rca.rootCause) : 'No structured RCA artifact recorded.'
    });

    // 2. Source-to-sink / exploit flow evidence
    const hasS2S = Boolean(sourceToSinkEvidence && (sourceToSinkEvidence.untrustedSource || sourceToSinkEvidence.dangerousSink));
    checks.push({
        id: 'SOURCE_TO_SINK_EVIDENCE',
        label: 'Source-to-sink or vulnerability location evidence',
        status: hasS2S ? CHECK_STATUS.PASS : (isSecretFinding ? CHECK_STATUS.NOT_APPLICABLE : CHECK_STATUS.MISSING),
        required: !isSecretFinding,
        detail: hasS2S
            ? `Method: ${sourceToSinkEvidence.analysisMethod || 'Heuristic'} | FormalTaintProof: ${Boolean(sourceToSinkEvidence.formalTaintProofSupplied)}`
            : (isSecretFinding ? 'Not required for static credential exposure finding.' : 'Source-to-sink trace artifact missing.')
    });

    // 3. Baseline reproduction / documented constraint
    let baselineCheckStatus = CHECK_STATUS.MISSING;
    let baselineDetail = 'No baseline execution record present.';
    if (baselineValidation) {
        if (baselineValidation.executed === true && (baselineValidation.passed === true || baselineValidation.testsTotal > 0)) {
            baselineCheckStatus = CHECK_STATUS.PASS;
            baselineDetail = baselineValidation.summary || `Baseline test executed (${baselineValidation.testsTotal} tests).`;
        } else if (baselineValidation.baselineExceptionAuthorized === true) {
            baselineCheckStatus = CHECK_STATUS.PASS;
            baselineDetail = `Baseline exception authorized: ${baselineValidation.baselineExceptionRationale || 'Documented engineering constraint'}`;
        } else if (baselineValidation.status === 'UNTESTED' || baselineValidation.machineStatus === 'UNTESTED') {
            baselineCheckStatus = CHECK_STATUS.FAIL;
            baselineDetail = `UNTESTED: ${baselineValidation.rootError || baselineValidation.reason || 'Zero tests executed without authorized exception'}`;
        } else if (baselineValidation.executed === false) {
            baselineCheckStatus = CHECK_STATUS.FAIL;
            baselineDetail = `Execution blocked: ${baselineValidation.rootError || baselineValidation.reason || 'Baseline execution did not run'}`;
        } else {
            baselineCheckStatus = CHECK_STATUS.PASS;
            baselineDetail = baselineValidation.summary || 'Baseline test executed.';
        }
    }
    checks.push({
        id: 'BASELINE_EVIDENCE',
        label: 'Baseline test reproduction or documented constraint',
        status: baselineCheckStatus,
        required: true,
        detail: baselineDetail
    });

    // 4. Approved code diff & SHA-256 scope integrity
    const hasDiff = Boolean(patchDiff && String(patchDiff).trim().length > 0);
    const hasStage4Approval = Boolean(approvalRecord && approvalRecord.decision === 'APPROVED');
    const diffScopeOk = scopeVerification ? (scopeVerification.passed !== false) : true;
    const integrityTampered = integrityVerification && integrityVerification.status === 'TAMPERING_DETECTED';
    let diffCheckStatus = CHECK_STATUS.MISSING;
    let diffDetail = 'No proposed or approved patch diff present.';
    if (integrityTampered || !diffScopeOk) {
        diffCheckStatus = CHECK_STATUS.FAIL;
        diffDetail = integrityTampered
            ? 'Evidence integrity mismatch detected on persisted artifacts.'
            : 'Post-apply file scope verification failed.';
    } else if (hasDiff && hasStage4Approval) {
        diffCheckStatus = CHECK_STATUS.PASS;
        diffDetail = `Diff SHA-256 ${String(proposedDiffSha256 || approvalRecord?.proposedDiffSha256 || '').slice(0, 12) || 'verified'} authorized & scoped.`;
    } else if (hasDiff) {
        diffCheckStatus = CHECK_STATUS.MISSING;
        diffDetail = 'Diff generated, awaiting Stage 4 diff-bound human authorization.';
    }
    checks.push({
        id: 'CODE_DIFF_INTEGRITY',
        label: 'Approved code diff & scope integrity verified',
        status: diffCheckStatus,
        required: true,
        detail: diffDetail
    });

    // 5. Genuine post-fix build and test execution
    const valTestsTotal = Number(validation?.testsTotal ?? validation?.totalTests ?? ((validation?.testsPassed || 0) + (validation?.testsFailed || 0)));
    const valTestsPassed = Number(validation?.testsPassed ?? 0);
    const valTestsFailed = Number(validation?.testsFailed ?? 0);
    const valMachine = String(validation?.machineStatus || validation?.status || '').toUpperCase();
    const valCat = String(validation?.failureCategory || '').toUpperCase();
    const testsExplicitPass = Boolean(
        validation &&
        validation.executed === true &&
        (validation.passed === true || valMachine === 'PASSED' || valMachine === 'PASS') &&
        valTestsTotal > 0 &&
        valTestsFailed === 0 &&
        (validation.exitCode === 0 || validation.exitCode === undefined)
    );
    const testsExplicitFail = Boolean(
        validation && (
            validation.passed === false ||
            valMachine === 'FAILED' ||
            valMachine === 'FAIL' ||
            valCat === 'BUILD_FAILED' ||
            valCat === 'TESTS_FAILED' ||
            valCat === 'NO_TESTS_DISCOVERED' ||
            valCat === 'EXECUTION_BLOCKED' ||
            valCat === 'TIMED_OUT' ||
            valCat === 'CANCELLED' ||
            (typeof validation.exitCode === 'number' && validation.exitCode !== 0 && validation.executed !== false) ||
            (validation.executed === true && valTestsTotal === 0)
        )
    );

    let testCheckStatus = CHECK_STATUS.MISSING;
    let testCheckDetail = 'Post-fix build/test execution has not completed.';
    if (integrityTampered) {
        testCheckStatus = CHECK_STATUS.FAIL;
        testCheckDetail = 'Validation evidence failed integrity check.';
    } else if (testsExplicitFail) {
        testCheckStatus = CHECK_STATUS.FAIL;
        testCheckDetail = validation.rootError || validation.summary || `Post-fix validation failed (${valCat || valMachine || 'Exit ' + validation.exitCode}).`;
    } else if (validation?.executed === false) {
        testCheckStatus = CHECK_STATUS.MISSING;
        testCheckDetail = validation.rootError || validation.reason || `Could not run validation tests (${valCat || valMachine}).`;
    } else if (testsExplicitPass) {
        testCheckStatus = CHECK_STATUS.PASS;
        testCheckDetail = `Passed ${valTestsPassed}/${valTestsTotal} targeted tests (Exit code 0).`;
    }
    checks.push({
        id: 'POST_FIX_TEST_EXECUTION',
        label: 'Post-fix build & test execution passed (>0 tests)',
        status: testCheckStatus,
        required: true,
        detail: testCheckDetail
    });

    // 6. Originating scanner re-scan
    const reScanMachine = String(reScanVerification?.machineStatus || reScanVerification?.status || '').toUpperCase();
    let reScanStatus = CHECK_STATUS.NOT_APPLICABLE;
    let reScanDetail = 'Originating finding is not mapped to an automated local scanner.';
    if (reScanVerification || requiresScannerReScan) {
        if (reScanMachine === 'RESOLVED') {
            reScanStatus = CHECK_STATUS.PASS;
            reScanDetail = reScanVerification.reason || 'Originating scanner confirmed finding absent.';
        } else if (reScanMachine === 'STILL_PRESENT' || reScanMachine === 'REGRESSION_DETECTED' || reScanMachine === 'FAILED') {
            reScanStatus = CHECK_STATUS.FAIL;
            reScanDetail = reScanVerification?.reason || `Scanner re-scan reported ${reScanMachine}.`;
        } else {
            reScanStatus = CHECK_STATUS.MISSING;
            reScanDetail = reScanVerification?.reason || `Scanner re-scan is ${reScanMachine || 'NOT EXECUTED'}.`;
        }
    }
    checks.push({
        id: 'SCANNER_RESCAN',
        label: 'Originating scanner post-fix re-scan verified',
        status: reScanStatus,
        required: reScanStatus !== CHECK_STATUS.NOT_APPLICABLE,
        detail: reScanDetail
    });

    // 7. Security hygiene & regression verification
    const rawSecRating = String(securityReview?.rating || '').toUpperCase();
    let secCheckStatus = CHECK_STATUS.MISSING;
    let secCheckDetail = 'Independent security & suppression checks have not yet completed.';
    if (suppressionDetected || integrityTampered) {
        secCheckStatus = CHECK_STATUS.FAIL;
        secCheckDetail = suppressionDetected
            ? 'Security diagnostic suppression or test weakening detected.'
            : 'Artifact SHA-256 / hash-chain tampering detected.';
    } else if (testCheckStatus === CHECK_STATUS.FAIL || reScanStatus === CHECK_STATUS.FAIL) {
        secCheckStatus = CHECK_STATUS.FAIL;
        secCheckDetail = 'Validation or re-scan check failed; cannot confirm security closure.';
    } else if (rawSecRating === 'PASS' && testCheckStatus === CHECK_STATUS.PASS && reScanStatus !== CHECK_STATUS.FAIL && reScanStatus !== CHECK_STATUS.MISSING) {
        secCheckStatus = CHECK_STATUS.PASS;
        secCheckDetail = securityReview?.summary || 'Security hygiene, suppression, and regression checks passed.';
    } else if (rawSecRating === 'FAIL') {
        secCheckStatus = CHECK_STATUS.FAIL;
        secCheckDetail = securityReview?.summary || 'Security audit checks reported FAIL.';
    }
    checks.push({
        id: 'INDEPENDENT_SECURITY_CHECKS',
        label: 'Security suppression & regression validation passed',
        status: secCheckStatus,
        required: true,
        detail: secCheckDetail
    });

    // 8. Secret-specific operational & rotation controls (applicable ONLY to secret/credential findings)
    const secretActions = isSecretFinding ? buildSecretRemediationActions(finding) : [];
    const extCheck = isSecretFinding ? detectSecretManagerExternalization(patchDiff) : null;
    if (isSecretFinding) {
        checks.push({
            id: 'SECRET_MANAGER_REPLACEMENT',
            label: 'Code externalizes credential to env / secret manager',
            status: extCheck.verified ? CHECK_STATUS.PASS : CHECK_STATUS.MISSING,
            required: true,
            detail: extCheck.reason
        });
        checks.push({
            id: 'SECRET_REVOCATION_CONFIRMED',
            label: 'Manual credential revocation confirmed by operator',
            status: secretRemediation?.revokedConfirmed === true ? CHECK_STATUS.PASS : CHECK_STATUS.MISSING,
            required: true,
            detail: secretRemediation?.revokedConfirmed === true
                ? 'Operator recorded credential revocation.'
                : 'Required manual action: Revoke exposed secret at issuing provider.'
        });
        checks.push({
            id: 'SECRET_ROTATION_CONFIRMED',
            label: 'Manual credential rotation confirmed by operator',
            status: secretRemediation?.rotatedConfirmed === true ? CHECK_STATUS.PASS : CHECK_STATUS.MISSING,
            required: true,
            detail: secretRemediation?.rotatedConfirmed === true
                ? 'Operator recorded credential rotation.'
                : 'Required manual action: Issue new rotated credential and store securely.'
        });
        checks.push({
            id: 'EXPOSED_CREDENTIAL_INVALIDATED',
            label: 'Exposed secret invalidated across Git history/logs',
            status: secretRemediation?.gitHistoryInvalidationConfirmed === true ? CHECK_STATUS.PASS : CHECK_STATUS.MISSING,
            required: true,
            detail: secretRemediation?.gitHistoryInvalidationConfirmed === true
                ? 'Operator confirmed exposed credential cannot be replayed.'
                : 'Required manual action: Verify prior value in commits/logs is invalidated.'
        });
    } else {
        checks.push(
            { id: 'SECRET_MANAGER_REPLACEMENT', label: 'Secret-manager externalization check', status: CHECK_STATUS.NOT_APPLICABLE, required: false, detail: 'Not applicable (non-credential finding).' },
            { id: 'SECRET_REVOCATION_CONFIRMED', label: 'Credential revocation check', status: CHECK_STATUS.NOT_APPLICABLE, required: false, detail: 'Not applicable (non-credential finding).' },
            { id: 'SECRET_ROTATION_CONFIRMED', label: 'Credential rotation check', status: CHECK_STATUS.NOT_APPLICABLE, required: false, detail: 'Not applicable (non-credential finding).' },
            { id: 'EXPOSED_CREDENTIAL_INVALIDATED', label: 'Exposed credential invalidation check', status: CHECK_STATUS.NOT_APPLICABLE, required: false, detail: 'Not applicable (non-credential finding).' }
        );
    }

    const applicableChecks = checks.filter(c => c.status !== CHECK_STATUS.NOT_APPLICABLE);
    const passedChecks = applicableChecks.filter(c => c.status === CHECK_STATUS.PASS);
    const failedChecks = applicableChecks.filter(c => c.status === CHECK_STATUS.FAIL);
    const missingChecks = applicableChecks.filter(c => c.status === CHECK_STATUS.MISSING);

    const passedCount = passedChecks.length;
    const failedCount = failedChecks.length;
    const missingCount = missingChecks.length;
    const totalApplicable = applicableChecks.length;
    const notApplicableCount = checks.length - totalApplicable;
    const completionSummary = `${passedCount} of ${totalApplicable} required checks complete`;

    let recommendation = REVIEW_RECOMMENDATION.READY_FOR_REVIEW;
    let finalReviewStatus = 'READY FOR REVIEW — All required checks verified';
    let finalSignOffAllowed = true;

    const outcomeBlocked = outcomeEvaluation && outcomeEvaluation.isResolved === false;
    if (failedCount > 0 || outcomeBlocked || testCheckStatus === CHECK_STATUS.FAIL || reScanStatus === CHECK_STATUS.FAIL) {
        recommendation = REVIEW_RECOMMENDATION.BLOCKED;
        finalSignOffAllowed = false;
        if (testCheckStatus === CHECK_STATUS.FAIL || reScanStatus === CHECK_STATUS.FAIL) {
            finalReviewStatus = 'BLOCKED — Post-fix validation failed';
        } else if (integrityTampered) {
            finalReviewStatus = 'BLOCKED — Evidence integrity mismatch detected';
        } else if (suppressionDetected) {
            finalReviewStatus = 'BLOCKED — Diagnostic suppression detected';
        } else {
            finalReviewStatus = 'BLOCKED — Required validation incomplete or failed';
        }
    } else if (missingCount > 0) {
        recommendation = REVIEW_RECOMMENDATION.REVIEW_REQUIRED;
        finalReviewStatus = isSecretFinding
            ? 'REVIEW REQUIRED — Secret revocation & rotation confirmation required'
            : 'REVIEW REQUIRED — Incomplete verification evidence';
        // Automated Stage 8 code sign-off only unlocked if outcomeEvaluation passed cleanly and code checks passed;
        // still clearly flagged as REVIEW REQUIRED when manual checks (such as secret rotation) remain pending.
        finalSignOffAllowed = Boolean(testCheckStatus === CHECK_STATUS.PASS && diffCheckStatus === CHECK_STATUS.PASS);
    }

    return {
        schemaVersion: 'GCAC-EVIDENCE-CHECKLIST-1.0',
        isSecretFinding,
        recommendation,
        finalReviewStatus,
        finalSignOffAllowed,
        completionSummary,
        passedCount,
        failedCount,
        missingCount,
        notApplicableCount,
        totalApplicable,
        passedCheckIds: passedChecks.map(c => c.id),
        failedCheckIds: failedChecks.map(c => c.id),
        missingCheckIds: missingChecks.map(c => c.id),
        secretRemediationActions: secretActions,
        checks
    };
}

module.exports = {
    CHECK_STATUS,
    REVIEW_RECOMMENDATION,
    isSecretOrCredentialFinding,
    buildSecretRemediationActions,
    detectSecretManagerExternalization,
    buildEvidenceChecklist
};

