'use strict';

const { CANONICAL_STAGES } = require('./runStateContract');
const { COPILOT_APPROVAL_LIMITATION_DISCLOSURE } = require('./approvalGovernance');

const EMOJI_AND_DECORATIVE_REGEX = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\uFE0F]/gu;

function stripDecorativeSymbols(text = '') {
    return String(text ?? '')
        .replace(EMOJI_AND_DECORATIVE_REGEX, '')
        .replace(/[ \t]{2,}/g, ' ')
        .trim();
}

function getStageDisplayName(stageNumber, stageId) {
    const found = CANONICAL_STAGES.find(
        s => s.stageNumber === Number(stageNumber) || (stageId && s.id === stageId)
    );
    return found ? `Stage ${found.stageNumber} (${found.label})` : `Stage ${stageNumber || '?'} (${stageId || 'context'})`;
}

function formatHelpMarkdown() {
    return [
        '### GCAC Vulnerability Orchestrator',
        '',
        'Enterprise vulnerability remediation workflow controller.',
        '',
        '**Available Commands:**',
        '- `@vulnerability-orchestrator /remediate-vulnerability <ID>` — Execute Stage 1 through Stage 3 and pause at Stage 4 Human Approval Gate.',
        '- `@vulnerability-orchestrator /approve <ID>` — Authorize Stage 4 diff-bound patch, apply inside isolated worktree (Stage 5), and run Stage 6/7 verification.',
        '- `@vulnerability-orchestrator /final-approve <ID>` — Record final Stage 8 sign-off and conclude Stage 9 evidence closure (prohibited if validation failed).',
        '',
        '**Usage Example:**',
        '- `@vulnerability-orchestrator /remediate-vulnerability SCAN-SECRET-005`',
        ''
    ].join('\n');
}

function formatRunHeaderMarkdown(vulnId, runModeDesc) {
    return [
        `### GCAC Orchestrator: \`${stripDecorativeSymbols(vulnId)}\``,
        `- **Requested Operation**: ${stripDecorativeSymbols(runModeDesc)}`,
        ''
    ].join('\n') + '\n';
}

function formatStageEventMarkdown(evt) {
    if (!evt || typeof evt !== 'object') return '';
    const stageLabel = getStageDisplayName(evt.stageNumber, evt.stageId);
    const summary = evt.summary ? stripDecorativeSymbols(evt.summary) : '';

    if (evt.type === 'STAGE_START') {
        return `- **${stageLabel}** — ACTIVE\n`;
    }
    if (evt.type === 'STAGE_COMPLETE') {
        return `- **${stageLabel}** — COMPLETED${summary ? `: ${summary}` : ''}\n`;
    }
    if (evt.type === 'STAGE_FAILED') {
        const cat = evt.failureCategory ? ` [${evt.failureCategory}]` : '';
        return `- **${stageLabel}** — FAILED${cat}${summary ? `: ${summary}` : ''}\n`;
    }
    if (evt.type === 'STAGE_BLOCKED' || evt.type === 'FINAL_GATE_BLOCKED') {
        return `- **${stageLabel}** — BLOCKED${summary ? `: ${summary}` : ''}\n`;
    }
    return '';
}

function formatGateMarkdown(vulnId, result) {
    if (result.workflowLifecycle === 'BLOCKED' || result.status === 'BLOCKED' || result.isBlocked) {
        return formatTerminalConclusionMarkdown(vulnId, result);
    }

    if (result.isAwaitingApproval) {
        const lines = [
            '',
            '---',
            result.executionMode === 'LOCAL_DEVELOPMENT' ? '### LOCAL_DEVELOPMENT — Exact-Diff Developer Consent Required' : '### Gate 4 — Human Approval Required',
            `- **Finding ID**: \`${vulnId}\``,
            '- **Workflow Status**: `AWAITING APPROVAL`',
            `- **Baseline Validation**: \`${stripDecorativeSymbols(result.baselineValidation ? result.baselineValidation.status : 'NOT EXECUTED')}\``,
            result.proposedDiffSha256 ? `- **Proposed Diff SHA-256**: \`${result.proposedDiffSha256}\`` : null,
            '- **Identity Status**: `AUTHENTICATION_NOT_VERIFIED` (Local IDE Mode)',
            `- **Control Boundary**: ${stripDecorativeSymbols(COPILOT_APPROVAL_LIMITATION_DISCLOSURE)}`,
            '',
            '**Proposed Diff:**',
            '```diff',
            String(result.patchDiff || '').trim(),
            '```',
            '',
            '**Required Action:**',
            `- Authorize in Copilot Chat: \`@vulnerability-orchestrator /approve ${vulnId}\``,
            '- Or review and authorize via Stage 4 Human Approval Gate in the GCAC Remediation Hub.'
        ].filter(l => l !== null);
        return lines.join('\n') + '\n';
    }

    if (result.isAwaitingFinalApproval && !result.finalGateBlocked) {
        const checklist = result.evidenceChecklist || result.securityReview?.evidenceChecklist || null;
        const lines = [
            '',
            '---',
            '### Gate 8 — Final Human Sign-Off Required',
            `- **Finding ID**: \`${vulnId}\``,
            '- **Workflow Status**: `AWAITING APPROVAL`',
            `- **Post-Fix Validation Outcome**: \`${result.securityValidationOutcome || (result.validation ? (result.validation.outcome || result.validation.status) : 'NOT VERIFIED')}\``,
            `- **Security Review Status**: \`${checklist?.finalReviewStatus || result.securityReview?.rating || 'NOT VERIFIED'}\``,
            result.publicationPlan?.status === 'READY'
                ? `- **Final approval publication**: Create a draft PR in \`${result.publicationPlan.owner}/${result.publicationPlan.repository}\`, targeting \`${result.publicationPlan.baseBranch}\`. No merge is performed.`
                : `- **GitHub publication**: ${stripDecorativeSymbols(result.publicationPlan?.reason || 'Not configured. Final approval records local evidence only; no PR will be created.')}`,
            checklist ? `- **Evidence Completeness**: ${checklist.completionSummary} (Failed: ${checklist.failedCount}, Missing: ${checklist.missingCount})` : null
        ].filter(l => l !== null);

        if (checklist?.isSecretFinding && Array.isArray(checklist.secretRemediationActions) && checklist.secretRemediationActions.length > 0) {
            lines.push('- **Secret Remediation Manual Controls Required Before Operational Closure**:');
            for (const act of checklist.secretRemediationActions) {
                lines.push(`  - \`${act.id}\`: ${act.action}`);
            }
        }

        lines.push(
            '',
            '**Required Action:**',
            `- Sign off in Copilot Chat: \`@vulnerability-orchestrator /final-approve ${vulnId}\``,
            '- Or complete Final Sign-off in the GCAC Remediation Hub.'
        );
        return lines.join('\n') + '\n';
    }

    return '';
}

function formatTerminalConclusionMarkdown(vulnId, result) {
    if (result.isManualReview || result.status === 'MANUAL_REVIEW') {
        return `\n### Manual Architectural / Security Review Required
- **Finding ID**: \`${vulnId}\`
- **Workflow Lifecycle**: \`BLOCKED\`
- **Reason**: ${stripDecorativeSymbols(result.remediationDecision?.blockingReason || result.failureReason || 'No safe automated remediation strategy is available.')}
- **Baseline / Post-Fix Tests**: \`NOT_EXECUTED\`
- **Re-Scan**: \`NOT_VERIFIED\`
- **Stage 4 Approval**: Unavailable — this is an architectural-review referral, not a code proposal awaiting approval.
- **Next Required Action**: Prepare a reviewed migration plan before proposing code changes. Final remediation sign-off remains blocked.
${(result.remediationDecision?.manualReviewPlan || []).map((step, i) => `${i + 1}. ${stripDecorativeSymbols(step)}`).join('\n')}
`;
    }
    if (result.executionMode === 'LOCAL_DEVELOPMENT' && result.localOutcome) {
        return `### LOCAL_DEVELOPMENT — ${result.localOutcome}
- **Finding ID**: ${vulnId}
- **Run ID**: ${result.runId}
- **Baseline**: ${result.baselineValidation?.machineStatus || 'NOT_EXECUTED'}${result.baselineValidation?.baselineExceptionAuthorized ? ' (development exception acknowledged; baseline did not pass)' : ''}
- **Tests**: ${result.validation?.machineStatus || result.postFixValidation?.machineStatus || 'NOT_EXECUTED'}
- **Test counts**: ${result.validation?.testsTotal ?? result.postFixValidation?.testsTotal ?? 0} total; ${result.validation?.testsFailed ?? result.postFixValidation?.testsFailed ?? 0} failed
- **Approval**: ${result.approvalRecord?.approvalMode || result.approvalDecision || 'NOT_REQUESTED'}
- **Re-scan**: ${result.reScanVerification?.machineStatus || 'NOT_VERIFIED'}
- **Verified remediation**: ${result.verifiedRemediation === true}
- **Stage 8**: DEFERRED_IN_DEV_MODE
- **Formal closure**: DEFERRED_IN_DEV_MODE
${(result.stages || []).map(stage => `- Stage ${stage.stageNumber}: ${stage.status}`).join('\n')}
${(result.verificationLimitations || []).join('\n')}
${result.failureReason || ''}
`;
    }

    const checklist = result.evidenceChecklist || result.securityReview?.evidenceChecklist || null;

    if (result.failureCategory === 'TOOLCHAIN_IMAGE_UNAVAILABLE') {
        const diagSummary = stripDecorativeSymbols(
            result.failureReason || 'Toolchain image unavailable or unprovisioned.'
        );
        const remGuidance = result.diagnosticGuidance?.remediation
            ? stripDecorativeSymbols(result.diagnosticGuidance.remediation)
            : 'Provision verified local container image matching repository toolchain.';
        const lines = [
            '',
            '---',
            '### Workflow Blocked — Toolchain Image Unavailable',
            `- **Finding ID**: \`${vulnId}\``,
            `- **Workflow Status**: \`${result.workflowLifecycle || 'BLOCKED'}\``,
            `- **Stage 3 Baseline Outcome**: \`${result.baselineOutcome || 'COULD_NOT_RUN'}\``,
            `- **Post-Fix Validation**: \`${result.securityValidationOutcome || 'NOT_EXECUTED'}\``,
            `- **Failure Category**: \`${result.failureCategory || 'TOOLCHAIN_IMAGE_UNAVAILABLE'}\``,
            '- **Stage 4 Review**: `BLOCKED_BY_PREREQUISITE`',
            '- **Stages 5–9**: `NOT_STARTED`',
            `- **Diagnostics**: ${diagSummary}`,
            `- **Remediation**: ${remGuidance}`,
            '- **Retry Status**: `DISABLED` — Prerequisites not satisfied (Provision required toolchain before retry)'
        ];
        return lines.join('\n') + '\n';
    }

    if (result.workflowLifecycle === 'BLOCKED' || result.status === 'BLOCKED') {
        return `\n### Workflow Blocked — Prerequisites Not Satisfied
- **Finding ID**: \`${vulnId}\`
- **Failure Category**: \`${result.failureCategory || 'PREREQUISITE_BLOCKED'}\`
- **Diagnostics**: ${stripDecorativeSymbols(result.failureReason || 'Required execution prerequisites are unavailable.')}
- **Post-Fix Validation**: \`${result.securityValidationOutcome || 'NOT_EXECUTED'}\`
- **Next Required Action**: Resolve the reported prerequisite before retrying.
`;
    }

    if (result.finalGateBlocked || (!result.isCompleted && !result.isAwaitingApproval && !result.isAwaitingFinalApproval)) {
        const val = result.validation || {};
        const diagSummary = stripDecorativeSymbols(
            val.rootError || val.summary || result.failureReason || 'Post-fix validation did not pass.'
        );
        const testCountsStr = val.countsKnown
            ? `Passed: ${val.testsPassed ?? 0}, Failed: ${val.testsFailed ?? 0}, Total: ${val.testsTotal ?? 0}`
            : 'NOT AVAILABLE';
        const nextAction = result.retryEligibility?.canReviseFix
            ? 'Review Failure / Revise Fix in the GCAC Remediation Hub (generates revised patch and enforces fresh Stage 4 review).'
            : (result.retryEligibility?.retryEligible
                ? `Retry Stage ${result.failedStage || 6} in the GCAC Remediation Hub after resolving transient condition.`
                : 'Inspect diagnostics and remediate root cause before re-running validation.');

        const lines = [
            '',
            '---',
            '### Workflow Ended — Validation Failed',
            `- **Finding ID**: \`${vulnId}\``,
            `- **Workflow Lifecycle**: \`${result.workflowLifecycle || 'COMPLETED'}\``,
            `- **Baseline Outcome**: \`${result.baselineOutcome || result.baselineValidation?.status || 'NOT AVAILABLE'}\``,
            `- **Post-Fix Test Outcome**: \`${result.securityValidationOutcome || val.status || 'FAILED'}\``,
            `- **Actual Test Counts**: ${testCountsStr}`,
            `- **Re-Scan Status**: \`${result.reScanVerification?.status || result.reScanVerification?.machineStatus || 'NOT VERIFIED'}\``,
            `- **Final Human-Review Eligibility**: \`${checklist?.finalSignOffAllowed ? 'ELIGIBLE' : 'BLOCKED'}\``,
            `- **Failure Category**: \`${result.failureCategory || val.failureCategory || 'VALIDATION_FAILED'}\``,
            checklist ? `- **Evidence Completeness**: ${checklist.completionSummary} (Failed: ${checklist.failedCount}, Missing: ${checklist.missingCount})` : null,
            `- **Diagnostic Reason**: ${diagSummary}`,
            `- **Next Required Action**: ${nextAction}`
        ].filter(l => l !== null);

        if (checklist?.isSecretFinding && Array.isArray(checklist.secretRemediationActions) && checklist.secretRemediationActions.length > 0) {
            lines.push('- **Manual Secret Controls Still Required**:');
            for (const act of checklist.secretRemediationActions) {
                lines.push(`  - \`${act.id}\`: ${act.action}`);
            }
        }
        return lines.join('\n') + '\n';
    }

    if (result.isCompleted) {
        const val = result.validation || {};
        const testCountsStr = val.countsKnown
            ? `Passed: ${val.testsPassed ?? 0}, Failed: ${val.testsFailed ?? 0}, Total: ${val.testsTotal ?? 0}`
            : 'NOT AVAILABLE';
        const lines = [
            '',
            '---',
            '### Workflow Concluded — Verified and Signed Off',
            `- **Finding ID**: \`${vulnId}\``,
            `- **Workflow Lifecycle**: \`${result.workflowLifecycle || 'COMPLETED'}\``,
            `- **Baseline Outcome**: \`${result.baselineOutcome || result.baselineValidation?.status || 'PASS'}\``,
            `- **Post-Fix Test Outcome**: \`${result.securityValidationOutcome || val.status || 'PASS'}\``,
            `- **Actual Test Counts**: ${testCountsStr}`,
            `- **Re-Scan Status**: \`${result.reScanVerification?.status || result.reScanVerification?.machineStatus || 'RESOLVED'}\``,
            `- **Final Human-Review Eligibility**: \`${checklist?.finalSignOffAllowed ? 'ELIGIBLE' : 'BLOCKED'}\``,
            checklist ? `- **Evidence Completeness**: ${checklist.completionSummary}` : null,
            `- **Report Artifact**: \`${stripDecorativeSymbols(result.reportPath || 'N/A')}\``,
            `- **Recorded Status**: \`${stripDecorativeSymbols(result.status || 'Completed')}\``,
            result.publicationResult?.status === 'CREATED'
                ? `- **GitHub draft pull request**: [Review PR #${result.publicationResult.number}](${result.publicationResult.url})`
                : `- **GitHub pull request**: Not created — ${stripDecorativeSymbols(result.publicationResult?.reason || 'No reviewed publication plan was configured.')}`,
            '- **Next Step**: Hand off verified local changes to Application Team CI/CD verification outside agent boundary.'
        ].filter(l => l !== null);

        if (checklist?.isSecretFinding && Array.isArray(checklist.secretRemediationActions) && checklist.secretRemediationActions.length > 0) {
            lines.push('- **Manual Secret Controls Checklist**:');
            for (const act of checklist.secretRemediationActions) {
                lines.push(`  - \`${act.id}\`: ${act.action}`);
            }
        }
        return lines.join('\n') + '\n';
    }

    return '';
}

function formatErrorMarkdown(title, message) {
    return `\n\n**${stripDecorativeSymbols(title)}**: ${stripDecorativeSymbols(message)}\n`;
}

module.exports = {
    EMOJI_AND_DECORATIVE_REGEX,
    stripDecorativeSymbols,
    getStageDisplayName,
    formatHelpMarkdown,
    formatRunHeaderMarkdown,
    formatStageEventMarkdown,
    formatGateMarkdown,
    formatTerminalConclusionMarkdown,
    formatErrorMarkdown
};

