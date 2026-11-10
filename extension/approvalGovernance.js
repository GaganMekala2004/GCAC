'use strict';

const crypto = require('crypto');

const APPROVAL_SCHEMA_VERSION = 'GCAC-PH2-APPROVAL-1.0';
const APPROVAL_POLICY_VERSION = 'GCAC-PH2-GOV-1.0';
const DEFAULT_APPROVAL_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const AUTH_STATUS = Object.freeze({
    AUTHENTICATION_NOT_VERIFIED: 'AUTHENTICATION_NOT_VERIFIED',
    VERIFIED_INDEPENDENT_REVIEWER: 'VERIFIED_INDEPENDENT_REVIEWER'
});

const APPROVAL_MODE = Object.freeze({
    LOCAL_POC_APPROVAL: 'LOCAL_POC_APPROVAL',
    ENTERPRISE_VERIFIED_APPROVAL: 'ENTERPRISE_VERIFIED_APPROVAL'
});

const COPILOT_APPROVAL_LIMITATION_DISCLOSURE =
    'VS Code Extension Host cannot intercept or pre-authorize native GitHub Copilot Chat agent file-edit tool calls. ' +
    'Diff-bound approval is strictly enforced on the extension-controlled edit path; native Copilot Chat edits should be restricted to proposal/review mode or an isolated runner before production mutation.';

class ApprovalBlockedError extends Error {
    constructor(reason, code = 'APPROVAL_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'ApprovalBlockedError';
        this.code = code;
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

/**
 * Abstract interface for human approval identity & authorization providers.
 */
class ApprovalProvider {
    verifyIdentityAndAuthority(_decisionInput, _pendingRequest) {
        throw new Error('ApprovalProvider.verifyIdentityAndAuthority() must be implemented by subclass.');
    }
}

/**
 * Local PoC developer approval provider.
 * Explicitly records AUTHENTICATION_NOT_VERIFIED and never pretends a local
 * username or local JSON digest is an authenticated non-self enterprise signature.
 */
class LocalPoCApprovalProvider extends ApprovalProvider {
    constructor(options = {}) {
        super();
        this.requireAuthenticatedApproval = options.requireAuthenticatedApproval === true;
    }

    verifyIdentityAndAuthority(decisionInput = {}, _pendingRequest = {}) {
        if (this.requireAuthenticatedApproval) {
            throw new ApprovalBlockedError(
                'Authenticated enterprise identity provider is required for this execution path; local PoC approval failed closed (AUTHENTICATION_NOT_VERIFIED).',
                'AUTHENTICATION_NOT_VERIFIED'
            );
        }

        // Local entered username is NOT authenticated identity — do not treat it as verified claim
        return {
            approvalMode: APPROVAL_MODE.LOCAL_POC_APPROVAL,
            reviewerIdentityClaim: null,
            reviewerAuthorizationStatus: AUTH_STATUS.AUTHENTICATION_NOT_VERIFIED,
            signatureNotice: 'LOCAL_UNAUTHENTICATED_DIGEST_ONLY',
            claimedDisplayHint: decisionInput.localHint ? String(decisionInput.localHint).slice(0, 64) : 'local-ide-developer'
        };
    }
}

/**
 * Interface adapter for future/enterprise identity-verified non-self approval.
 */
class EnterpriseIdentityApprovalProvider extends ApprovalProvider {
    constructor(verifyTokenFn) {
        super();
        if (typeof verifyTokenFn !== 'function') {
            throw new ApprovalBlockedError('Trusted identity token verifier function is missing.', 'NO_TRUSTED_PROVIDER');
        }
        this.verifyTokenFn = verifyTokenFn;
    }

    verifyIdentityAndAuthority(decisionInput = {}, pendingRequest = {}) {
        const verified = this.verifyTokenFn(decisionInput.authToken, pendingRequest);
        if (!verified || !verified.authenticated || !verified.reviewerId) {
            throw new ApprovalBlockedError(
                'Enterprise reviewer token could not be authenticated (AUTHENTICATION_NOT_VERIFIED).',
                'AUTHENTICATION_NOT_VERIFIED'
            );
        }
        if (pendingRequest.authorId && verified.reviewerId === pendingRequest.authorId) {
            throw new ApprovalBlockedError(
                'Self-approval rejected: reviewer identity matches remediation author identity.',
                'SELF_APPROVAL_BLOCKED'
            );
        }
        return {
            approvalMode: APPROVAL_MODE.ENTERPRISE_VERIFIED_APPROVAL,
            reviewerIdentityClaim: String(verified.reviewerId),
            reviewerAuthorizationStatus: AUTH_STATUS.VERIFIED_INDEPENDENT_REVIEWER,
            signatureNotice: verified.signatureRef ? `VERIFIED_SIGNATURE:${verified.signatureRef}` : 'VERIFIED_OIDC_CLAIM'
        };
    }
}

function normalizeRepoRelPath(p) {
    return String(p || '').trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/^(?:a|b)\//, '');
}

function computeDiffSha256(diffText) {
    return crypto.createHash('sha256').update(String(diffText || ''), 'utf8').digest('hex');
}

/**
 * Extracts exact file paths touched by a unified git diff.
 */
function extractDiffFilePaths(diffText, fallbackTargetRelPath = null) {
    const files = new Set();
    const lines = String(diffText || '').split(/\r?\n/);

    for (const line of lines) {
        if (line.startsWith('diff --git ')) {
            const m = line.match(/^diff --git\s+a\/(.+?)\s+b\/(.+)$/);
            if (m && m[2]) {
                files.add(normalizeRepoRelPath(m[2]));
            }
        } else if (line.startsWith('+++ ')) {
            const raw = line.slice(4).trim();
            if (raw && raw !== '/dev/null') {
                files.add(normalizeRepoRelPath(raw));
            }
        } else if (line.startsWith('--- ')) {
            const raw = line.slice(4).trim();
            if (raw && raw !== '/dev/null') {
                files.add(normalizeRepoRelPath(raw));
            }
        }
    }

    if (files.size === 0 && fallbackTargetRelPath) {
        files.add(normalizeRepoRelPath(fallbackTargetRelPath));
    }

    return Array.from(files).sort();
}

/**
 * Creates a diff-bound approval request strictly AFTER RCA, baseline evidence,
 * and the proposed patch exist. Never approves an unspecified future patch.
 */
function createApprovalRequest(context = {}) {
    const {
        runId,
        vulnerabilityId,
        applicationId,
        baseCommitHash,
        patchDiff,
        approvedFilePaths,
        rca,
        baselineValidation,
        authorId = null,
        ttlMs = DEFAULT_APPROVAL_TTL_MS
    } = context;

    if (!runId || !vulnerabilityId || !applicationId) {
        throw new ApprovalBlockedError('runId, vulnerabilityId, and applicationId are required before creating approval request.', 'MALFORMED_REQUEST');
    }
    if (!rca || typeof rca !== 'object') {
        throw new ApprovalBlockedError('Genuine RCA evidence is required before requesting approval.', 'MISSING_RCA');
    }
    if (!baselineValidation || typeof baselineValidation !== 'object') {
        throw new ApprovalBlockedError('Baseline test evidence record is required before requesting approval.', 'MISSING_BASELINE');
    }
    if (!patchDiff || typeof patchDiff !== 'string' || patchDiff.trim().length === 0) {
        throw new ApprovalBlockedError('Proposed patch diff must be generated before requesting approval.', 'MISSING_PROPOSED_DIFF');
    }

    const normalizedFiles = Array.isArray(approvedFilePaths) && approvedFilePaths.length > 0
        ? Array.from(new Set(approvedFilePaths.map(normalizeRepoRelPath))).sort()
        : extractDiffFilePaths(patchDiff);

    if (normalizedFiles.length === 0) {
        throw new ApprovalBlockedError('Exact allowed file manifest could not be derived from proposed diff.', 'MISSING_FILE_MANIFEST');
    }

    const nowMs = Date.now();
    const createdAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(nowMs + Math.max(1000, Number(ttlMs) || DEFAULT_APPROVAL_TTL_MS)).toISOString();
    const proposedDiffSha256 = computeDiffSha256(patchDiff);

    return {
        schemaVersion: APPROVAL_SCHEMA_VERSION,
        policyVersion: APPROVAL_POLICY_VERSION,
        runId: String(runId),
        vulnerabilityId: String(vulnerabilityId),
        applicationId: String(applicationId),
        baseCommitHash: String(baseCommitHash || 'UNBOUND_NON_GIT'),
        proposedDiffSha256,
        approvedFilePaths: normalizedFiles,
        decision: 'PENDING',
        timestamp: createdAt,
        expiresAt,
        authorId,
        approvalMode: APPROVAL_MODE.LOCAL_POC_APPROVAL,
        reviewerIdentityClaim: null,
        reviewerAuthorizationStatus: AUTH_STATUS.AUTHENTICATION_NOT_VERIFIED,
        consumedAtStage5: false,
        copilotLimitationDisclosure: COPILOT_APPROVAL_LIMITATION_DISCLOSURE
    };
}

/**
 * Records an explicit human approval or rejection bound to the exact proposed diff.
 */
function recordApprovalDecision(pendingRequest, decisionInput = {}, provider = new LocalPoCApprovalProvider()) {
    if (!pendingRequest || typeof pendingRequest !== 'object' || pendingRequest.schemaVersion !== APPROVAL_SCHEMA_VERSION) {
        throw new ApprovalBlockedError('Malformed or missing pending approval request.', 'MALFORMED_APPROVAL');
    }
    if (decisionInput.modelGenerated === true) {
        throw new ApprovalBlockedError('Models cannot generate their own authorization.', 'MODEL_SELF_AUTH_BLOCKED');
    }

    const decision = String(decisionInput.decision || '').toUpperCase();
    if (decision !== 'APPROVED' && decision !== 'REJECTED') {
        throw new ApprovalBlockedError(`Invalid approval decision '${decisionInput.decision}'. Must be APPROVED or REJECTED.`, 'MALFORMED_APPROVAL');
    }

    const nowMs = typeof decisionInput.nowMs === 'number' ? decisionInput.nowMs : Date.now();
    const expiresMs = Date.parse(pendingRequest.expiresAt);
    if (Number.isNaN(expiresMs) || nowMs > expiresMs) {
        throw new ApprovalBlockedError('Pending approval request has expired; regenerate proposal and request fresh review.', 'APPROVAL_EXPIRED');
    }

    const activeProvider = provider || new LocalPoCApprovalProvider();
    const identityInfo = decision === 'APPROVED'
        ? activeProvider.verifyIdentityAndAuthority(decisionInput, pendingRequest)
        : {
            approvalMode: APPROVAL_MODE.LOCAL_POC_APPROVAL,
            reviewerIdentityClaim: null,
            reviewerAuthorizationStatus: AUTH_STATUS.AUTHENTICATION_NOT_VERIFIED,
            signatureNotice: 'LOCAL_REJECTION_RECORD'
        };

    return {
        ...pendingRequest,
        decision,
        timestamp: new Date(nowMs).toISOString(),
        approvalMode: identityInfo.approvalMode,
        reviewerIdentityClaim: identityInfo.reviewerIdentityClaim,
        reviewerAuthorizationStatus: identityInfo.reviewerAuthorizationStatus,
        signatureNotice: identityInfo.signatureNotice,
        consumedAtStage5: false
    };
}

/**
 * Strictly verifies an approval record before applying Stage 5 changes.
 * Fails closed on missing, malformed, rejected, expired, replayed, or drifted records.
 */
function verifyApprovalForExecution(approvalRecord, currentContext = {}, options = {}) {
    if (!approvalRecord || typeof approvalRecord !== 'object') {
        throw new ApprovalBlockedError('Missing Stage 4 approval record.', 'MISSING_APPROVAL');
    }
    if (approvalRecord.schemaVersion !== APPROVAL_SCHEMA_VERSION || !approvalRecord.policyVersion) {
        throw new ApprovalBlockedError('Malformed approval record schema.', 'MALFORMED_APPROVAL');
    }
    if (approvalRecord.decision !== 'APPROVED') {
        throw new ApprovalBlockedError(`Execution blocked: approval decision is '${approvalRecord.decision}'.`, 'APPROVAL_NOT_GRANTED');
    }

    const nowMs = typeof options.nowMs === 'number' ? options.nowMs : Date.now();
    const expiresMs = Date.parse(approvalRecord.expiresAt);
    if (!approvalRecord.expiresAt || Number.isNaN(expiresMs) || nowMs > expiresMs) {
        throw new ApprovalBlockedError(`Approval expired at '${approvalRecord.expiresAt}'.`, 'APPROVAL_EXPIRED');
    }

    if (approvalRecord.consumedAtStage5 === true && options.allowConsumedForFinalGate !== true) {
        throw new ApprovalBlockedError('Duplicate approval submission / replay blocked: Stage 4 approval already consumed.', 'APPROVAL_REPLAY_BLOCKED');
    }

    if (!currentContext.runId || approvalRecord.runId !== String(currentContext.runId)) {
        throw new ApprovalBlockedError(
            `Replayed approval blocked: approval runId '${approvalRecord.runId}' !== active runId '${currentContext.runId}'.`,
            'RUN_ID_MISMATCH'
        );
    }

    if (!currentContext.vulnerabilityId || approvalRecord.vulnerabilityId !== String(currentContext.vulnerabilityId)) {
        throw new ApprovalBlockedError(
            `Vulnerability mismatch: approval is bound to '${approvalRecord.vulnerabilityId}', not '${currentContext.vulnerabilityId}'.`,
            'VULNERABILITY_MISMATCH'
        );
    }

    if (!currentContext.applicationId || approvalRecord.applicationId !== String(currentContext.applicationId)) {
        throw new ApprovalBlockedError(
            `Application mismatch: approval is bound to '${approvalRecord.applicationId}', not '${currentContext.applicationId}'.`,
            'APPLICATION_MISMATCH'
        );
    }

    if (!currentContext.baseCommitHash || approvalRecord.baseCommitHash !== String(currentContext.baseCommitHash)) {
        throw new ApprovalBlockedError(
            `Base commit mismatch: approval base '${approvalRecord.baseCommitHash}' !== current '${currentContext.baseCommitHash}'.`,
            'BASE_COMMIT_MISMATCH'
        );
    }

    const actualDiffSha = computeDiffSha256(currentContext.patchDiff || '');
    if (approvalRecord.proposedDiffSha256 !== actualDiffSha) {
        throw new ApprovalBlockedError(
            'Proposed diff SHA-256 changed after approval; re-approval required.',
            'DIFF_HASH_MISMATCH'
        );
    }

    const approvedFiles = Array.isArray(approvalRecord.approvedFilePaths)
        ? Array.from(new Set(approvalRecord.approvedFilePaths.map(normalizeRepoRelPath))).sort()
        : [];
    const currentFiles = Array.isArray(currentContext.currentFilePaths)
        ? Array.from(new Set(currentContext.currentFilePaths.map(normalizeRepoRelPath))).sort()
        : extractDiffFilePaths(currentContext.patchDiff || '');

    if (approvedFiles.length === 0 ||
        approvedFiles.length !== currentFiles.length ||
        approvedFiles.some((f, i) => f !== currentFiles[i])) {
        throw new ApprovalBlockedError(
            `Approved file list mismatch: approved=[${approvedFiles.join(', ')}] vs current=[${currentFiles.join(', ')}].`,
            'FILE_LIST_MISMATCH'
        );
    }

    if (options.requireAuthenticatedApproval === true &&
        approvalRecord.reviewerAuthorizationStatus !== AUTH_STATUS.VERIFIED_INDEPENDENT_REVIEWER) {
        throw new ApprovalBlockedError(
            'Execution requires verified enterprise reviewer authentication (AUTHENTICATION_NOT_VERIFIED).',
            'AUTHENTICATION_NOT_VERIFIED'
        );
    }

    return {
        verified: true,
        runId: approvalRecord.runId,
        proposedDiffSha256: approvalRecord.proposedDiffSha256,
        approvedFilePaths: approvedFiles,
        reviewerAuthorizationStatus: approvalRecord.reviewerAuthorizationStatus,
        approvalMode: approvalRecord.approvalMode
    };
}

/**
 * Verifies the resulting applied change on disk matches the approved proposal manifest.
 */
function verifyPostApplyMatchesProposal(approvalRecord, actualAppliedFiles = [], actualDiffText = null) {
    const approvedFiles = Array.isArray(approvalRecord?.approvedFilePaths)
        ? Array.from(new Set(approvalRecord.approvedFilePaths.map(normalizeRepoRelPath))).sort()
        : [];
    const actualFiles = Array.from(new Set((actualAppliedFiles || []).map(normalizeRepoRelPath))).sort();

    if (approvedFiles.length === 0 ||
        approvedFiles.length !== actualFiles.length ||
        approvedFiles.some((f, i) => f !== actualFiles[i])) {
        throw new ApprovalBlockedError(
            `Applied files [${actualFiles.join(', ')}] do not match approved manifest [${approvedFiles.join(', ')}].`,
            'POST_APPLY_FILE_MISMATCH'
        );
    }

    if (typeof actualDiffText === 'string' && actualDiffText.trim().length > 0) {
        const appliedDiffFiles = extractDiffFilePaths(actualDiffText);
        if (appliedDiffFiles.some(f => !approvedFiles.includes(f))) {
            throw new ApprovalBlockedError(
                `Resulting Git diff touches unapproved files: [${appliedDiffFiles.join(', ')}].`,
                'POST_APPLY_DIFF_MISMATCH'
            );
        }
    }

    return {
        verified: true,
        appliedDiffSha256: typeof actualDiffText === 'string' ? computeDiffSha256(actualDiffText) : null,
        approvedFilePaths: approvedFiles
    };
}

module.exports = {
    APPROVAL_SCHEMA_VERSION,
    APPROVAL_POLICY_VERSION,
    DEFAULT_APPROVAL_TTL_MS,
    AUTH_STATUS,
    APPROVAL_MODE,
    COPILOT_APPROVAL_LIMITATION_DISCLOSURE,
    ApprovalBlockedError,
    ApprovalProvider,
    LocalPoCApprovalProvider,
    EnterpriseIdentityApprovalProvider,
    normalizeRepoRelPath,
    computeDiffSha256,
    extractDiffFilePaths,
    createApprovalRequest,
    recordApprovalDecision,
    verifyApprovalForExecution,
    verifyPostApplyMatchesProposal
};

