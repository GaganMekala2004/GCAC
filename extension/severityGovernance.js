'use strict';

/**
 * Scanner Severity & AI Triage Governance Policy (P0-E / SEC-09).
 *
 * Rules enforced:
 *  - Original scanner severity & SLA deadlines remain authoritative and immutable.
 *  - AI may advise, explain, categorize, and recommend prioritization/remediation.
 *  - AI MUST NOT downgrade severity, extend SLAs, close findings, accept risk,
 *    or mark Critical/High findings as no-action without independent human governance.
 */

const SEVERITY_RANK = Object.freeze({
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFORMATIONAL: 0,
    INFO: 0,
    UNKNOWN: -1
});

const NO_ACTION_PATTERN = /\b(?:no[- ]action|won'?t[- ]fix|false[- ]positive|ignore|close[- ]finding|accept[- ]risk|not[- ]exploitable|not[- ]applicable)\b/i;

function normalizeSeverityName(rawSeverity) {
    const upper = (rawSeverity || '').toString().trim().toUpperCase();
    if (upper.includes('CRIT')) return 'CRITICAL';
    if (upper.includes('HIGH') || upper === 'ERROR') return 'HIGH';
    if (upper.includes('MED') || upper === 'WARNING') return 'MEDIUM';
    if (upper.includes('LOW')) return 'LOW';
    if (upper.includes('INFO') || upper === 'NOTE') return 'INFORMATIONAL';
    return 'UNKNOWN';
}

function getSeverityRank(rawSeverity) {
    const name = normalizeSeverityName(rawSeverity);
    return SEVERITY_RANK[name] !== undefined ? SEVERITY_RANK[name] : -1;
}

/**
 * Deterministically evaluates AI classification output against authoritative scanner metadata.
 * Separates authoritative scanner severity from advisory AI classification and enforces
 * independent governance review on downgrades or Critical/High no-action proposals.
 *
 * @param {object} params
 * @param {object} params.finding
 * @param {object} [params.aiClassification]
 * @returns {{
 *   originalScannerSeverity: string,
 *   authoritativeSlaStatus: string,
 *   advisoryAiClassification: object,
 *   aiConfidence: number|string|null,
 *   reviewRecommendation: string,
 *   finalGovernanceDisposition: string,
 *   downgradeAttemptBlocked: boolean,
 *   requiresIndependentReview: boolean,
 *   governanceNotices: string[]
 * }}
 */
function enforceSeverityGovernance({ finding = {}, aiClassification = {} } = {}) {
    const rawOriginalSeverity = finding.Severity || finding.severity || 'MEDIUM';
    const originalScannerSeverity = normalizeSeverityName(rawOriginalSeverity);
    const originalRank = getSeverityRank(originalScannerSeverity);
    const authoritativeSlaStatus = finding.SLA_Status || finding.Sla_Status || finding.slaStatus || 'Unknown';

    const rawAiSeverity = aiClassification?.severity || null;
    const aiSeverityNormalized = rawAiSeverity ? normalizeSeverityName(rawAiSeverity) : null;
    const aiRank = aiSeverityNormalized ? getSeverityRank(aiSeverityNormalized) : -1;

    const advisoryText = [
        aiClassification?.route,
        aiClassification?.strategy,
        aiClassification?.summary,
        aiClassification?.disposition
    ].filter(Boolean).join(' ');

    const isNoActionSuggestion = NO_ACTION_PATTERN.test(advisoryText) ||
        String(aiClassification?.route || '').toLowerCase() === 'noaction' ||
        String(aiClassification?.route || '').toLowerCase() === 'nocoderemediation';

    const governanceNotices = [];
    let downgradeAttemptBlocked = false;
    let requiresIndependentReview = String(finding.Requires_Human_Review || '').toLowerCase() === 'true';

    if (aiRank >= 0 && originalRank >= 0 && aiRank < originalRank) {
        downgradeAttemptBlocked = true;
        requiresIndependentReview = true;
        governanceNotices.push(
            `AI attempted severity downgrade (${aiSeverityNormalized} < authoritative ${originalScannerSeverity}); downgrade rejected and authoritative severity preserved.`
        );
    }

    if ((originalRank >= SEVERITY_RANK.HIGH) && isNoActionSuggestion) {
        requiresIndependentReview = true;
        governanceNotices.push(
            `Authoritative ${originalScannerSeverity} finding received advisory no-action/non-code recommendation; routed to mandatory independent human governance review.`
        );
    }

    // Disallow AI attempts to alter SLA deadlines
    if (aiClassification && (aiClassification.slaStatus || aiClassification.SLA_Status || aiClassification.slaDeadline)) {
        governanceNotices.push('AI response attempted to specify SLA metadata; authoritative SLA remains immutable.');
    }

    const reviewRecommendation = requiresIndependentReview
        ? 'MANDATORY_INDEPENDENT_REVIEW'
        : 'STANDARD_HUMAN_REVIEW';

    const advisoryAiClassification = {
        cwe: aiClassification?.cwe || finding.CVE_ID || 'Unknown',
        advisorySuggestedSeverity: aiSeverityNormalized || originalScannerSeverity,
        route: aiClassification?.route || 'SpecializedAction',
        exploitability: aiClassification?.exploitability || 'Unknown',
        strategy: aiClassification?.strategy || '',
        attackVector: aiClassification?.attackVector || '',
        summary: aiClassification?.summary || '',
        isNoActionSuggestion
    };

    const aiConfidence = aiClassification?.confidence ?? null;

    return {
        originalScannerSeverity,
        authoritativeSlaStatus,
        advisoryAiClassification,
        aiConfidence,
        reviewRecommendation,
        finalGovernanceDisposition: 'PENDING_HUMAN_GOVERNANCE',
        downgradeAttemptBlocked,
        requiresIndependentReview,
        governanceNotices
    };
}

module.exports = {
    SEVERITY_RANK,
    normalizeSeverityName,
    getSeverityRank,
    enforceSeverityGovernance
};

