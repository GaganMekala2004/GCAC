'use strict';

const { maskSensitiveEvidence } = require('./scanning/findingModel');

/**
 * Schema-Allowlisted Single-Finding Minimization Engine (P0-D / SEC-02 / SEC-03).
 *
 * Strips organizational PII (Product_Owner, Primary_Manager, Secondary_Manager,
 * Application_Lead), infrastructure identifiers (Subscription, Resource_Group, VM_Name),
 * RawValuesJson, unrelated rows, and credential literals before constructing any
 * agent-facing or LLM-bound finding context.
 */

const ALLOWED_SINGLE_FINDING_FIELDS = Object.freeze([
    'Vulnerability_ID',
    'Context_Schema_Version',
    'Source_Type',
    'Source_Origin',
    'Scanner_ID',
    'Scanner_Version',
    'Scan_ID',
    'Detection_Method',
    'Finding_Fingerprint',
    'Application_Number',
    'Application_Name',
    'Application_Identity_Source',
    'CVE_ID',
    'Title',
    'Detailed_Name',
    'Severity',
    'SLA_Status',
    'Location_Path',
    'Line_Number',
    'Evidence_Ref',
    'Source_Classification',
    'Technology',
    'Repository',
    'Repository_Root',
    'Canonical_Repository_ID',
    'Project_Path',
    'Package_Name',
    'Current_Version',
    'Fixed_Version',
    'Advisory_URL',
    'Remediation_Guidance',
    'Description'
]);

const ALLOWED_FIELD_SET = new Set(ALLOWED_SINGLE_FINDING_FIELDS);

const SENSITIVE_OR_PROHIBITED_FIELDS = new Set([
    'Product_Owner',
    'Primary_Manager',
    'Secondary_Manager',
    'Application_Lead',
    'Subscription',
    'Resource_Group',
    'VM_Name',
    'RawValuesJson',
    'RawValues',
    'Owner_Email',
    'Contact_Email',
    'TokenMap'
]);

/**
 * Produces a strictly allowlisted single-finding minimized object safe for
 * passing to agent prompts and minimized evidence exports.
 * Rejects arrays of multiple findings and strips unknown or sensitive fields.
 *
 * @param {object} rawFinding
 * @param {object} [options]
 * @param {boolean} [options.strictRejectUnknown=false] - When true, throws on unexpected prohibited fields
 * @returns {object}
 */
function buildMinimizedSingleFinding(rawFinding, options = {}) {
    if (!rawFinding || typeof rawFinding !== 'object') {
        throw new Error('DataMinimization Error: Finding record must be a single non-null object.');
    }

    if (Array.isArray(rawFinding)) {
        if (rawFinding.length !== 1) {
            throw new Error(`SEC-02 / SEC-03 Blocked: Expected strictly 1 finding extract, received ${rawFinding.length} records.`);
        }
        rawFinding = rawFinding[0];
    }

    if (Array.isArray(rawFinding.findings) || Array.isArray(rawFinding.allVulnerabilities) || Array.isArray(rawFinding.rows)) {
        throw new Error('SEC-02 / SEC-03 Blocked: Master export arrays cannot be embedded inside a single-finding extract.');
    }

    const unexpectedFields = [];
    for (const key of Object.keys(rawFinding)) {
        if (!ALLOWED_FIELD_SET.has(key) && SENSITIVE_OR_PROHIBITED_FIELDS.has(key)) {
            unexpectedFields.push(key);
        }
    }

    if (options.strictRejectUnknown && unexpectedFields.length > 0) {
        throw new Error(`DataMinimization Schema Blocked: Prohibited sensitive fields present: ${unexpectedFields.join(', ')}`);
    }

    const minimized = {};
    for (const field of ALLOWED_SINGLE_FINDING_FIELDS) {
        if (rawFinding[field] !== undefined && rawFinding[field] !== null && rawFinding[field] !== '') {
            minimized[field] = maskTextForAgent(String(rawFinding[field]));
        }
    }

    if (!minimized.Vulnerability_ID && typeof rawFinding.findingId === 'string') {
        minimized.Vulnerability_ID = rawFinding.findingId.trim();
    }
    if (!minimized.CVE_ID && typeof rawFinding.cwe === 'string') {
        minimized.CVE_ID = rawFinding.cwe.trim();
    }
    if (!minimized.Severity && typeof rawFinding.severity === 'string') {
        minimized.Severity = rawFinding.severity.trim().toUpperCase();
    }
    if (!minimized.Title && typeof rawFinding.title === 'string') {
        minimized.Title = maskTextForAgent(rawFinding.title);
    }
    if (!minimized.Location_Path && typeof rawFinding.filePath === 'string') {
        minimized.Location_Path = maskTextForAgent(rawFinding.filePath);
    }
    if (!minimized.Remediation_Guidance && typeof rawFinding.remediationGuidance === 'string') {
        minimized.Remediation_Guidance = maskTextForAgent(rawFinding.remediationGuidance);
    }
    if (!minimized.Scanner_ID && typeof rawFinding.scannerId === 'string') {
        minimized.Scanner_ID = rawFinding.scannerId.trim();
    }

    if (!minimized.Vulnerability_ID) {
        throw new Error('DataMinimization Error: Missing mandatory Vulnerability_ID in single-finding extract.');
    }

    return minimized;
}

/**
 * Masks credentials and obvious PII tokens in free-text fields before LLM use.
 * @param {string} value
 * @returns {string}
 */
function maskTextForAgent(value) {
    if (!value) return '';
    let masked = maskSensitiveEvidence(String(value));
    masked = masked.replace(/\b[A-Za-z0-9._%+-]+@(?!example\.com\b|example\.org\b|localhost\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi, '[REDACTED_EMAIL]');
    masked = masked.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
    return masked;
}

module.exports = {
    ALLOWED_SINGLE_FINDING_FIELDS,
    SENSITIVE_OR_PROHIBITED_FIELDS,
    buildMinimizedSingleFinding,
    maskTextForAgent
};

