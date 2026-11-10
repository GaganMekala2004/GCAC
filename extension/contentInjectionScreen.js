'use strict';

const crypto = require('crypto');

const INJECTION_POLICY_VERSION = 'GCAC-PH2-INJ-1.0';

const TRUST_CLASSES = Object.freeze({
    UNTRUSTED_SOURCE_COMMENT: 'UNTRUSTED_SOURCE_COMMENT',
    UNTRUSTED_SOURCE_CODE: 'UNTRUSTED_SOURCE_CODE',
    UNTRUSTED_SCANNER_FINDING: 'UNTRUSTED_SCANNER_FINDING',
    UNTRUSTED_CSV_FIELD: 'UNTRUSTED_CSV_FIELD',
    UNTRUSTED_EXCEL_FIELD: 'UNTRUSTED_EXCEL_FIELD',
    UNTRUSTED_README: 'UNTRUSTED_README',
    UNTRUSTED_MARKDOWN_REPORT: 'UNTRUSTED_MARKDOWN_REPORT',
    UNTRUSTED_TEST_NAME: 'UNTRUSTED_TEST_NAME',
    UNTRUSTED_BUILD_TEST_OUTPUT: 'UNTRUSTED_BUILD_TEST_OUTPUT',
    UNTRUSTED_REPO_CONFIG: 'UNTRUSTED_REPO_CONFIG',
    UNTRUSTED_MODEL_RESPONSE: 'UNTRUSTED_MODEL_RESPONSE'
});

const SCREEN_OUTCOME = Object.freeze({
    ALLOW_UNTRUSTED_DATA: 'ALLOW_UNTRUSTED_DATA',
    HOLD_FOR_REVIEW: 'HOLD_FOR_REVIEW',
    QUARANTINE: 'QUARANTINE',
    BLOCK: 'BLOCK'
});

class ContentInjectionBlockedError extends Error {
    constructor(decision) {
        super(
            `ContentInjectionScreen ${decision.outcome} (${decision.ruleId}): ${decision.reason} ` +
            `[runId=${decision.runId}, source=${decision.contentSource}, policy=${decision.policyVersion}]`
        );
        this.name = 'ContentInjectionBlockedError';
        this.decision = decision;
    }
}

/**
 * Structured prompt-injection and untrusted-content detection rules.
 * Every rule carries an explicit rule ID, target outcome, and policy rationale.
 */
const STRUCTURED_INJECTION_RULES = Object.freeze([
    {
        id: 'INJ-001',
        category: 'INSTRUCTION_HIERARCHY_OVERRIDE',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Instruction hierarchy override attempt detected in untrusted content.',
        regex: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior|system|above|security)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior|security|safety|system)\s+(?:instructions?|rules?|policies?)|forget\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|rules?)|override\s+(?:system|security)\s+(?:prompt|policy|instructions?)|you\s+are\s+now\s+in\s+(?:unrestricted|developer|admin|god)\s+mode|new\s+system\s+instruction\s*:)\b/i
    },
    {
        id: 'INJ-002',
        category: 'AGENT_IMPERSONATION',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Agent or system role impersonation detected in untrusted content.',
        regex: /(?:<\/?(?:system|assistant|developer|orchestrator)\b[^>]*>|\[(?:GOVERNANCE_GATE|SECURITY_REVIEW|CLASSIFICATION_AGENT|FINAL_GATE)\]\s*(?:APPROVED|PASS|PASSED|RESOLVED)|^\s*(?:System|Assistant|SecurityReviewAgent|Orchestrator)\s*:\s*(?:You\s+must|Approve|Mark|Set|Override))/im
    },
    {
        id: 'INJ-003',
        category: 'TOOL_CALL_IMPERSONATION',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Tool-call or MCP invocation impersonation detected in untrusted content.',
        regex: /(?:<\/?(?:tool_call|function_call|mcp_call|invoke)\b[^>]*>|["']tool(?:_name)?["']\s*:\s*["'](?:approve_pr|approve_remediation_pr|publish_remediation_pr|execute_batch_remediation|execute_remediation|run_command|write_file)["']|\b(?:invoke_tool|call_tool|execute_mcp)\s*:\s*[a-z0-9_-]+)/i
    },
    {
        id: 'INJ-004',
        category: 'FAKE_APPROVAL_INSTRUCTION',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Fake approval or authorization override instruction detected in untrusted content.',
        regex: /\b(?:auto[- ]?approve\s+(?:this|the|all)\s+(?:patch|fix|remediation|pr|pull\s+request)|bypass\s+(?:all\s+)?(?:human\s+)?approval\s+gates?|human\s+approval\s+(?:is\s+)?already\s+granted|set\s+isApproved\s*(?:=|to)\s*true|grant\s+stage\s*[46]\s+approval|skip\s+stage\s*[46]\s+gate)\b/i
    },
    {
        id: 'INJ-005',
        category: 'FAKE_RESULT_PASS_MARKER',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Forged PASS or RESULT control-flow marker detected in untrusted content.',
        regex: /(?:^\s*[Rr][Ee][Ss][Uu][Ll][Tt]\s*:\s*(?:PASS|PASSED|SUCCESS|RESOLVED|APPROVED|pass|passed|success|resolved|approved)\b|\bRESULT\s*:\s*(?:PASS|PASSED|SUCCESS|RESOLVED|APPROVED)\b|\[(?:PASS|pass)\]|\bRESULT\s*=\s*(?:PASS|PASSED|RESOLVED)\b|\bFinal_Validation_Status\s*[:=]\s*["']?PASS["']?|\bRemediation_Status\s*[:=]\s*["']?Remediated["']?)/m
    },
    {
        id: 'INJ-006',
        category: 'POLICY_IGNORE_REQUEST',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Request to ignore security policy or disable guardrails detected.',
        regex: /\b(?:ignore\s+(?:the\s+)?security\s+policy|disable\s+(?:outboundcontextgate|security\s+(?:checks?|review|gate)|scope\s+check)|suppress\s+all\s+warnings|add\s+#pragma\s+warning\s+disable|mark\s+(?:this\s+)?(?:vulnerability|finding)\s+as\s+(?:resolved|false[- ]positive|no[- ]action)\s+without)\b/i
    },
    {
        id: 'INJ-007',
        category: 'TEST_DISABLE_REQUEST',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Instruction to disable, delete, or falsify tests detected in untrusted content.',
        regex: /\b(?:disable\s+(?:all\s+)?(?:unit\s+)?tests?|skip\s+all\s+(?:unit\s+)?tests?|delete\s+failing\s+tests?|comment\s+out\s+(?:all\s+)?assertions?|force\s+(?:the\s+)?tests?\s+to\s+pass|replace\s+assertions?\s+with\s+true)\b/i
    },
    {
        id: 'INJ-008',
        category: 'CREDENTIAL_EXFILTRATION_INSTRUCTION',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Instruction to read, print, or exfiltrate credentials/secrets detected.',
        regex: /(?:(?:print|dump|output|leak|send|upload|exfiltrate|read|cat)\s+(?:all\s+)?(?:env(?:ironment)?\s+variables?|credentials?|secrets?|api[_ ]?keys?|\.env\b|id_rsa\b|vulnerabilities\.csv\b|vulnerabilities\.db\b)|\bsend\s+.*\bto\s+https?:\/\/)/i
    },
    {
        id: 'INJ-009',
        category: 'HIDDEN_UNICODE_CONTROL',
        outcome: SCREEN_OUTCOME.QUARANTINE,
        reason: 'Hidden zero-width, bidirectional control, soft-hyphen, or Unicode tag characters detected.',
        // Allow optional single BOM at offset 0 via preprocessing; match any remaining hidden control chars
        regex: /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\u00AD]|\uDB40[\uDC00-\uDC7F]/
    },
    {
        id: 'INJ-010',
        category: 'HIDDEN_HTML_DIRECTIVE',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Hidden HTML/Markdown comment containing directive or control tokens detected.',
        regex: /<!--[\s\S]*?(?:ignore|override|bypass|approve|RESULT\s*:|\[PASS\]|assistant|system|tool_call|exfiltrate|disable\s+test)[\s\S]*?-->/i
    },
    {
        id: 'INJ-012',
        category: 'UNRELATED_TASK_EXPANSION',
        outcome: SCREEN_OUTCOME.BLOCK,
        reason: 'Attempt to expand remediation scope into protected configs, unrelated repositories, or git publish.',
        regex: /\b(?:also\s+(?:modify|edit|update|overwrite)\s+(?:(?:\.github|\.vscode|\.agents)(?:[\\/]|\b)|another\s+repo(?:sitory)?\b|unrelated\s+files?\b|all\s+files\b)|automatically\s+(?:commit\s+and\s+push|push\s+to\s+remote|open\s+(?:a\s+)?pull\s+request|merge\s+pr)\b|run\s+git\s+push\b)/i
    }
]);

const AMBIGUOUS_HOLD_RULES = Object.freeze([
    {
        id: 'INJ-013',
        category: 'AMBIGUOUS_CONTROL_DIRECTIVE',
        outcome: SCREEN_OUTCOME.HOLD_FOR_REVIEW,
        reason: 'Ambiguous imperative language referencing policy/review/test bypass detected; requires human review.',
        regex: /\b(?:skip\s+review|do\s+not\s+run\s+tests?|treat\s+as\s+approved|ignore\s+this\s+finding|override\s+policy|never\s+say\s+blocked)\b/i
    }
]);

const ENCODED_SMUGGLE_TRIGGER = /\b(?:ignore|disregard|override|bypass|approve_pr|isApproved|RESULT\s*:\s*PASS|\[PASS\]|system\s+instruction|exfiltrate|disable\s+tests?|git\s+push)\b/i;

/**
 * Extracts comment blocks from source code so comments are explicitly inspected
 * under UNTRUSTED_SOURCE_COMMENT trust class.
 * @param {string} sourceCode
 * @returns {Array<{ line: number, text: string }>}
 */
function extractSourceComments(sourceCode) {
    if (!sourceCode || typeof sourceCode !== 'string') return [];
    const comments = [];
    const patterns = [
        /\/\*[\s\S]*?\*\//g,
        /<!--[\s\S]*?-->/g,
        /(^|[^\S\r\n])\/\/.*$/gm,
        /(^|[^\S\r\n])#(?!!).*$/gm,
        /(^|[^\S\r\n])--.*$/gm
    ];

    for (const rx of patterns) {
        let m;
        while ((m = rx.exec(sourceCode)) !== null) {
            const line = sourceCode.slice(0, m.index).split('\n').length;
            comments.push({ line, text: m[0] });
        }
    }
    return comments;
}

/**
 * Attempts realistic bounded detection of Base64, URL-encoded, or Hex-escaped
 * instruction smuggling payloads without false-positiving on SHA-256 hex digests.
 * @param {string} text
 * @returns {{ detected: boolean, encoding: string, index: number }|null}
 */
function detectEncodedSmuggling(text) {
    if (!text || typeof text !== 'string') return null;

    // 1. Base64 candidates (>= 24 chars, multiple of 4 including optional '=' padding)
    const b64Regex = /(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])/g;
    let match;
    while ((match = b64Regex.exec(text)) !== null) {
        const candidate = match[1];
        if (candidate.length % 4 !== 0 || candidate.length > 4096) continue;
        // Skip purely hex strings (e.g. SHA-256)
        if (/^[0-9a-f]+$/i.test(candidate)) continue;
        try {
            const decoded = Buffer.from(candidate, 'base64').toString('utf8');
            if (isMostlyPrintableAscii(decoded) && ENCODED_SMUGGLE_TRIGGER.test(decoded)) {
                return { detected: true, encoding: 'base64', index: match.index };
            }
        } catch {
            // ignore non-UTF8 base64
        }
    }

    // 2. Percent-encoded strings (at least 6 %XX escapes)
    const pctRegex = /(?:%[0-9A-Fa-f]{2}[^ \r\n]*){6,}/g;
    while ((match = pctRegex.exec(text)) !== null) {
        try {
            const decoded = decodeURIComponent(match[0]);
            if (ENCODED_SMUGGLE_TRIGGER.test(decoded)) {
                return { detected: true, encoding: 'url-encoded', index: match.index };
            }
        } catch {
            // ignore malformed escapes
        }
    }

    // 3. \xNN hex-escaped string literals (at least 8 consecutive/nearby \xNN sequences)
    const hexEscRegex = /(?:\\x[0-9A-Fa-f]{2}){8,}/g;
    while ((match = hexEscRegex.exec(text)) !== null) {
        const bytes = [];
        const pairRx = /\\x([0-9A-Fa-f]{2})/g;
        let pm;
        while ((pm = pairRx.exec(match[0])) !== null) {
            bytes.push(parseInt(pm[1], 16));
        }
        const decoded = Buffer.from(bytes).toString('utf8');
        if (ENCODED_SMUGGLE_TRIGGER.test(decoded)) {
            return { detected: true, encoding: 'hex-escape', index: match.index };
        }
    }

    return null;
}

function isMostlyPrintableAscii(str) {
    if (!str || str.length < 8) return false;
    let printable = 0;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) printable++;
    }
    return (printable / str.length) >= 0.9;
}

class ContentInjectionScreen {
    constructor(options = {}) {
        this.policyVersion = options.policyVersion || INJECTION_POLICY_VERSION;
        this.evidenceRecords = [];
        this.onRecord = typeof options.onRecord === 'function' ? options.onRecord : null;
    }

    /**
     * Screens a single untrusted text input and emits a structured evidence record
     * containing zero raw secret/payload values.
     *
     * @param {object} params
     * @param {string} params.text
     * @param {string} [params.contentSource='unknown']
     * @param {string} [params.trustClass=TRUST_CLASSES.UNTRUSTED_SOURCE_CODE]
     * @param {string} [params.runId='unbound-run']
     * @param {string} [params.filePath='']
     * @returns {{
     *   allowed: boolean,
     *   requiresReview: boolean,
     *   outcome: string,
     *   ruleId: string,
     *   reason: string,
     *   matches: object[],
     *   record: object
     * }}
     */
    screen(params = {}) {
        const rawText = typeof params.text === 'string' ? params.text : '';
        const runId = params.runId ? String(params.runId) : 'unbound-run';
        const contentSource = params.contentSource || 'unknown';
        const trustClass = params.trustClass || TRUST_CLASSES.UNTRUSTED_SOURCE_CODE;
        const filePath = params.filePath || contentSource;

        // Ignore a single standard UTF-8 BOM at index 0; flag any embedded U+FEFF elsewhere
        const textForUnicodeScan = rawText.startsWith('\uFEFF') ? rawText.slice(1) : rawText;

        const matches = [];

        // If scanning full source code, extract and tag comments explicitly as UNTRUSTED_SOURCE_COMMENT
        const scanTargets = [{ targetText: rawText, targetUnicodeText: textForUnicodeScan, sourceLabel: contentSource, lineOffset: 0 }];
        if (trustClass === TRUST_CLASSES.UNTRUSTED_SOURCE_CODE) {
            const comments = extractSourceComments(rawText);
            for (const c of comments) {
                scanTargets.push({
                    targetText: c.text,
                    targetUnicodeText: c.text,
                    sourceLabel: `${contentSource}#comment`,
                    lineOffset: c.line - 1
                });
            }
        }

        for (const target of scanTargets) {
            for (const rule of STRUCTURED_INJECTION_RULES) {
                const candidate = rule.id === 'INJ-009' ? target.targetUnicodeText : target.targetText;
                const m = rule.regex.exec(candidate);
                if (m) {
                    const line = target.lineOffset + candidate.slice(0, m.index).split('\n').length;
                    matches.push({
                        ruleId: rule.id,
                        category: rule.category,
                        outcome: rule.outcome,
                        reason: rule.reason,
                        line,
                        excerptSha256: crypto.createHash('sha256').update(m[0], 'utf8').digest('hex').slice(0, 16)
                    });
                }
            }

            const smuggle = detectEncodedSmuggling(target.targetText);
            if (smuggle) {
                const line = target.lineOffset + target.targetText.slice(0, smuggle.index).split('\n').length;
                matches.push({
                    ruleId: 'INJ-011',
                    category: 'ENCODED_INSTRUCTION_SMUGGLING',
                    outcome: SCREEN_OUTCOME.BLOCK,
                    reason: `Encoded (${smuggle.encoding}) instruction smuggling payload detected in untrusted content.`,
                    line,
                    excerptSha256: crypto.createHash('sha256').update(target.targetText.slice(smuggle.index, smuggle.index + 32), 'utf8').digest('hex').slice(0, 16)
                });
            }

            for (const rule of AMBIGUOUS_HOLD_RULES) {
                const m = rule.regex.exec(target.targetText);
                if (m) {
                    const line = target.lineOffset + target.targetText.slice(0, m.index).split('\n').length;
                    matches.push({
                        ruleId: rule.id,
                        category: rule.category,
                        outcome: rule.outcome,
                        reason: rule.reason,
                        line,
                        excerptSha256: crypto.createHash('sha256').update(m[0], 'utf8').digest('hex').slice(0, 16)
                    });
                }
            }
        }

        // Prioritize severity: BLOCK > QUARANTINE > HOLD_FOR_REVIEW > ALLOW_UNTRUSTED_DATA
        let primary = null;
        const priority = {
            [SCREEN_OUTCOME.BLOCK]: 3,
            [SCREEN_OUTCOME.QUARANTINE]: 2,
            [SCREEN_OUTCOME.HOLD_FOR_REVIEW]: 1,
            [SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA]: 0
        };
        for (const m of matches) {
            if (!primary || priority[m.outcome] > priority[primary.outcome]) {
                primary = m;
            }
        }

        const outcome = primary ? primary.outcome : SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA;
        const ruleId = primary ? primary.ruleId : 'INJ-PASS';
        const reason = primary ? primary.reason : 'No high-confidence or ambiguous injection directives detected; treated strictly as untrusted data.';
        const redactedLoc = `${this._redactLocation(filePath)}${primary ? `:line=${primary.line}` : ''}`;

        const record = {
            runId,
            contentSource,
            trustClass,
            ruleId,
            outcome,
            policyVersion: this.policyVersion,
            timestamp: new Date().toISOString(),
            redactedLocation: redactedLoc,
            matchCount: matches.length
        };

        this.evidenceRecords.push(record);
        if (this.evidenceRecords.length > 500) {
            this.evidenceRecords.shift();
        }
        if (this.onRecord) {
            try { this.onRecord(record); } catch {}
        }

        return {
            allowed: outcome === SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA,
            requiresReview: outcome === SCREEN_OUTCOME.HOLD_FOR_REVIEW,
            outcome,
            ruleId,
            reason,
            matches,
            record
        };
    }

    /**
     * Fail-closed wrapper throwing ContentInjectionBlockedError when BLOCK or QUARANTINE (or HOLD_FOR_REVIEW if strict).
     */
    assertSafeUntrustedData(params = {}, { blockOnHold = true } = {}) {
        const res = this.screen(params);
        if (res.outcome === SCREEN_OUTCOME.BLOCK ||
            res.outcome === SCREEN_OUTCOME.QUARANTINE ||
            (blockOnHold && res.outcome === SCREEN_OUTCOME.HOLD_FOR_REVIEW)) {
            throw new ContentInjectionBlockedError(res.record);
        }
        return res;
    }

    /**
     * Screens a list of untrusted items (e.g. finding fields, source code, README, test output).
     */
    screenAll(items = []) {
        const results = [];
        for (const item of items) {
            if (!item || typeof item.text !== 'string' || item.text.length === 0) continue;
            results.push(this.screen(item));
        }
        const blocked = results.find(r => r.outcome === SCREEN_OUTCOME.BLOCK || r.outcome === SCREEN_OUTCOME.QUARANTINE);
        const held = results.find(r => r.outcome === SCREEN_OUTCOME.HOLD_FOR_REVIEW);
        return {
            allowed: !blocked && !held,
            outcome: blocked ? blocked.outcome : (held ? held.outcome : SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA),
            blockingResult: blocked || held || null,
            results
        };
    }

    getEvidenceRecords(runId = null) {
        if (!runId) return [...this.evidenceRecords];
        return this.evidenceRecords.filter(r => r.runId === runId);
    }

    _redactLocation(loc) {
        return String(loc || 'untrusted').replace(/\\/g, '/').split('/').slice(-2).join('/');
    }
}

const defaultScreen = new ContentInjectionScreen();

module.exports = {
    INJECTION_POLICY_VERSION,
    TRUST_CLASSES,
    SCREEN_OUTCOME,
    STRUCTURED_INJECTION_RULES,
    ContentInjectionScreen,
    ContentInjectionBlockedError,
    contentInjectionScreen: defaultScreen,
    extractSourceComments,
    detectEncodedSmuggling
};
