'use strict';

const fs = require('fs');
const path = require('path');

const POLICY_VERSION = 'GCAC-P0D-1.0';

const DEFAULT_POLICY = Object.freeze({
    maxPayloadBytes: 32768,
    maxSourceChars: 16000,
    maxFiles: 1,
    minHighEntropyLength: 20,
    minHighEntropyBitsPerChar: 3.85,
    blockedPathPatterns: [
        /(?:^|[\\/])\.env(?:\.[^\\/\s]+)?$/i,
        /\.(?:pem|key|pfx|p12|jks|keystore)$/i,
        /(?:^|[\\/])\.(?:git|github|vscode|agents)(?:[\\/]|$)/i,
        /(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
        /(?:^|[\\/])(?:vulnerabilities\.csv|vulnerabilities\.db|rawvalues(?:json)?|credentials\.json)$/i
    ],
    auditLogPath: null
});

class OutboundContextBlockedError extends Error {
    constructor(decisionRecord) {
        super(
            `OutboundContextGate BLOCKED (${decisionRecord.ruleId}): ${decisionRecord.reason} ` +
            `[runId=${decisionRecord.runId}, location=${decisionRecord.redactedLocation}]`
        );
        this.name = 'OutboundContextBlockedError';
        this.decision = decisionRecord;
    }
}

/**
 * Calculates Shannon entropy (bits per character) for high-entropy string detection.
 * @param {string} str
 * @returns {number}
 */
function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = Object.create(null);
    for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const key in freq) {
        const p = freq[key] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

const SECRET_RULES = [
    {
        id: 'SEC-KEY-PRIVATE-KEY',
        reason: 'Private key block detected in outbound context',
        regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----/i
    },
    {
        id: 'SEC-KEY-STRIPE',
        reason: 'Live/test Stripe-format API key detected in outbound context',
        regex: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{8,}\b/
    },
    {
        id: 'SEC-KEY-AWS',
        reason: 'AWS access key identifier detected in outbound context',
        regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/
    },
    {
        id: 'SEC-KEY-GITHUB',
        reason: 'GitHub personal/OAuth access token detected in outbound context',
        regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/
    },
    {
        id: 'SEC-KEY-JWT',
        reason: 'JWT bearer token detected in outbound context',
        regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/
    },
    {
        id: 'SEC-CRED-CONNSTR',
        reason: 'Connection string with embedded password/account key detected',
        regex: /(?:Password|Pwd|AccountKey|SharedAccessKey)\s*=\s*(?!\$\{|@Microsoft\.KeyVault|<)([^;\r\n"']{6,})/i
    },
    {
        id: 'SEC-CRED-ASSIGN',
        reason: 'Hardcoded credential or API secret assignment detected',
        regex: /["']?(?:password|passwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'](?!\$\{|@Microsoft\.KeyVault|Environment\.|<)[A-Za-z0-9_+=/.!@#$%^&*-]{8,}["']/i
    },
    {
        id: 'SEC-BEARER',
        reason: 'Hardcoded Authorization Bearer token detected',
        regex: /\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*/i
    }
];

const PII_RULES = [
    {
        id: 'PII-SSN',
        reason: 'US Social Security Number pattern detected in outbound context',
        regex: /\b\d{3}-\d{2}-\d{4}\b/
    },
    {
        id: 'PII-CARD-PAN',
        reason: 'Potential 16-digit payment card number detected in outbound context',
        regex: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/
    },
    {
        id: 'PII-EMAIL-METADATA',
        reason: 'Personal/corporate email address detected in outbound context',
        regex: /\b[A-Za-z0-9._%+-]+@(?!example\.com\b|example\.org\b|localhost\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i
    }
];

const INJECTION_RULES = [
    {
        id: 'INJ-OVERRIDE-DIRECTIVE',
        reason: 'Prompt-injection instruction override phrase detected in untrusted context',
        regex: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior|system|above)\s+instructions?|disregard\s+(?:all\s+)?(?:security|safety|system)\s+rules?|override\s+security\s+policy|bypass\s+(?:all\s+)?approval\s+gates?)\b/i
    },
    {
        id: 'INJ-ZERO-WIDTH',
        reason: 'Hidden zero-width or bidirectional control characters detected',
        regex: /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/
    },
    {
        id: 'INJ-HIDDEN-HTML',
        reason: 'Hidden HTML comment containing directive tokens detected',
        regex: /<!--[\s\S]*?(?:ignore|override|bypass|approve|RESULT\s*:|assistant|system)[\s\S]*?-->/i
    },
    {
        id: 'INJ-RESULT-SMUGGLING',
        reason: 'Control-flow RESULT: token smuggling detected in untrusted input',
        regex: /^\s*RESULT\s*:\s*(?:PASS|PASSED|SUCCESS|RESOLVED|APPROVED)\b/im
    },
    {
        id: 'INJ-ROLE-TAG-SMUGGLING',
        reason: 'Role/channel delimiter tag smuggling detected in untrusted context',
        regex: /<\/?(?:system|assistant|tool_call|function_call)\b[^>]*>/i
    }
];

class OutboundContextGate {
    constructor(policyOverrides = {}) {
        this.policy = {
            ...DEFAULT_POLICY,
            ...policyOverrides,
            blockedPathPatterns: policyOverrides.blockedPathPatterns || DEFAULT_POLICY.blockedPathPatterns
        };
        this.auditEvents = [];
    }

    /**
     * Evaluates an extension-constructed AI context before vscode.lm transmission.
     * Fail closed: blocks restricted paths, credentials, high-entropy strings, PII,
     * binary/malformed inputs, excessive sizes/file counts, and injection markers.
     *
     * @param {object} request
     * @returns {{ allowed: true, decision: object } | { allowed: false, decision: object }}
     */
    evaluate(request) {
        const runId = (request && request.runId) ? String(request.runId) : 'unbound-run';
        const targetPaths = this._normalizeTargetPaths(request);

        const recordDecision = (decision, ruleId, reason, redactedLocation, payloadBytes = 0) => {
            const event = {
                timestamp: new Date().toISOString(),
                runId,
                decision,
                ruleId,
                reason,
                redactedLocation,
                payloadBytes,
                policyVersion: POLICY_VERSION
            };
            this.auditEvents.push(event);
            if (this.auditEvents.length > 500) {
                this.auditEvents.shift();
            }
            this._persistAuditEvent(event);
            return { allowed: decision === 'ALLOW', decision: event };
        };

        // 1. Validate malformed request shape
        if (!request || typeof request !== 'object' || typeof request.prompt !== 'string' || request.prompt.trim().length === 0) {
            return recordDecision('BLOCK', 'MALFORMED-INPUT', 'Model prompt must be a non-empty string.', 'prompt:input', 0);
        }

        const promptText = request.prompt;
        const systemPromptText = typeof request.systemPrompt === 'string' ? request.systemPrompt : '';
        const sourceCodeText = typeof request.sourceCode === 'string' ? request.sourceCode : '';
        const combinedText = [systemPromptText, promptText, sourceCodeText].filter(Boolean).join('\n');
        const payloadBytes = Buffer.byteLength(
            systemPromptText ? `${systemPromptText}\n${promptText}` : promptText,
            'utf8'
        );

        // 2. Enforce file count restriction
        if (targetPaths.length > this.policy.maxFiles) {
            return recordDecision(
                'BLOCK',
                'SCOPE-TOO-MANY-FILES',
                `Context references ${targetPaths.length} files, exceeding single-request limit of ${this.policy.maxFiles}.`,
                `files:count=${targetPaths.length}`,
                payloadBytes
            );
        }

        // 3. Enforce restricted path policies
        for (const p of targetPaths) {
            for (const rx of this.policy.blockedPathPatterns) {
                if (rx.test(p)) {
                    return recordDecision(
                        'BLOCK',
                        'PATH-RESTRICTED',
                        'Restricted or sensitive file path cannot be transmitted to LLM.',
                        `path:${this._redactPath(p)}`,
                        payloadBytes
                    );
                }
            }
        }
        // Check embedded prompt references to sensitive config/master stores
        if (/(?:vulnerability[\\/])?vulnerabilities\.csv\b|vulnerabilities\.db\b|\bRawValuesJson\b/i.test(combinedText)) {
            return recordDecision(
                'BLOCK',
                'MASTER-DATA-REFERENCE',
                'Reference to master export or RawValuesJson detected inside outbound prompt.',
                'prompt:master-data-ref',
                payloadBytes
            );
        }

        // 4. Reject unexpected binary data or excessive non-printable control characters
        if (this._containsBinaryData(combinedText)) {
            return recordDecision(
                'BLOCK',
                'BINARY-PAYLOAD',
                'Unexpected binary bytes or excessive non-printable characters detected.',
                'prompt:binary-scan',
                payloadBytes
            );
        }

        // 5. Enforce size / source-code caps
        if (payloadBytes > this.policy.maxPayloadBytes) {
            return recordDecision(
                'BLOCK',
                'PAYLOAD-SIZE-EXCEEDED',
                `Outbound prompt size (${payloadBytes} bytes) exceeds cap (${this.policy.maxPayloadBytes} bytes).`,
                `prompt:bytes=${payloadBytes}`,
                payloadBytes
            );
        }

        if (typeof request.sourceCode === 'string' && request.sourceCode.length > this.policy.maxSourceChars) {
            return recordDecision(
                'BLOCK',
                'SOURCE-CONTEXT-EXCEEDED',
                `Source code length (${request.sourceCode.length} chars) exceeds limit (${this.policy.maxSourceChars} chars).`,
                `source:chars=${request.sourceCode.length}`,
                payloadBytes
            );
        }

        // 6. Inspect for secrets, credentials, API keys, private keys
        for (const rule of SECRET_RULES) {
            const match = rule.regex.exec(combinedText);
            if (match) {
                const lineNum = this._findLineNumber(combinedText, match.index);
                return recordDecision(
                    'BLOCK',
                    rule.id,
                    rule.reason,
                    `${this._redactPath(targetPaths[0] || 'prompt')}:line=${lineNum}`,
                    payloadBytes
                );
            }
        }

        // 7. Inspect for high-entropy string literals (excluding URLs/paths/identifiers)
        const entropyHit = this._detectHighEntropyLiteral(combinedText);
        if (entropyHit) {
            return recordDecision(
                'BLOCK',
                'SEC-HIGH-ENTROPY',
                `High-entropy secret-like literal detected (${entropyHit.bitsPerChar.toFixed(2)} bits/char).`,
                `${this._redactPath(targetPaths[0] || 'prompt')}:line=${entropyHit.line}`,
                payloadBytes
            );
        }

        // 8. Inspect for PII
        for (const rule of PII_RULES) {
            const match = rule.regex.exec(combinedText);
            if (match) {
                const lineNum = this._findLineNumber(combinedText, match.index);
                return recordDecision(
                    'BLOCK',
                    rule.id,
                    rule.reason,
                    `${this._redactPath(targetPaths[0] || 'prompt')}:line=${lineNum}`,
                    payloadBytes
                );
            }
        }

        // 9. Inspect untrusted content & prompt for instruction injection / smuggling
        const untrustedToCheck = typeof request.untrustedContent === 'string'
            ? `${request.untrustedContent}\n${promptText}`
            : promptText;
        for (const rule of INJECTION_RULES) {
            const match = rule.regex.exec(untrustedToCheck);
            if (match) {
                const lineNum = this._findLineNumber(untrustedToCheck, match.index);
                return recordDecision(
                    'BLOCK',
                    rule.id,
                    rule.reason,
                    `${this._redactPath(targetPaths[0] || 'untrusted')}:line=${lineNum}`,
                    payloadBytes
                );
            }
        }

        return recordDecision(
            'ALLOW',
            'PASS-ALL-CHECKS',
            'Outbound context passed path, size, secret, PII, binary, and injection checks.',
            targetPaths[0] ? `path:${this._redactPath(targetPaths[0])}` : 'prompt:sanitized',
            payloadBytes
        );
    }

    /**
     * Evaluates and throws OutboundContextBlockedError on deny (fail-closed wrapper).
     * @param {object} request
     * @returns {object} ALLOW decision record
     */
    assertAllowed(request) {
        const res = this.evaluate(request);
        if (!res.allowed) {
            throw new OutboundContextBlockedError(res.decision);
        }
        return res.decision;
    }

    getAuditEvents(runId = null) {
        if (!runId) return [...this.auditEvents];
        return this.auditEvents.filter(e => e.runId === runId);
    }

    _normalizeTargetPaths(request) {
        const list = [];
        if (Array.isArray(request?.targetPaths)) {
            for (const p of request.targetPaths) {
                if (typeof p === 'string' && p.trim()) list.push(p.trim());
            }
        }
        if (typeof request?.filePath === 'string' && request.filePath.trim()) {
            if (!list.includes(request.filePath.trim())) {
                list.push(request.filePath.trim());
            }
        }
        return list;
    }

    _containsBinaryData(text) {
        if (text.includes('\u0000')) return true;
        let controlCount = 0;
        const sampleLen = Math.min(text.length, 4096);
        for (let i = 0; i < sampleLen; i++) {
            const code = text.charCodeAt(i);
            if (code === 65533) return true; // Replacement char U+FFFD indicates corrupted binary stream
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
                controlCount++;
            }
        }
        return sampleLen > 0 && (controlCount / sampleLen) > 0.02;
    }

    _detectHighEntropyLiteral(text) {
        // Inspect quoted literals >= minHighEntropyLength characters that contain mixed classes
        const literalRegex = /["']([A-Za-z0-9+/=_-]{20,})["']/g;
        let match;
        while ((match = literalRegex.exec(text)) !== null) {
            const candidate = match[1];
            // Skip clear placeholders, URLs, or repetitive single-case snake/kebab symbols
            if (/^(?:[A-Z0-9_-]+|[a-z0-9-]+)$/.test(candidate)) continue;
            if (/^(?:placeholder|redacted|masked|example|sample)/i.test(candidate)) continue;
            if (!/[0-9]/.test(candidate) || !/[A-Za-z]/.test(candidate)) continue;

            const bitsPerChar = calculateShannonEntropy(candidate);
            if (bitsPerChar >= this.policy.minHighEntropyBitsPerChar) {
                return {
                    bitsPerChar,
                    line: this._findLineNumber(text, match.index)
                };
            }
        }
        return null;
    }

    _findLineNumber(text, index) {
        if (index <= 0) return 1;
        return text.slice(0, index).split('\n').length;
    }

    _redactPath(p) {
        return String(p || 'unknown').replace(/\\/g, '/').split('/').slice(-2).join('/');
    }

    _persistAuditEvent(event) {
        if (!this.policy.auditLogPath) return;
        try {
            const dir = path.dirname(this.policy.auditLogPath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.appendFileSync(this.policy.auditLogPath, JSON.stringify(event) + '\n', 'utf8');
        } catch (e) {
            // Never emit raw secret context on log error
        }
    }
}

const defaultGate = new OutboundContextGate();

module.exports = {
    POLICY_VERSION,
    DEFAULT_POLICY,
    OutboundContextGate,
    OutboundContextBlockedError,
    outboundContextGate: defaultGate,
    calculateShannonEntropy
};
