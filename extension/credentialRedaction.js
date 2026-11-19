'use strict';
const { secretLiteralEntropy } = require('./outboundContextGate');
function createCredentialRedactor() {
    const secrets = new Map();
    let currentInput = '';
    let nextToken = 1;
    function token(value) {
        if (!secrets.has(value)) {
            let placeholder;
            do { placeholder = `<GCAC_REDACTED_${nextToken++}>`; } while (currentInput.includes(placeholder));
            secrets.set(value, placeholder);
        }
        return secrets.get(value);
    }
    function redact(value) {
        if (typeof value !== 'string') return value;
        currentInput = value;
        return value
            .replace(/-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|PGP)\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:(?:RSA|EC|DSA|OPENSSH|PGP)\s+)?PRIVATE\s+KEY-----/g, token)
            .replace(/\b[sr]k_(?:live|test)_[0-9A-Za-z]{8,}\b/g, token)
            .replace(/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g, token)
            .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, token)
            .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, token)
            .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, token)
            .replace(/(\bBearer\s+)([A-Za-z0-9\-._~+/]{16,}=*)/gi, (_, prefix, secret) => prefix + token(secret))
            .replace(/((?:Password|Pwd|AccountKey|SharedAccessKey)\s*=\s*)([^;\r\n"']{6,})/gi, (_, prefix, secret) => prefix + (/^(?:<|\$\{|@Microsoft\.KeyVault)/.test(secret) ? secret : token(secret)))
            .replace(/(["']?(?:password|passwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'])([^"'\r\n]{8,})(["'])/gi, (_, prefix, secret, suffix) => prefix + (/^(?:<|\$\{|@Microsoft\.KeyVault|Environment\.)/.test(secret) ? secret : token(secret)) + suffix);
    }
    // Only source text gets reversible entropy masking. All outbound requests
    // still pass through the gate, including model feedback and metadata.
    function redactSource(value) {
        return redact(value).replace(/(["'])([A-Za-z0-9+/=_-]{20,})(["'])/g,
            (literal, left, body, right) => secretLiteralEntropy(body) ? left + token(body) + right : literal);
    }
    // Local reconstruction preserves exact patch context. Never send this map
    // or reconstructed proposal back to a model without redacting it again.
    function restore(value) {
        let result = value;
        for (const [secret, placeholder] of secrets) result = result.split(placeholder).join(secret);
        return result;
    }
    return { redact, redactSource, restore };
}
function redactCredentials(value) { return createCredentialRedactor().redact(value); }
module.exports = { createCredentialRedactor, redactCredentials };
