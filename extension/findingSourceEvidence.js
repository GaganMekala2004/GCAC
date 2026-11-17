'use strict';
const { SCANNER_RULES } = require('./scanning/adapters/secretsConfigScanner');
function assertCurrentFinding(finding, source) {
    const scanner = finding.Scanner_ID || finding.scannerId;
    if (scanner !== 'secrets-config') return;
    const id = finding.Rule_ID || finding.ruleId || String(finding.Detailed_Name || '').match(/^SEC-\d+/)?.[0];
    const rule = SCANNER_RULES.find(entry => entry.ruleId === id);
    const line = Number(finding.Line_Number || finding.line);
    if (!rule || !Number.isInteger(line) || line < 1 || !rule.regex.test(source.split(/\r?\n/)[line - 1] || '')) {
        const error = new Error('FINDING_STALE: The recorded scanner rule does not match the current source location. Run a fresh scan before remediation.');
        error.failureCategory = 'FINDING_STALE';
        throw error;
    }
}
module.exports = { assertCurrentFinding };
