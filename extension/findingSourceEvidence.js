'use strict';
const { SCANNER_RULES } = require('./scanning/adapters/secretsConfigScanner');
const fs = require('node:fs');
const path = require('node:path');

// Keep detections visible. These GCAC fixtures deliberately contain examples
// that a maintainer must distinguish from an actual credential or code defect.
function fixtureReviewReason(repository, finding) {
    if (finding.Scanner_ID !== 'secrets-config' || !repository ||
        !fs.existsSync(path.join(repository, 'VulnerabilityRemediation.sln'))) return '';
    const file = String(finding.Location_Path || '').replace(/\\/g, '/');
    if (file === 'src/VulnerabilityRemediation.Repository/Services/SampleRepositoriesSeeder.cs') {
        return 'Manual fixture review: the sample seeder embeds example source. Inspect the reported line and scan the generated repository separately.';
    }
    if (['tests/extension/phase3SandboxSecurity.test.js', 'tests/extension/realWorldUsability.test.js',
        'tests/extension/testRunner.test.js'].includes(file)) {
        return 'Manual fixture review: inspect the reported literal in this GCAC regression test before changing its security assertions.';
    }
    return '';
}
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
module.exports = { assertCurrentFinding, fixtureReviewReason };
