'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { buildMinimizedSingleFinding } = require('../../extension/dataMinimization');
const { loadVulnerabilityDetails } = require('../../extension/reportParser');
const { createCanonicalStages, RUN_STATE_SCHEMA_VERSION } = require('../../extension/runStateContract');
const { RemediationEngine } = require('../../extension/remediationEngine');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-provenance-diagnostics-'));
    try {
        const scanner = new SecretsConfigScanner();
        const file = path.join(root, 'Controller.cs');
        fs.writeFileSync(file, 'string sql = "SELECT * from Payments WHERE Id = " + request.Id;\nProcess.Start("cmd.exe", $"/c task {input}");\nusing var digest = MD5.Create();\n');
        const findings = scanner.scanFile(file, root, 'provenance-regression');
        for (const [rule, cwe, line] of [['SEC-005', 'CWE-89', 1], ['SEC-004', 'CWE-78', 2], ['SEC-003', 'CWE-327', 3]]) {
            const finding = findings.find(f => f.ruleId === rule);
            assert(finding);
            assert.strictEqual(finding.scannerId, 'secrets-config');
            assert.strictEqual(finding.cwe, cwe);
            assert.strictEqual(finding.line, line);
            const minimized = buildMinimizedSingleFinding(finding.toCsvCompatibleRecord());
            assert.strictEqual(minimized.Rule_ID, rule);
            assert.strictEqual(minimized.CVE_ID, cwe);
        }
        const id = 'DIAG-HANDOFF';
        const dir = path.join(root, 'remediation-output', id);
        fs.mkdirSync(dir, { recursive: true });
        const stages = createCanonicalStages();
        stages[0].status = 'completed';
        fs.writeFileSync(path.join(dir, 'run-state.json'), JSON.stringify({ schemaVersion: RUN_STATE_SCHEMA_VERSION, vulnerabilityId: id, runId: 'current-handoff', status: 'HANDED_OFF_TO_COPILOT', securityValidationOutcome: 'NOT_EXECUTED', stages }));
        fs.writeFileSync(path.join(dir, 'remediation-report.md'), '# Old report\n## Documentation Agent\nFinal Status: VALIDATION_FAILED\n## Root Cause\nHuman Review: APPROVED');
        const details = loadVulnerabilityDetails(root, id);
        assert.strictEqual(details.workflowLifecycle, 'HANDED_OFF_TO_COPILOT');
        assert.strictEqual(details.securityValidationOutcome, 'NOT_EXECUTED');
        assert.strictEqual(details.stages[3].status, 'pending');
        assert(details.diagnostics.rootError.includes('no verified'));
        const category = RemediationEngine.prototype._classifyPipelineError({ name: 'OutboundContextBlockedError', message: 'OutboundContextGate BLOCKED (SEC-KEY-STRIPE)' });
        assert.strictEqual(category, 'OUTBOUND_CONTEXT_BLOCKED');
        console.log('Scanner rule provenance and canonical handoff diagnostics resist stale Markdown.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(e => { console.error(e); process.exitCode = 1; });
