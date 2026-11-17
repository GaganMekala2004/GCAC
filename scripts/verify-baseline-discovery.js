'use strict';
// Explicit live integration check: executes only through the Docker gateway.
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { runBaselineTests } = require('../extension/testRunner');
const { WorkspaceStagingManager } = require('../extension/sandbox/workspaceStaging');
async function main() {
    const workspaceRoot = path.resolve(__dirname, '..');
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-live-baseline-'));
    const results = [];
    try {
        const staged = new WorkspaceStagingManager({ stagingRoot: temp }).stageWorkspace({ instanceId: 'baseline-source', runId: 'baseline-live-check', sourceRoot: path.join(workspaceRoot, 'sample-repos/payments-api') });
        for (const mode of ['passing', 'failing']) {
            if (mode === 'failing') {
                fs.writeFileSync(path.join(staged.workDir, 'tests/PaymentsAPI.Tests/DiscoveryFailureTests.cs'), 'using Xunit; public class DiscoveryFailureTests { [Fact] public void IntentionalVerificationFailure() { Assert.Equal(1, 2); } }');
            }
            const result = await runBaselineTests({ Technology: 'dotnet', Vulnerability_ID: 'DIAG-BASELINE', Application_Number: 'APP-1001' }, workspaceRoot, { workingDirectory: staged.workDir });
            const trx = Object.entries(result.outputArtifacts || {}).filter(([name]) => name.endsWith('.trx'));
            assert(result.executed && result.testsTotal > 0, [result.rootError, ...(result.stdout || '').split('\n').filter(line => /error |failed|exception/i.test(line))].join('\n'));
            assert.strictEqual(result.backendType, 'local-container');
            assert.strictEqual(result.networkPolicy, 'NO_NETWORK');
            assert(trx.length > 0, 'Current execution must produce TRX');
            assert.strictEqual(result.machineStatus, mode === 'passing' ? 'PASSED' : 'FAILED');
            if (mode === 'failing') assert(result.testsFailed > 0);
            trx.forEach(([, data], index) => fs.writeFileSync(path.join(workspaceRoot, 'docs/enterprise/fixes/evidence', `baseline-${mode}-${index + 1}.trx`), data.content));
            const record = { scenario: mode, runId: result.runId, backendType: result.backendType, networkPolicy: result.networkPolicy, imageDigest: result.imageDigest, machineStatus: result.machineStatus, failureCategory: result.failureCategory, testsTotal: result.testsTotal, testsPassed: result.testsPassed, testsFailed: result.testsFailed, artifacts: trx.map(([name, data], index) => ({ name, file: `baseline-${mode}-${index + 1}.trx`, sha256: data.sha256 })), timestamp: new Date().toISOString() };
            results.push(record);
            console.log(JSON.stringify(record));
        }
        fs.writeFileSync(path.join(workspaceRoot, 'docs/enterprise/fixes/evidence/baseline-discovery.json'), JSON.stringify(results, null, 2) + '\n');
    } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
main().catch(e => { console.error(e); process.exitCode = 1; });
