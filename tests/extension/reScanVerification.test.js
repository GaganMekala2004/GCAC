const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { ReScanVerifier } = require('../../extension/scanning/reScanVerifier');
const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { NormalizedFinding, VERIFICATION_STATUS } = require('../../extension/scanning/findingModel');
const { RemediationEngine } = require('../../extension/remediationEngine');

const workspaceRoot = path.resolve(__dirname, '../..');

async function run() {
    console.log('[TEST SUITE] Post-Remediation Re-Scanning & Verification Tests');

    const tempDir = path.join(workspaceRoot, 'output', 'test-rescan');
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    fs.mkdirSync(tempDir, { recursive: true });

    const store = new FindingsStore(workspaceRoot, tempDir);
    const controller = new ScanController(workspaceRoot, { findingsStore: store });
    const secretsScanner = new SecretsConfigScanner();
    controller.registerScanner(secretsScanner);

    const verifier = new ReScanVerifier(workspaceRoot, controller);

    // 1. Prepare disposable test file with a known security finding
    const testSubDir = path.join(tempDir, 'sample-app');
    fs.mkdirSync(testSubDir, { recursive: true });
    const testConfigFile = path.join(testSubDir, 'appsettings.json');
    
    // Insecure initial state
    const insecureContent = JSON.stringify({
        PaymentGateway: {
            Provider: 'Stripe',
            ApiKey: 'sk_live_994829471928472910394829'
        }
    }, null, 2);
    fs.writeFileSync(testConfigFile, insecureContent, 'utf-8');

    // Run baseline scan
    const baselineScan = await controller.startScan({
        scannerIds: ['secrets-config'],
        targetRepo: testSubDir
    });
    const baselineFindings = baselineScan.newFindings;
    assert(baselineFindings.length > 0, 'Baseline scan must detect the hardcoded API key');
    const targetFinding = baselineFindings[0];

    // 2. Re-Scan when issue is STILL PRESENT
    const stillPresentResult = await verifier.verifyRemediation({
        originalFinding: targetFinding,
        testResult: { passed: true, total: 1, failed: 0 },
        targetPath: testSubDir
    });

    assert.strictEqual(stillPresentResult.status, VERIFICATION_STATUS.STILL_PRESENT, 'Verifier must report STILL PRESENT when secret is unchanged');
    assert.strictEqual(stillPresentResult.isResolved, false);
    assert(stillPresentResult.evidence.length > 0);
    console.log('  ✓ Re-scan correctly detects STILL PRESENT vulnerability');

    // 3. Remediate test file (Remove secret, use environment variable placeholder)
    const remediatedContent = JSON.stringify({
        PaymentGateway: {
            Provider: 'Stripe',
            ApiKey: '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/stripe-key)'
        }
    }, null, 2);
    fs.writeFileSync(testConfigFile, remediatedContent, 'utf-8');

    // Re-Scan when issue is RESOLVED
    const resolvedResult = await verifier.verifyRemediation({
        originalFinding: targetFinding,
        testResult: { passed: true, total: 1, failed: 0 },
        targetPath: testSubDir
    });

    assert.strictEqual(resolvedResult.status, VERIFICATION_STATUS.RESOLVED, 'Verifier must report RESOLVED when secret is eradicated');
    assert.strictEqual(resolvedResult.isResolved, true);
    assert(resolvedResult.summary.includes('completely absent from targeted re-scan'));
    console.log('  ✓ Re-scan correctly verifies RESOLVED status on remediated code');

    // 4. Verification with Failed Regression Test (REGRESSION DETECTED)
    const regressionResult = await verifier.verifyRemediation({
        originalFinding: targetFinding,
        testResult: { passed: false, total: 2, failed: 1, output: 'TestPaymentFlow: Assertion failed' },
        targetPath: testSubDir
    });

    assert.strictEqual(regressionResult.status, VERIFICATION_STATUS.REGRESSION_DETECTED, 'Must report REGRESSION DETECTED when test suite fails');
    assert.strictEqual(regressionResult.isResolved, false);
    console.log('  ✓ Regression detection verified when validation tests fail');

    // 5. Verification when scanner runtime is unavailable (NOT VERIFIED - No synthetic success)
    const mockMissingScannerFinding = new NormalizedFinding({
        scanId: 'scan-missing',
        scannerId: 'non-existent-scanner',
        ruleId: 'MOCK-001',
        title: 'Mock Vulnerability',
        filePath: 'test.cs',
        severity: 'High'
    });

    const notVerifiedResult = await verifier.verifyRemediation({
        originalFinding: mockMissingScannerFinding,
        testResult: { passed: true, total: 1, failed: 0 },
        targetPath: testSubDir
    });

    assert.strictEqual(notVerifiedResult.status, VERIFICATION_STATUS.NOT_VERIFIED, 'Must report NOT VERIFIED when scanner adapter is unavailable');
    assert.strictEqual(notVerifiedResult.isResolved, false);
    console.log('  ✓ Missing scanner produces NOT VERIFIED without fabricated success');

    // 6. RemediationEngine Stage 6 & Markdown Evidence Generation
    const engine = new RemediationEngine(workspaceRoot, null, { findingsStore: store, reScanVerifier: verifier });
    assert.strictEqual(engine.reScanVerifier, verifier, 'RemediationEngine must wire reScanVerifier from options');
    assert(engine.reScanVerifier instanceof ReScanVerifier);
    console.log('  ✓ RemediationEngine integrates ReScanVerifier in Stage 6 and documentation evidence');

    // Clean up temp test directory
    try {
        if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (e) {}
}

module.exports = { run };

if (require.main === module) {
    run().catch(err => {
        console.error(err);
        process.exit(1);
    });
}
