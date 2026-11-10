const csvTests = require('./csvParser.test');
const reportTests = require('./reportParser.test');
const securityTests = require('./security.test');
const testRunnerTests = require('./testRunner.test');
const stateMachineTests = require('./stateMachine.test');
const metricsTests = require('./metrics.test');
const scannerAdaptersTests = require('./scannerAdapters.test');
const findingsStoreTests = require('./findingsStore.test');
const reScanVerificationTests = require('./reScanVerification.test');
const phase1SecurityTests = require('./phase1Security.test');

async function main() {
    console.log('===============================================================');
    console.log('GCAC Remediation Hub — Automated Regression Test Suite');
    console.log('Target: Milestone B Integrated Vulnerability Scanning & Verification');
    console.log('===============================================================\n');

    const suites = [
        { name: 'CSV Parser & Row Isolation', fn: csvTests.run },
        { name: 'Report Parser & Evidence Discovery', fn: reportTests.run },
        { name: 'Security Containment & Webview Hardening', fn: securityTests.run },
        { name: 'Deterministic Test Runner Execution', fn: testRunnerTests.run },
        { name: 'Workflow State Machine & Approval Gates', fn: stateMachineTests.run },
        { name: 'Dashboard Metrics & Quality Accuracy', fn: metricsTests.run },
        { name: 'Scanner Adapters & Controller Execution', fn: scannerAdaptersTests.run },
        { name: 'Normalized Findings Model & Storage', fn: findingsStoreTests.run },
        { name: 'Post-Remediation Re-Scanning & Verification', fn: reScanVerificationTests.run },
        { name: 'Phase 1 P0 Security Containment & Core Integrity', fn: phase1SecurityTests.run }
    ];

    let passedSuites = 0;
    let failedSuites = 0;
    const failures = [];

    const startTime = Date.now();

    for (const suite of suites) {
        try {
            await suite.fn();
            passedSuites++;
            console.log(`[PASS] Suite '${suite.name}' passed cleanly.\n`);
        } catch (err) {
            failedSuites++;
            failures.push({ name: suite.name, error: err });
            console.error(`[FAIL] Suite '${suite.name}' failed: ${err.message}\n${err.stack}\n`);
        }
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log('===============================================================');
    console.log('TEST SUITE EXECUTION SUMMARY');
    console.log(`Total Suites:  ${suites.length}`);
    console.log(`Passed Suites: ${passedSuites}`);
    console.log(`Failed Suites: ${failedSuites}`);
    console.log(`Duration:      ${duration}s`);
    console.log('===============================================================');

    if (failedSuites > 0) {
        console.error(`\n❌ Regression tests FAILED (${failedSuites} failed suites).`);
        process.exit(1);
    } else {
        console.log('\n✅ All automated regression test suites PASSED successfully.');
        process.exit(0);
    }
}

main().catch(err => {
    console.error('Fatal test execution error:', err);
    process.exit(1);
});
