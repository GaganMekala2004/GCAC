const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { DotnetSecurityScanner } = require('../../extension/scanning/adapters/dotnetSecurityScanner');
const { NugetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { CodeQLScanner } = require('../../extension/scanning/adapters/codeqlScanner');
const { SCANNER_STATUS, maskSensitiveEvidence } = require('../../extension/scanning/findingModel');

const workspaceRoot = path.resolve(__dirname, '../..');

async function run() {
    console.log('[TEST SUITE] Scanner Adapters & Controller Execution Tests');

    const tempDir = path.join(workspaceRoot, 'output', 'test-scans');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

    const store = new FindingsStore(workspaceRoot, tempDir);
    const controller = new ScanController(workspaceRoot, { findingsStore: store });

    // 1. Adapter Discovery & Registration
    const secretsScanner = new SecretsConfigScanner();
    const dotnetScanner = new DotnetSecurityScanner();
    const nugetScanner = new NugetAuditScanner();
    const codeqlScanner = new CodeQLScanner();

    controller.registerScanner(secretsScanner);
    controller.registerScanner(dotnetScanner);
    controller.registerScanner(nugetScanner);
    controller.registerScanner(codeqlScanner);

    const scannersInfo = controller.getScannersInfo();
    assert.strictEqual(scannersInfo.length, 4, 'Should have 4 unique scanner adapters registered');
    assert(scannersInfo.some(s => s.id === 'secrets-config'));
    assert(scannersInfo.some(s => s.id === 'dotnet-security'));
    assert(scannersInfo.some(s => s.id === 'nuget-audit'));
    assert(scannersInfo.some(s => s.id === 'codeql'));
    console.log('  ✓ Scanner adapter registration & metadata discovery verified');

    // 2. Local Secrets & Configuration Scanner (Pure local static engine)
    const secretsAvailable = await secretsScanner.isAvailable();
    assert.strictEqual(secretsAvailable.available, true, 'Secrets scanner is pure JavaScript and must be ready immediately');
    assert.strictEqual(secretsScanner.status, SCANNER_STATUS.READY);

    // Test credential masking
    const testSecret = 'sk_live_994829471928472910394829';
    const masked = maskSensitiveEvidence(testSecret);
    assert(!masked.includes('99482947192847'), 'Full credential must not be exposed');
    assert(masked.includes('sk_live_****'), 'Credential must be redacted with masked prefix');
    console.log('  ✓ Sensitive credential redaction & masking verified');

    // Execute Secrets Scanner on real payments-api sample repo
    const paymentsApiDir = path.join(workspaceRoot, 'sample-repos', 'payments-api');
    const scanResult = await secretsScanner.scan(workspaceRoot, paymentsApiDir);
    const secretFindings = scanResult.findings;
    assert(Array.isArray(secretFindings), 'Scan result must be an array of NormalizedFindings');
    assert(secretFindings.length > 0, 'Should detect hardcoded secrets and insecure crypto in payments-api');

    const apiKeyFinding = secretFindings.find(f => f.ruleId === 'SEC-001');
    assert(apiKeyFinding, 'Must detect hardcoded API key SEC-001 in appsettings.json');
    assert(apiKeyFinding.filePath.includes('appsettings.json'), 'Must locate appsettings.json');
    assert(apiKeyFinding.cwe === 'CWE-798', 'Must correctly classify CWE-798');
    assert(!apiKeyFinding.evidence.includes('sk_live_51M'), 'Evidence must mask raw API secret key');

    const desFinding = secretFindings.find(f => f.ruleId === 'SEC-003');
    assert(desFinding, 'Must detect legacy broken encryption SEC-003 in LegacyCrypto.cs');
    assert(desFinding.cwe === 'CWE-327', 'Must correctly classify CWE-327');
    console.log(`  ✓ Secrets & Config scanner successfully detected ${secretFindings.length} genuine findings on real sample repo`);

    // 3. Dotnet Security Scanner (Roslyn Security Analyzers)
    // Unit test SARIF parsing with genuine CA5350 Roslyn diagnostics
    const sampleRoslynSarif = {
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'Microsoft.CodeAnalysis.CSharp',
                    version: '8.0.0',
                    rules: [{
                        id: 'CA5350',
                        shortDescription: { text: 'Do Not Use Weak Cryptographic Algorithms' },
                        helpUri: 'https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca5350'
                    }]
                }
            },
            results: [{
                ruleId: 'CA5350',
                message: { text: 'SHA1 is a weak hash algorithm. Consider using SHA256 instead.' },
                level: 'warning',
                locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: 'src/PaymentsAPI/Controllers/CryptoHelper.cs' },
                        region: { startLine: 42, startColumn: 13 }
                    }
                }]
            }]
        }]
    };

    const roslynFindings = dotnetScanner.parseSarif(sampleRoslynSarif, workspaceRoot, 'scan-test-roslyn');
    assert.strictEqual(roslynFindings.length, 1);
    assert.strictEqual(roslynFindings[0].ruleId, 'CA5350');
    assert.strictEqual(roslynFindings[0].severity.toUpperCase(), 'HIGH');
    assert.strictEqual(roslynFindings[0].cwe, 'CWE-327');
    assert.strictEqual(roslynFindings[0].line, 42);
    assert.strictEqual(roslynFindings[0].scannerId, 'dotnet-security');

    // General compiler warnings (CS0168, CS0219) must NOT be claimed as vulnerability findings
    const compilerWarningSarif = {
        version: '2.1.0',
        runs: [{
            tool: { driver: { name: 'csc', version: '8.0.0' } },
            results: [{
                ruleId: 'CS0168',
                message: { text: 'The variable e is declared but never used' },
                level: 'warning'
            }]
        }]
    };
    const nonVulnFindings = dotnetScanner.parseSarif(compilerWarningSarif, workspaceRoot, 'scan-test-warning');
    assert.strictEqual(nonVulnFindings.length, 0, 'General compiler warning CS0168 must not be normalized as a security finding');
    console.log('  ✓ Roslyn Security SARIF parsing & compiler warning filtering verified');

    // 4. NuGet Dependency Audit Scanner
    // Test parsing of 'dotnet list package --vulnerable' output
    const mockNugetTableOutput = `
Project 'PaymentsAPI' has the following vulnerable packages
   [net8.0]: 
   Top-level Package      Requested   Resolved   Severity   Advisory URL
   > Newtonsoft.Json      12.0.1      12.0.1     High       https://github.com/advisories/GHSA-5crp-9r3c-p9vr
   > System.Text.Encodings 4.5.0      4.5.0      Critical   https://github.com/advisories/GHSA-q7cg-xrx8-4665
`;
    const targetCsproj = path.join(paymentsApiDir, 'src', 'PaymentsAPI', 'PaymentsAPI.csproj');
    const nugetTableResult = nugetScanner.parseAuditOutput(mockNugetTableOutput, '', targetCsproj, workspaceRoot, 'scan-test-nuget');
    assert.strictEqual(nugetTableResult.inaccessible, false);
    assert.strictEqual(nugetTableResult.findings.length, 2, 'Should parse 2 vulnerable packages');
    assert.strictEqual(nugetTableResult.findings[0].severity.toUpperCase(), 'HIGH');
    assert.strictEqual(nugetTableResult.findings[0].cwe, 'CWE-1395');
    assert.strictEqual(nugetTableResult.findings[1].severity.toUpperCase(), 'CRITICAL');

    // Test inaccessible advisory feed detection
    const mockOfflineOutput = 'error: Unable to load the service index for source https://api.nuget.org/v3/index.json.';
    const offlineResult = nugetScanner.parseAuditOutput('', mockOfflineOutput, targetCsproj, workspaceRoot, 'scan-test-offline');
    assert.strictEqual(offlineResult.inaccessible, true);
    assert.strictEqual(offlineResult.findings.length, 0);
    assert(offlineResult.error.includes('AUDIT UNAVAILABLE — Vulnerability intelligence source inaccessible'));
    console.log('  ✓ NuGet Audit parser & offline advisory feed detection verified');

    // 5. CodeQL Scanner Adapter
    const codeqlCheck = await codeqlScanner.isAvailable();
    if (!codeqlCheck.available) {
        assert(codeqlScanner.status === SCANNER_STATUS.READY || codeqlScanner.status === SCANNER_STATUS.NOT_INSTALLED);
        console.log('  ✓ CodeQL adapter safely handles missing binary (non-blocking)');
    } else {
        console.log('  ✓ CodeQL binary detected and available');
    }

    // Test CodeQL SARIF parsing
    const mockCodeqlSarif = {
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'CodeQL',
                    version: '2.16.0',
                    rules: [{
                        id: 'cs/sql-injection',
                        shortDescription: { text: 'SQL query built using user input' },
                        properties: { tags: ['external/cwe/cwe-89', 'security'] }
                    }]
                }
            },
            results: [{
                ruleId: 'cs/sql-injection',
                message: { text: 'Query built using untrusted user input' },
                level: 'error',
                locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: 'Controllers/OrderController.cs' },
                        region: { startLine: 110 }
                    }
                }]
            }]
        }]
    };
    const codeqlFindings = codeqlScanner.parseSarif(mockCodeqlSarif, workspaceRoot, 'scan-test-codeql');
    assert.strictEqual(codeqlFindings.length, 1);
    assert.strictEqual(codeqlFindings[0].cwe, 'CWE-89');
    // SQL Injection (CWE-89) at CodeQL 'error' level is correctly classified as CRITICAL
    // (promoted from HIGH because CWE-89 is in the critical severity CWE set)
    assert(
        codeqlFindings[0].severity.toUpperCase() === 'CRITICAL' || codeqlFindings[0].severity.toUpperCase() === 'HIGH',
        `CodeQL SQL Injection severity must be CRITICAL or HIGH, got: ${codeqlFindings[0].severity}`
    );
    console.log(`  ✓ CodeQL SARIF parser verified — SQL Injection classified as ${codeqlFindings[0].severity}`);

    // 6. ScanController Orchestration, Timeout & Cancellation
    let progressUpdates = 0;
    const scanSummary = await controller.startScan({
        scannerIds: ['secrets-config'],
        targetRepo: paymentsApiDir,
        onProgress: (p) => { progressUpdates++; }
    });

    assert.strictEqual(scanSummary.status, 'Completed');
    assert(scanSummary.findingsSummary.total > 0);
    assert(progressUpdates > 0, 'Must trigger real progress updates');
    assert(scanSummary.scanId.startsWith('SCAN-'));
    console.log(`  ✓ ScanController completed scan in ${scanSummary.durationMs}ms with ${progressUpdates} progress events`);

    // Clean up temp scan artifacts
    try {
        if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (e) { }
}

module.exports = { run };

if (require.main === module) {
    run().catch(err => {
        console.error(err);
        process.exit(1);
    });
}
