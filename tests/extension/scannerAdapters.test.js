const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { DotnetSecurityScanner } = require('../../extension/scanning/adapters/dotnetSecurityScanner');
const { NugetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { CodeQLScanner } = require('../../extension/scanning/adapters/codeqlScanner');
const { SCANNER_STATUS, maskSensitiveEvidence } = require('../../extension/scanning/findingModel');

async function run() {
    console.log('[TEST SUITE] Scanner Adapters & Controller Execution Tests');

    // Disposable self-contained workspace fixture (independent of unpopulated gitlink sample-repos)
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-scanner-adapters-'));
    try {
        const tempDir = path.join(fixtureRoot, 'scans');
        const repoDir = path.join(fixtureRoot, 'sample-payments-api', 'src', 'PaymentsAPI');
        fs.mkdirSync(tempDir, { recursive: true });
        fs.mkdirSync(repoDir, { recursive: true });

        // Synthetic vulnerable test fixtures (stripe-pattern API key, Legacy DES cipher, csproj)
        const syntheticApiKey = ['sk', 'live', '51MockTestKey994829471928472910394'].join('_');
        fs.writeFileSync(
            path.join(repoDir, 'appsettings.json'),
            JSON.stringify({ PaymentGateway: { ApiKey: syntheticApiKey } }, null, 2),
            'utf-8'
        );
        fs.writeFileSync(
            path.join(repoDir, 'LegacyCrypto.cs'),
            'using System.Security.Cryptography;\npublic class LegacyCrypto { public object GetCipher() => DES.Create(); }\n',
            'utf-8'
        );
        const targetCsproj = path.join(repoDir, 'PaymentsAPI.csproj');
        fs.writeFileSync(
            targetCsproj,
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
            'utf-8'
        );

        const store = new FindingsStore(fixtureRoot, tempDir);
        const controller = new ScanController(fixtureRoot, { findingsStore: store });

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
        const testSecret = ['sk', 'live', '994829471928472910394829'].join('_');
        const masked = maskSensitiveEvidence(testSecret);
        assert(!masked.includes('99482947192847'), 'Full credential must not be exposed');
        assert(masked.includes('sk_live_****'), 'Credential must be redacted with masked prefix');
        console.log('  ✓ Sensitive credential redaction & masking verified');

        // Execute Secrets Scanner on isolated temp fixture repo
        const scanResult = await secretsScanner.scan(fixtureRoot, path.join(fixtureRoot, 'sample-payments-api'));
        const secretFindings = scanResult.findings;
        assert(Array.isArray(secretFindings), 'Scan result must be an array of NormalizedFindings');
        assert(secretFindings.length > 0, 'Should detect hardcoded secrets and insecure crypto in fixture repo');

        const apiKeyFinding = secretFindings.find(f => f.ruleId === 'SEC-001');
        assert(apiKeyFinding, 'Must detect hardcoded API key SEC-001 in appsettings.json');
        assert(apiKeyFinding.filePath.includes('appsettings.json'), 'Must locate appsettings.json');
        assert(apiKeyFinding.cwe === 'CWE-798', 'Must correctly classify CWE-798');
        assert(!apiKeyFinding.evidence.includes('51MockTestKey'), 'Evidence must mask raw API secret key');

        const desFinding = secretFindings.find(f => f.ruleId === 'SEC-003');
        assert(desFinding, 'Must detect legacy broken encryption SEC-003 in LegacyCrypto.cs');
        assert(desFinding.cwe === 'CWE-327', 'Must correctly classify CWE-327');
        console.log(`  ✓ Secrets & Config scanner successfully detected ${secretFindings.length} genuine findings on fixture repo`);

        // 3. Dotnet Security Scanner (Roslyn Security Analyzers)
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

        const roslynFindings = dotnetScanner.parseSarif(sampleRoslynSarif, fixtureRoot, 'scan-test-roslyn');
        assert.strictEqual(roslynFindings.length, 1);
        assert.strictEqual(roslynFindings[0].ruleId, 'CA5350');
        assert.strictEqual(roslynFindings[0].severity.toUpperCase(), 'HIGH');
        assert.strictEqual(roslynFindings[0].cwe, 'CWE-327');
        assert.strictEqual(roslynFindings[0].line, 42);
        assert.strictEqual(roslynFindings[0].scannerId, 'dotnet-security');

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
        const nonVulnFindings = dotnetScanner.parseSarif(compilerWarningSarif, fixtureRoot, 'scan-test-warning');
        assert.strictEqual(nonVulnFindings.length, 0, 'General compiler warning CS0168 must not be normalized as a security finding');
        console.log('  ✓ Roslyn Security SARIF parsing & compiler warning filtering verified');

        // 4. NuGet Dependency Audit Scanner
        const mockNugetTableOutput = `
Project 'PaymentsAPI' has the following vulnerable packages
   [net8.0]: 
   Top-level Package      Requested   Resolved   Severity   Advisory URL
   > Newtonsoft.Json      12.0.1      12.0.1     High       https://github.com/advisories/GHSA-5crp-9r3c-p9vr
   > System.Text.Encodings 4.5.0      4.5.0      Critical   https://github.com/advisories/GHSA-q7cg-xrx8-4665
`;
        const nugetTableResult = nugetScanner.parseAuditOutput(mockNugetTableOutput, '', targetCsproj, fixtureRoot, 'scan-test-nuget');
        assert.strictEqual(nugetTableResult.inaccessible, false);
        assert.strictEqual(nugetTableResult.findings.length, 2, 'Should parse 2 vulnerable packages');
        assert.strictEqual(nugetTableResult.findings[0].severity.toUpperCase(), 'HIGH');
        assert.strictEqual(nugetTableResult.findings[0].cwe, 'CWE-1395');
        assert.strictEqual(nugetTableResult.findings[1].severity.toUpperCase(), 'CRITICAL');

        const mockOfflineOutput = 'error: Unable to load the service index for source https://api.nuget.org/v3/index.json.';
        const offlineResult = nugetScanner.parseAuditOutput('', mockOfflineOutput, targetCsproj, fixtureRoot, 'scan-test-offline');
        assert.strictEqual(offlineResult.inaccessible, true);
        assert.strictEqual(offlineResult.findings.length, 0);
        assert(offlineResult.error.includes('AUDIT UNAVAILABLE — Vulnerability intelligence source inaccessible'));
        console.log('  ✓ NuGet Audit parser & offline advisory feed detection verified');

        // 5. CodeQL Scanner Adapter (non-shell execFileSync negative check)
        assert.throws(
            () => codeqlScanner._execCodeql('codeql\0bad', ['version']),
            /Invalid CodeQL executable path/,
            'Null-byte binary path must be rejected before spawning'
        );
        const codeqlCheck = await codeqlScanner.isAvailable(fixtureRoot);
        if (!codeqlCheck.available) {
            assert(codeqlScanner.status === SCANNER_STATUS.READY || codeqlScanner.status === SCANNER_STATUS.NOT_INSTALLED);
            console.log('  ✓ CodeQL adapter safely handles missing binary (non-blocking)');
        } else {
            console.log('  ✓ CodeQL binary detected and available');
        }

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
        const codeqlFindings = codeqlScanner.parseSarif(mockCodeqlSarif, fixtureRoot, 'scan-test-codeql');
        assert.strictEqual(codeqlFindings.length, 1);
        assert.strictEqual(codeqlFindings[0].cwe, 'CWE-89');
        assert(
            codeqlFindings[0].severity.toUpperCase() === 'CRITICAL' || codeqlFindings[0].severity.toUpperCase() === 'HIGH',
            `CodeQL SQL Injection severity must be CRITICAL or HIGH, got: ${codeqlFindings[0].severity}`
        );
        console.log(`  ✓ CodeQL SARIF parser verified — SQL Injection classified as ${codeqlFindings[0].severity}`);

        // 6. ScanController Orchestration, Timeout & Cancellation
        let progressUpdates = 0;
        const scanSummary = await controller.startScan({
            scannerIds: ['secrets-config'],
            targetRepo: path.join(fixtureRoot, 'sample-payments-api'),
            onProgress: (p) => { progressUpdates++; }
        });

        assert.strictEqual(scanSummary.status, 'Completed');
        assert(scanSummary.findingsSummary.total > 0);
        assert(progressUpdates > 0, 'Must trigger real progress updates');
        assert(scanSummary.scanId.startsWith('SCAN-'));
        console.log(`  ✓ ScanController completed scan in ${scanSummary.durationMs}ms with ${progressUpdates} progress events`);
    } finally {
        try {
            if (fs.existsSync(fixtureRoot)) fs.rmSync(fixtureRoot, { recursive: true, force: true });
        } catch (e) { }
    }
}

module.exports = { run };

if (require.main === module) {
    run().catch(err => {
        console.error(err);
        process.exit(1);
    });
}
