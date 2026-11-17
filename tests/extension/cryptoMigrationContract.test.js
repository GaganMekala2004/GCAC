'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { RemediationEngine } = require('../../extension/remediationEngine');
const { RunStateManager, normalizeCanonicalRunState, createCanonicalStages } = require('../../extension/runStateContract');
const { evaluateRemediationStrategy } = require('../../extension/remediationDecisionEngine');
const { validateCryptoContract } = require('../../extension/cryptoContractValidation');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-crypto-review-'));
    try {
        fs.mkdirSync(path.join(root, 'src')); fs.mkdirSync(path.join(root, 'tests'));
        const target = 'src/LegacyCrypto.cs';
        const source = 'using System.Security.Cryptography; namespace Sample; public class LegacyCrypto { public byte[] Encrypt(byte[] data, byte[] key, byte[] iv) { using var des = DES.Create(); return data; } }';
        fs.writeFileSync(path.join(root, target), source);
        fs.writeFileSync(path.join(root, 'tests', 'Tests.csproj'), '<Project><PackageReference Include="xunit" Version="2.9.2" /></Project>');
        const manager = new RunStateManager(root);
        const engine = Object.create(RemediationEngine.prototype);
        engine.loadRunState = id => manager.loadState(id);
        engine.saveRunState = (id, state) => manager.saveState(id, state);
        const finding = { Vulnerability_ID: 'CRYPTO-REVIEW', Title: 'Broken cryptographic algorithm DES', Location_Path: target };
        manager.saveState('CRYPTO-REVIEW', { status: 'MANUAL_REVIEW', isManualReview: true, sourceFilePath: path.join(root, target), targetRelPath: target,
            baseTargetSha256: crypto.createHash('sha256').update(source).digest('hex') });
        assert.throws(() => engine.approveCryptoMigrationContract('CRYPTO-REVIEW', { acknowledged: true, legacyData: 'PRESERVE' }), /explicit no-legacy-data/);
        const state = engine.approveCryptoMigrationContract('CRYPTO-REVIEW', { acknowledged: true, legacyData: 'NONE' });
        const decision = evaluateRemediationStrategy({ finding, sourceCode: source, cryptoMigrationContract: state.cryptoMigrationContract });
        assert(decision.automatedExecutionAllowed);
        assert.strictEqual(decision.blastRadius, 'HIGH');
        assert(decision.recommendedStrategy.includes('12-byte nonce'));
        assert.strictEqual(fs.readFileSync(path.join(root, target), 'utf8'), source, 'Contract review must never edit source');
        let calls = 0;
        const result = await validateCryptoContract({ repository: root, targetRelPath: target, finding, minimumTests: 4,
            artifactDir: path.join(root, 'evidence'), runTests: async (finding, copy, options) => {
                calls++; assert.notStrictEqual(copy, root); assert.strictEqual(options.workingDirectory, copy);
                const harness = fs.readFileSync(path.join(copy, 'tests', 'GcacReviewedCryptoContractTests.cs'), 'utf8');
                assert(harness.includes('Contract_TamperingAndWrongKeyRejected'));
                return { executed: true, passed: true, countsKnown: true, testsTotal: 4, testsPassed: 4, testsFailed: 0, exitCode: 0 };
            }
        });
        assert.strictEqual(calls, 1); assert.strictEqual(result.cryptoContractValidation.realExecution, true);
        assert(!fs.existsSync(path.join(root, 'tests', 'GcacReviewedCryptoContractTests.cs')));
        const missing = await validateCryptoContract({ repository: root, targetRelPath: target, finding, minimumTests: 4,
            artifactDir: path.join(root, 'evidence'), runTests: async () => ({ passed: true, countsKnown: true, testsTotal: 1 }) });
        assert.strictEqual(missing.passed, false);
        fs.appendFileSync(path.join(root, target), '// changed');
        assert.throws(() => engine.approveCryptoMigrationContract('CRYPTO-REVIEW', { acknowledged: true, legacyData: 'NONE' }), /source changed/);
        const stages = createCanonicalStages(); stages[7].status = 'completed'; stages[8].status = 'active';
        const closed = normalizeCanonicalRunState({ status: 'COMPLETED', workflowLifecycle: 'COMPLETED', formalClosure: 'RESOLVED_CLOSED',
            approvalDecision: 'APPROVED_STAGE8', securityValidationOutcome: 'PASSED', stages });
        assert.strictEqual(closed.stages[8].status, 'completed');
        console.log('Crypto migration: explicit source-bound contract, high-risk review, isolated contract-test execution and zero-test rejection verified.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
