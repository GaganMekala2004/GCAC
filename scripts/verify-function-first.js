'use strict';
// Live technical integration proof. The proposal/review provider and consent are
// explicit AUTOMATED TEST FIXTURES, never represented as Copilot or a human.
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');
const { WorkspaceStagingManager } = require('../extension/sandbox/workspaceStaging');
const { RepositoryContextRegistry } = require('../extension/repositoryContext');
const { FindingsStore } = require('../extension/scanning/findingsStore');
const { SecretsConfigScanner } = require('../extension/scanning/adapters/secretsConfigScanner');
const { ReScanVerifier } = require('../extension/scanning/reScanVerifier');
const { ContainerSandboxBackend } = require('../extension/sandbox/containerSandboxBackend');
const { RemediationEngine } = require('../extension/remediationEngine');
const { LocalPoCApprovalProvider } = require('../extension/approvalGovernance');
const extensionRoot = path.resolve(__dirname, '..');
const evidenceDir = path.join(extensionRoot, 'docs/enterprise/fixes/evidence/function-first');
function git(cwd, args) { return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } }); }
function makePatch(original, fixed, temp, target) {
    const a = path.join(temp, 'before.cs'), b = path.join(temp, 'after.cs');
    fs.writeFileSync(a, original); fs.writeFileSync(b, fixed);
    let output;
    try { output = git(temp, ['diff', '--no-index', '--', a, b]); } catch (err) { if (err.status !== 1) throw err; output = err.stdout; }
    return output.split('\n').filter(line => !line.startsWith('diff --git ') && !line.startsWith('index ')).map(line => line.startsWith('--- ') ? `--- a/${target}` : line.startsWith('+++ ') ? `+++ b/${target}` : line).join('\n');
}
async function main() {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-function-proof-'));
    const records = [];
    fs.mkdirSync(evidenceDir, { recursive: true });
    try {
        const scenarios = process.argv[2] ? [process.argv[2]] : ['verified', 'defective', 'missing-tests', 'cancel-retry'];
        assert(scenarios.every(name => ['verified', 'defective', 'missing-tests', 'cancel-retry'].includes(name)));
        for (const scenario of scenarios) {
            const workspace = path.join(temp, scenario); fs.mkdirSync(workspace);
            const staged = new WorkspaceStagingManager({ stagingRoot: path.join(workspace, 'staging') }).stageWorkspace({ instanceId: 'proof-source', runId: 'proof-source-run', sourceRoot: path.join(extensionRoot, 'sample-repos/payments-api') });
            const repo = staged.workDir;
            fs.copyFileSync(path.join(extensionRoot, 'tests/fixtures/payments/LegacyCryptoSecurityTests.cs'), path.join(repo, 'tests/PaymentsAPI.Tests/LegacyCryptoSecurityTests.cs'));
            if (scenario === 'missing-tests') fs.rmSync(path.join(repo, 'tests'), { recursive: true, force: true });
            git(repo, ['init']); git(repo, ['add', '.']);
            git(repo, ['-c', 'user.name=GCAC Test Fixture', '-c', 'user.email=fixture@example.com', '-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'Disposable synthetic regression fixture']);
            const registry = new RepositoryContextRegistry({ workspaceRoot: workspace, extensionRoot });
            const entry = registry.registerDevelopmentRepository(repo, { acknowledged: true, trusted: true, disposable: true });
            const scanner = new SecretsConfigScanner();
            const target = 'src/PaymentsAPI/LegacyCrypto.cs';
            const original = fs.readFileSync(path.join(repo, target), 'utf8');
            const finding = scanner.scanFile(path.join(repo, target), repo, `proof-${scenario}`, { repositoryRoot: repo }).find(item => item.ruleId === 'SEC-003');
            assert(finding, 'Fresh scan must actually detect DES');
            Object.assign(finding, { findingId: `DEV-CRYPTO-${scenario.toUpperCase()}`, applicationNumber: entry.applicationNumber, repository: repo, repositoryRoot: repo, technology: 'dotnet' });
            const store = new FindingsStore(workspace); store.saveFindings([finding]);
            const fixed = scenario !== 'defective' ? original.replace('        using var des = DES.Create();\n        using var encryptor = des.CreateEncryptor(key, iv);\n        return encryptor.TransformFinalBlock(data, 0, data.Length);',
                '        var ciphertext = new byte[data.Length + 16];\n        using var aes = new AesGcm(key, 16);\n        aes.Encrypt(iv, data, ciphertext.AsSpan(0, data.Length), ciphertext.AsSpan(data.Length, 16));\n        return ciphertext;') : original.replace('DES.Create()', 'Aes.Create()');
            assert.notStrictEqual(fixed, original);
            const patch = makePatch(original, fixed, workspace, target);
            const technicalFixture = {
                getAvailableModels: async () => [{ name: 'AUTHORED_TEST_FIXTURE_NOT_COPILOT' }],
                generateJson: async prompt => prompt.includes('Classification Agent') ? { cwe: 'CWE-327', severity: 'High', route: 'SpecializedAction', strategy: 'Replace DES with authenticated AES-256-GCM', summary: 'Fresh SEC-003 matched DES.Create.' } : prompt.includes('Root Cause Analysis') ? { rootCause: 'DES has inadequate key strength.', securityImpact: 'Ciphertext confidentiality is vulnerable to brute force.', proposedFix: 'Use authenticated AES-256-GCM with a unique 12-byte nonce per key.', affectedLines: '9-11', summary: 'The current source creates DES.' } : { rating: 'PASS', summary: 'Authored test review fixture; deterministic outcome still requires real Docker tests and a real re-scan.', auditChecks: ['Do not override failed assertions.'] },
                generateCompletion: async () => `\`\`\`diff\n${patch}\`\`\`\n\`\`\`full_code\n${fixed}\`\`\``
            };
            class TestConsentProvider extends LocalPoCApprovalProvider {
                verifyIdentityAndAuthority(input, pending) { return { ...super.verifyIdentityAndAuthority(input, pending), approvalMode: 'AUTOMATED_TEST_CONSENT_NOT_HUMAN', claimedDisplayHint: 'integration-test-only' }; }
            }
            const sandboxBackend = new ContainerSandboxBackend();
            const engine = new RemediationEngine(workspace, null, { executionEnvironment: { GCAC_EXECUTION_MODE: 'LOCAL_DEVELOPMENT' }, extensionRoot,
                registry, sandboxBackend, retryPolicy: { backoffMs: [0] }, findingsStore: store, reScanVerifier: new ReScanVerifier({ workspaceRoot: workspace, scanners: new Map([['secrets-config', scanner]]) }),
                llmClient: technicalFixture, approvalProvider: new TestConsentProvider(), authorizedRoots: [repo], runsRoot: path.join(workspace, 'runs') });
            let pause;
            if (scenario === 'missing-tests') {
                await assert.rejects(() => engine.executePipeline(finding.findingId, { workspaceTrusted: true }), /BLOCKED \(BaselineTest\)/);
                const blocked = engine.loadRunState(finding.findingId);
                assert.strictEqual(blocked.baselineValidation.machineStatus, 'UNTESTED');
                assert.strictEqual(blocked.stages[3].status, 'blocked_by_prerequisite');
                pause = await engine.acknowledgeDevelopmentBaselineException(finding.findingId,
                    { acknowledged: true, rationale: 'AUTOMATED_TEST_ACKNOWLEDGEMENT_NOT_HUMAN: Exercise the missing-suite path on a disposable fixture.' }, { workspaceTrusted: true });
            } else pause = await engine.executePipeline(finding.findingId, { workspaceTrusted: true });
            assert(pause.isAwaitingApproval, `Must pause for exact-diff consent: ${JSON.stringify({status: pause.status, decision: pause.remediationDecision})}`);
            const proposed = engine.loadRunState(finding.findingId);
            assert.strictEqual(proposed.baselineValidation.machineStatus, scenario === 'missing-tests' ? 'UNTESTED' : 'FAILED');
            if (scenario !== 'missing-tests') assert(proposed.baselineValidation.testsFailed > 0);
            assert.strictEqual(fs.readFileSync(path.join(repo, target), 'utf8'), original);
            await assert.rejects(() => engine.executePipeline(finding.findingId, { workspaceTrusted: true, isHumanApproved: true, approvedRunId: proposed.runId, approvedDiffSha256: '0'.repeat(64) }), /LOCAL_APPROVAL_DIFF_MISMATCH/);
            let cancelWatch;
            let result;
            try {
                result = await engine.executePipeline(finding.findingId, { workspaceTrusted: true, isHumanApproved: true, approvedRunId: proposed.runId, approvedDiffSha256: proposed.proposedDiffSha256, reviewerHint: 'AUTOMATED_TEST_CONSENT_NOT_HUMAN',
                    onProgress: event => {
                        if (scenario === 'cancel-retry' && event.type === 'STAGE_START' && event.stageNumber === 6) {
                            cancelWatch = setInterval(() => {
                                if ([...sandboxBackend.activeInstances.values()].some(instance => instance.childProcess)) {
                                    clearInterval(cancelWatch);
                                    engine.cancelRun(finding.findingId);
                                }
                            }, 50);
                        }
                    }
                });
            } finally { if (cancelWatch) clearInterval(cancelWatch); }
            let cancellationEvidence;
            if (scenario === 'cancel-retry') {
                assert.strictEqual(result.validation.machineStatus, 'CANCELLED');
                const eligibility = engine.evaluateRetryEligibility(finding.findingId, { workspaceTrusted: true });
                assert.strictEqual(eligibility.retryEligible, true, eligibility.reason);
                cancellationEvidence = { outcome: result.validation.machineStatus, backend: result.validation.backendType, retryEligible: eligibility.retryEligible, approvedDiffSha256: proposed.proposedDiffSha256 };
                result = await engine.retryStage(finding.findingId, 6, { workspaceTrusted: true });
                assert(result.attemptHistory.length > 0);
                assert.strictEqual(result.proposedDiffSha256, proposed.proposedDiffSha256);
            }
            assert.strictEqual(result.localOutcome, ['verified', 'cancel-retry'].includes(scenario) ? 'COMPLETED_VERIFIED' : scenario === 'defective' ? 'FAILED' : 'COMPLETED_WITH_LIMITATIONS');
            assert.strictEqual(result.stages[7].status, 'deferred_in_dev_mode');
            if (scenario !== 'missing-tests') {
                assert(result.validation.testsTotal >= 3);
                assert.strictEqual(result.validation.backendType, 'local-container');
                assert.strictEqual(result.validation.networkPolicy, 'NO_NETWORK');
            } else { assert.strictEqual(result.validation.executed, false); assert.strictEqual(result.verifiedRemediation, false); }
            assert.strictEqual(result.reScanVerification.machineStatus, ['verified', 'cancel-retry'].includes(scenario) ? 'RESOLVED' : scenario === 'defective' ? 'REGRESSION_DETECTED' : 'NOT_VERIFIED');
            assert.strictEqual(result.approvalRecord.approvalMode, 'AUTOMATED_TEST_CONSENT_NOT_HUMAN');
            assert.strictEqual(fs.readFileSync(path.join(repo, target), 'utf8'), original);
            const out = path.join(evidenceDir, scenario); fs.mkdirSync(out, { recursive: true });
            for (const [label, test] of [['baseline', result.baselineValidation], ['post-fix', result.validation]]) {
                fs.writeFileSync(path.join(out, `${label}.json`), JSON.stringify({ ...test, stdout: undefined, consoleOutput: undefined }, null, 2));
                for (const [name, data] of Object.entries(test.outputArtifacts || {})) if (name.endsWith('.trx')) fs.writeFileSync(path.join(out, `${label}.trx`), data.content);
            }
            fs.writeFileSync(path.join(out, 'approved-test.patch'), result.patchDiff);
            fs.writeFileSync(path.join(out, 're-scan.json'), JSON.stringify(result.reScanVerification, null, 2));
            const record = { scenario, cancellationEvidence, findingId: finding.findingId, runId: result.runId, executionMode: result.executionMode, localOutcome: result.localOutcome, verifiedRemediation: result.verifiedRemediation,
                baseline: { total: result.baselineValidation.testsTotal, failed: result.baselineValidation.testsFailed }, postFix: { total: result.validation.testsTotal, failed: result.validation.testsFailed },
                reScan: result.reScanVerification.machineStatus, stages: result.stages.map(stage => ({ number: stage.stageNumber, status: stage.status })),
                proposalProvider: 'AUTHORED_TEST_FIXTURE_NOT_COPILOT', approval: 'AUTOMATED_TEST_CONSENT_NOT_HUMAN', originalUnchanged: true };
            records.push(record); fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(record, null, 2)); console.log(JSON.stringify(record));
        }
        fs.writeFileSync(path.join(evidenceDir, 'summary.json'), JSON.stringify(records, null, 2));
    } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
main().catch(err => { console.error(err.message); process.exitCode = 1; });
