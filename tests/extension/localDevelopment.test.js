'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { resolveExecutionMode, assertDevelopmentRepository, canAcknowledgeMissingBaseline, developmentConclusion } = require('../../extension/executionMode');
const { RepositoryContextRegistry } = require('../../extension/repositoryContext');
const { applyExactPatch } = require('../../extension/patchApplication');
const { extractSourceToSinkEvidence } = require('../../extension/remediationDecisionEngine');
const { isStage4ConsentEligible } = require('../../extension/baselineEligibility');
const { createRunCancellation } = require('../../extension/runCancellation');
const { inspectDotnetProjects, detectRunner } = require('../../extension/testRunner');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { assertCurrentFinding } = require('../../extension/findingSourceEvidence');
async function run() {
    assert.strictEqual(resolveExecutionMode({}), 'ENTERPRISE');
    assert.strictEqual(resolveExecutionMode({ GCAC_EXECUTION_MODE: 'LOCAL_DEVELOPMENT' }), 'LOCAL_DEVELOPMENT');
    assert.throws(() => resolveExecutionMode({ GCAC_EXECUTION_MODE: 'LOCAL_DEVELOPMENT', NODE_ENV: 'production' }), /FORBIDDEN/);
    assert.throws(() => resolveExecutionMode({ GCAC_EXECUTION_MODE: 'unknown' }), /INVALID/);
    const construction = extractSourceToSinkEvidence({ finding: { Title: 'SQL Injection', Location_Path: 'Controller.cs' }, sourceCode: 'var query = "SELECT * FROM Orders WHERE Id = " + request.Id; var cmd = new SqlCommand(query);' });
    assert.strictEqual(construction.executionEvidence.executionObserved, false);
    const actualCommand = extractSourceToSinkEvidence({ finding: { Title: 'SQL Injection', Location_Path: 'Controller.cs' }, sourceCode: 'cmd.Parameters.AddWithValue("@id", request.Id); cmd.ExecuteReader();' });
    assert.strictEqual(actualCommand.executionEvidence.parameterizedExecutingCommandObserved, true);
    const unrelatedCommand = extractSourceToSinkEvidence({ finding: { Title: 'SQL Injection', Location_Path: 'Controller.cs' }, sourceCode: 'other.Parameters.AddWithValue("@id", request.Id); cmd.ExecuteReader();' });
    assert.strictEqual(unrelatedCommand.executionEvidence.parameterizedExecutingCommandObserved, false);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-local-policy-'));
    try {
        const repo = path.join(root, 'repo'); fs.mkdirSync(repo);
        execFileSync('git', ['init', repo], { stdio: 'ignore' });
        fs.writeFileSync(path.join(repo, 'source.cs'), 'vulnerable\n');
        const registry = new RepositoryContextRegistry({ workspaceRoot: root });
        assert.throws(() => assertDevelopmentRepository(registry, repo, true), /NOT_ENROLLED/);
        registry.registerDevelopmentRepository(repo, { trusted: true, disposable: true, acknowledged: true });
        assertDevelopmentRepository(registry, repo, true);
        assert.throws(() => assertDevelopmentRepository(registry, repo, false), /WORKSPACE_TRUST/);
        fs.writeFileSync(path.join(repo, 'App.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
        fs.writeFileSync(path.join(repo, 'App.sln'), 'Microsoft Visual Studio Solution File');
        assert.strictEqual(detectRunner({ Technology: 'dotnet' }, repo).hasTestProject, false);
        fs.mkdirSync(path.join(repo, 'tests'));
        fs.writeFileSync(path.join(repo, 'tests', 'Security.Tests.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>');
        assert.strictEqual(inspectDotnetProjects(repo).testProjects.length, 1, 'Read relative manifests against their repository, not the extension process cwd');
        let cancelled = 0;
        const upstream = createRunCancellation();
        const owned = createRunCancellation(upstream);
        owned.onCancel(() => cancelled++);
        upstream.cancel(); upstream.cancel();
        assert.strictEqual(cancelled, 1);
        assert.strictEqual(owned.isCancellationRequested, true);
        owned.dispose(); upstream.dispose();
        const diff = '--- a/source.cs\n+++ b/source.cs\n@@ -1 +1 @@\n-vulnerable\n+fixed\n';
        const pending = { status: 'AWAITING_HUMAN_APPROVAL', approvalDecision: 'PENDING_STAGE4', patchDiff: diff,
            proposedDiffSha256: require('crypto').createHash('sha256').update(diff).digest('hex'),
            baselineValidation: { executed: true, countsKnown: true, testsTotal: 1, testsPassed: 1, testsFailed: 0, machineStatus: 'PASSED', exitCode: 0 } };
        Object.assign(pending, { stage: 4, runId: 'current', vulnerabilityId: 'finding', applicationNumber: 'app',
            baseCommitHash: 'base', approvedFilePaths: ['source.cs'] });
        pending.pendingApprovalRequest = { runId: 'current', vulnerabilityId: 'finding', applicationId: 'app',
            baseCommitHash: 'base', proposedDiffSha256: pending.proposedDiffSha256, approvedFilePaths: ['source.cs'],
            decision: 'PENDING', consumedAtStage5: false, expiresAt: new Date(Date.now() + 60000).toISOString() };
        const foreign = { ...pending, approvalRecord: { runId: 'old', vulnerabilityId: 'finding', consumedAtStage5: true } };
        assert.strictEqual(isStage4ConsentEligible(pending), true);
        assert.strictEqual(isStage4ConsentEligible(foreign), true);
        for (const invalid of [
            { status: 'REJECTED' }, { patchAppliedAtStage5: true }, { stage4Approved: true },
            { approvalRecord: { ...foreign.approvalRecord, runId: 'current' } },
            { approvalRecord: { consumedAtStage5: true } },
            ...[{ expiresAt: '2000-01-01' }, { runId: 'old' }, { approvedFilePaths: ['wrong.cs'] },
                { baseCommitHash: 'previous' }].map(change => ({ pendingApprovalRequest: { ...pending.pendingApprovalRequest, ...change } }))
        ]) assert.strictEqual(isStage4ConsentEligible({ ...foreign, ...invalid }), false);
        assert.strictEqual(isStage4ConsentEligible({ ...pending, patchDiff: diff + 'changed' }), false);
        assert.strictEqual(isStage4ConsentEligible({ ...pending, baselineValidation: { machineStatus: 'UNTESTED' } }), false);
        assert.strictEqual(isStage4ConsentEligible({ Requires_Human_Review: 'true' }), false);
        applyExactPatch(repo, diff, true);
        assert.strictEqual(fs.readFileSync(path.join(repo, 'source.cs'), 'utf8'), 'vulnerable\n');
        applyExactPatch(repo, diff);
        assert.strictEqual(fs.readFileSync(path.join(repo, 'source.cs'), 'utf8'), 'fixed\n');
        assert.throws(() => applyExactPatch(repo, diff, true), /PATCH_DOES_NOT_APPLY/);
        assert.throws(() => assertCurrentFinding({ Scanner_ID: 'secrets-config', Rule_ID: 'SEC-003', Line_Number: '2' }, 'DES.Create();\nreturn result;'), /FINDING_STALE/);
        assertCurrentFinding({ Scanner_ID: 'secrets-config', Rule_ID: 'SEC-003', Line_Number: '1' }, 'DES.Create();');
        const crypto = path.join(repo, 'Crypto.cs');
        fs.writeFileSync(crypto, 'using var des = DES.Create();\nusing var encryptor = des.CreateEncryptor(key, iv);');
        const cryptoMatches = new SecretsConfigScanner().scanFile(crypto, repo, 'boundary-test');
        assert.deepStrictEqual(cryptoMatches.filter(f => f.ruleId === 'SEC-003').map(f => f.line), [1], 'CreateEncryptor must not be mistaken for a second DES.Create call');
        assert(canAcknowledgeMissingBaseline({ machineStatus: 'UNTESTED', failureCategory: 'NO_TESTS_DISCOVERED' }));
        assert(!canAcknowledgeMissingBaseline({ machineStatus: 'FAILED', failureCategory: 'TESTS_FAILED', testsFailed: 1 }));
        assert(!canAcknowledgeMissingBaseline({ machineStatus: 'FAILED', failureCategory: 'BUILD_FAILED' }));
        assert(!canAcknowledgeMissingBaseline({ machineStatus: 'BLOCKED', failureCategory: 'SANDBOX_UNAVAILABLE' }));
        assert.strictEqual(developmentConclusion({ evaluation: { isResolved: true }, baseline: {}, tests: { machineStatus: 'PASSED' } }).localOutcome, 'COMPLETED_VERIFIED');
        assert.strictEqual(developmentConclusion({ evaluation: { isResolved: true }, baseline: { baselineExceptionAuthorized: true }, tests: { machineStatus: 'PASSED' } }).localOutcome, 'COMPLETED_WITH_LIMITATIONS');
        assert.strictEqual(developmentConclusion({ evaluation: { isResolved: false }, tests: { machineStatus: 'FAILED', testsFailed: 1 } }).localOutcome, 'FAILED');
        console.log('Local policy: opt-in, production rejection, explicit repository enrollment, exact patch application and honest outcomes verified.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(e => { console.error(e); process.exitCode = 1; });
