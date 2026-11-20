'use strict';
// Disposable local-development acceptance. Consent is an automated test fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { WorkspaceStagingManager } = require('../extension/sandbox/workspaceStaging');
const { RepositoryContextRegistry } = require('../extension/repositoryContext');
const { SecretsConfigScanner } = require('../extension/scanning/adapters/secretsConfigScanner');
const { FindingsStore } = require('../extension/scanning/findingsStore');
const { ReScanVerifier } = require('../extension/scanning/reScanVerifier');
const { RemediationEngine } = require('../extension/remediationEngine');
const { LocalPoCApprovalProvider } = require('../extension/approvalGovernance');
const { Ollama, DirectClient } = require('../extension/providers/direct');
class FixtureConsent extends LocalPoCApprovalProvider {
    verifyIdentityAndAuthority(input, pending) {
        return {
            ...super.verifyIdentityAndAuthority(input, pending),
            approvalMode: 'AUTOMATED_TEST_CONSENT_NOT_HUMAN'
        };
    }
}
async function main() {
    const fixtureProvider = process.env.GCAC_TEST_CLAUDE_FIXTURE === '1' ? 'anthropic' :
        process.env.GCAC_TEST_OPENAI_FIXTURE === '1' ? 'openai' : process.env.GCAC_TEST_EXTERNAL_FIXTURE;
    const externalFixture = Boolean(fixtureProvider);
    const defective = process.argv[2] === 'defective';
    const providerId = fixtureProvider || 'ollama';
    const model = externalFixture ? 'contract-fixture' : process.env.GCAC_TEST_OLLAMA_MODEL;
    assert(model, 'Select an installed model explicitly');
    const endpoints = { azure: 'https://fixture.openai.azure.com/openai/v1/', compatible: 'https://fixture.example/v1/' };
    const selection = { id: providerId, model, ...(endpoints[providerId] ? { endpoint: endpoints[providerId] } : {}) };
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-direct-'));
    const extensionRoot = path.resolve(__dirname, '..');
    const repo = new WorkspaceStagingManager({
        stagingRoot: path.join(workspace, 'fixtures')
    }).stageWorkspace({
        instanceId: 'source',
        runId: 'acceptance',
        sourceRoot: path.join(extensionRoot, 'sample-repos/payments-api')
    }).workDir;
    const sql = process.argv[2] === 'sql';
    const file = sql ? 'src/PaymentsAPI/PaymentLookup.cs' : 'src/PaymentsAPI/ServiceCredential.cs';
    const original = sql
        ? `using System.Data.SqlClient;
namespace PaymentsAPI;
public class PaymentLookup
{
    public object? Lookup(PaymentsAPI.Controllers.PaymentRequest request, SqlConnection connection, Func<SqlCommand, object?>? execute = null)
    {
        string query = "SELECT * FROM Payments WHERE AccountId = '" + request.AccountId + "' AND Amount = " + request.Amount;
        using var cmd = new SqlCommand(query);
        cmd.Connection = connection;
        return execute == null ? cmd.ExecuteScalar() : execute(cmd);
    }
}
`
        : 'namespace PaymentsAPI;\npublic class ServiceCredential\n{\n    // The service has no configuration dependencies. A missing environment variable must throw InvalidOperationException.\n    public string ApiKey => System.Environment.GetEnvironmentVariable("GCAC_SERVICE_KEY") ?? "sk_live_00000000000000000000";\n}\n';
    fs.writeFileSync(path.join(repo, file), original);
    fs.writeFileSync(
        path.join(repo, 'tests/PaymentsAPI.Tests/CredentialTests.cs'),
        sql
            ? `using Xunit;
public class PaymentLookupTests {
    [Fact] public void BindsAccountIdAsData() {
        var request = new PaymentsAPI.Controllers.PaymentRequest { AccountId = "example-account", Amount = 3.5m };
        using var connection = new System.Data.SqlClient.SqlConnection();
        new PaymentsAPI.PaymentLookup().Lookup(request, connection, command => {
            Assert.DoesNotContain("example-account", command.CommandText);
            Assert.Equal(2, command.Parameters.Count);
            Assert.Contains(command.Parameters.Cast<System.Data.SqlClient.SqlParameter>(), p => Equals(p.Value, request.AccountId));
            Assert.Contains(command.Parameters.Cast<System.Data.SqlClient.SqlParameter>(), p => Equals(p.Value, request.Amount));
            return null;
        });
    }
}`
            : `using Xunit;
public class CredentialTests {
    [Fact] public void ReadsConfiguredCredential() {
        System.Environment.SetEnvironmentVariable("GCAC_SERVICE_KEY", "configured-value");
        Assert.Equal("configured-value", new PaymentsAPI.ServiceCredential().ApiKey);
        System.Environment.SetEnvironmentVariable("GCAC_SERVICE_KEY", null);
        Assert.Throws<System.InvalidOperationException>(() => new PaymentsAPI.ServiceCredential().ApiKey);
    }
}`
    );
    const git = (args) =>
        execFileSync('git', args, {
            cwd: repo,
            stdio: 'ignore',
            env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }
        });
    const missingTests = process.argv[2] === 'missing-tests';
    if (missingTests) fs.rmSync(path.join(repo,'tests'), {recursive:true});
    git(['init']);
    git(['add', '.']);
    git([
        '-c',
        'user.name=Fixture',
        '-c',
        'user.email=fixture@example.com',
        '-c',
        'core.hooksPath=/dev/null',
        'commit',
        '-m',
        'Disposable acceptance fixture'
    ]);
    const registry = new RepositoryContextRegistry({ workspaceRoot: workspace, extensionRoot });
    const registration = registry.registerDevelopmentRepository(repo, {
        acknowledged: true,
        trusted: true,
        disposable: true
    });
    const scanner = new SecretsConfigScanner();
    const finding = scanner
        .scanFile(path.join(repo, file), repo, 'acceptance', { repositoryRoot: repo })
        .find((f) => f.ruleId === (sql ? 'SEC-005' : 'SEC-001'));
    assert(finding);
    Object.assign(finding, {
        applicationNumber: registration.applicationNumber,
        repository: repo,
        repositoryRoot: repo,
        technology: 'dotnet'
    });
    if (!sql)
        finding.remediationGuidance =
            'Keep the existing environment variable lookup. Replace the embedded fallback string with a throw expression using System.InvalidOperationException when GCAC_SERVICE_KEY is absent.';
    const store = new FindingsStore(workspace);
    store.saveFindings([finding]);
    const engine = new RemediationEngine(workspace, null, {
        executionEnvironment: { GCAC_EXECUTION_MODE: 'LOCAL_DEVELOPMENT' },
        extensionRoot,
        registry,
        findingsStore: store,
        providerHost: {
            client: (p) => {
                assert.deepEqual(p, selection);
                const adapter = externalFixture
                    ? require('../tests/fixtures/openaiCredentialFixture').openaiCredentialFixture(defective, fixtureProvider, p.endpoint)
                    : new Ollama();
                return new DirectClient(adapter, model);
            }
        },
        reScanVerifier: new ReScanVerifier({
            workspaceRoot: workspace,
            scanners: new Map([[scanner.id, scanner]])
        }),
        approvalProvider: new FixtureConsent(),
        authorizedRoots: [repo],
        runsRoot: path.join(workspace, 'runs')
    });
    console.log('Disposable acceptance evidence', workspace);
    const id = finding.findingId;
    const start = () => engine.executePipeline(id, {
        workspaceTrusted: true,
        provider: selection
    });
    if (missingTests) {
        await assert.rejects(start(), /BLOCKED \(BaselineTest\)/);
        const blocked = engine.loadRunState(id);
        assert.equal(blocked.baselineValidation.machineStatus, 'UNTESTED');
        assert.equal(blocked.stages[3].status, 'blocked_by_prerequisite');
        console.log('Missing test suite blocked before approval');
        return;
    }
    const pause = await start();
    assert(pause.isAwaitingApproval, pause.status);
    const state = engine.loadRunState(id);
    assert.equal(state.proposalSource.diffSha256, state.proposedDiffSha256);
    if (externalFixture) assert.equal(state.proposalSource.kind, 'MODEL_PROPOSAL');
    const input = {
        workspaceTrusted: true,
        isHumanApproved: true,
        approvedRunId: state.runId,
        approvedDiffSha256: state.proposedDiffSha256,
        reviewerHint: 'AUTOMATED_TEST_CONSENT_NOT_HUMAN'
    };
    await assert.rejects(
        engine.executePipeline(id, { ...input, approvedDiffSha256: '0'.repeat(64) }),
        /LOCAL_APPROVAL_DIFF_MISMATCH/
    );
    const result = await engine.executePipeline(id, input);
    console.log(
        JSON.stringify({
            outcome: result.localOutcome,
            tests: result.validation?.testsTotal,
            rescan: result.reScanVerification?.machineStatus
        })
    );
    assert.equal(
        result.localOutcome,
        defective ? 'FAILED' : sql ? 'COMPLETED_VERIFIED' : 'COMPLETED_WITH_LIMITATIONS'
    );
    assert.equal(result.verifiedRemediation, sql);
    assert.equal(result.formalClosure, 'DEFERRED_IN_DEV_MODE');
    assert.equal(result.approvalRecord.approvalMode, 'AUTOMATED_TEST_CONSENT_NOT_HUMAN');
    assert.equal(result.reScanVerification.machineStatus, defective ? 'REGRESSION_DETECTED' : 'RESOLVED');
    if (process.argv.includes('--repeat-approval')) {
        const next = await start();
        assert(next.isAwaitingApproval);
        const pending = engine.loadRunState(id);
        assert.notEqual(pending.runId, state.runId);
        assert.equal(pending.approvalRecord, null);
        // Recreate the mixed-generation state written by older extension versions.
        engine.saveRunState(id, { ...pending, approvalRecord: result.approvalRecord });
        await assert.rejects(engine.executePipeline(id, input), /LOCAL_APPROVAL_DIFF_MISMATCH/);
        const consent = { ...input, approvedRunId: pending.runId, approvedDiffSha256: pending.proposedDiffSha256 };
        const reapplied = await engine.executePipeline(id, consent);
        assert.equal(reapplied.approvalRecord.runId, pending.runId);
        assert.equal(reapplied.localOutcome, result.localOutcome);
        assert.equal((await engine.executePipeline(id, consent)).duplicateSubmission, true);
    }
    if (defective) assert(result.validation.testsFailed > 0);
    assert(result.validation.testsPassed > 0);
    assert.equal(fs.readFileSync(path.join(repo, file), 'utf8'), original);
}
main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
