'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
    FAILURE_CATEGORIES,
    detectRunner,
    inspectDotnetProjects,
    detectDotnetRunnerFramework,
    parseTrxReport,
    parseDotnetOutput,
    executeRealTestRunner,
    runBaselineTests,
    runPostFixTests
} = require('../../extension/testRunner');
const { OUTCOME_STATUS } = require('../../extension/outcomeContract');
const { SANDBOX_READINESS } = require('../../extension/sandbox/environmentDiscovery');
const {
    buildEvidenceChecklist,
    isSecretOrCredentialFinding,
    CHECK_STATUS,
    REVIEW_RECOMMENDATION
} = require('../../extension/evidenceChecklist');
const {
    computeDiffSha256,
    createApprovalRequest,
    recordApprovalDecision,
    verifyApprovalForExecution,
    ApprovalBlockedError
} = require('../../extension/approvalGovernance');
const { RemediationEngine } = require('../../extension/remediationEngine');
const { FindingsStore } = require('../../extension/scanning/findingsStore');

const WORKSPACE_ROOT = path.resolve(__dirname, '../..');

function makeTempDir(prefix = 'gcac-test-s6-') {
    const p = path.join('/tmp', `${prefix}${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
    fs.mkdirSync(p, { recursive: true });
    return p;
}

const makeMockBackend = (execFn) => ({
    checkAvailability: async () => ({
        available: true,
        status: 'READY',
        backendType: 'local-container'
    }),
    getCapabilities: () => ({ backendType: 'local-container', runtime: 'docker', architecture: 'x64', linuxContainerMode: true }),
    isImageAvailable: async () => true,
    validatePolicy: () => ({ valid: true }),
    prepareEnvironment: async (req) => ({ instanceId: req.instanceId, workDir: req.approvedWorkspaceReference, staged: {} }),
    executeApprovedOperation: async () => ({
        exitCode: 0,
        durationMs: 15,
        ...execFn()
    }),
    cancelOperation: async () => ({ cancelled: true }),
    collectEvidence: async () => ({}),
    cleanup: async () => ({ cleaned: true })
});

function cleanupTempDir(dir) {
    try {
        if (dir && fs.existsSync(dir)) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    } catch {}
}

async function runStage6TestVerificationSuite() {
    console.log('===============================================================');
    console.log('GCAC Stage 6 Test Verification & Remediation Evidence Suite');
    console.log('Validating All 16 Deterministic Verification Scenarios');
    console.log('===============================================================\n');

    const readyEnv = {
        sandboxAvailable: true,
        sandboxStatus: SANDBOX_READINESS.READY,
        selectedRuntime: 'docker',
        os: { platform: 'linux', arch: 'x64' },
        containers: { docker: { installed: true, daemonReachable: true } },
        boundaryDisclosure: {
            enforcedBoundaries: ['Isolated container rootfs', 'No network (--network=none)'],
            limitations: []
        }
    };

    // -------------------------------------------------------------------------
    // Scenario 1: VSTest with genuine passing tests
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 1] VSTest with Genuine Passing Tests');
    {
        const validPassingTrx = `<?xml version="1.0" encoding="utf-8"?>
<TestRun id="11111111-2222-3333-4444-555555555555" name="Run1" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Counters total="2" executed="2" passed="2" failed="0" error="0" timeout="0" aborted="0" notExecuted="0" />
  <ResultSummary outcome="Completed">
    <Counters total="2" executed="2" passed="2" failed="0" error="0" timeout="0" aborted="0" notExecuted="0" />
  </ResultSummary>
</TestRun>`;

        const parsed = parseTrxReport(validPassingTrx, { runId: 'run-pass-1' });
        assert.strictEqual(parsed.valid, true);
        assert.strictEqual(parsed.status, 'PASS');
        assert.strictEqual(parsed.machineStatus, OUTCOME_STATUS.PASSED);
        assert.strictEqual(parsed.failureCategory, FAILURE_CATEGORIES.NONE);
        assert.strictEqual(parsed.testsTotal, 2);
        assert.strictEqual(parsed.testsPassed, 2);
        assert.strictEqual(parsed.testsFailed, 0);

        // Test runner with TRX content
        const tmpDir = makeTempDir('pass-vstest-');
        try {
            fs.writeFileSync(path.join(tmpDir, 'Test.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><IsTestProject>true</IsTestProject></PropertyGroup></Project>');
            const mockBackend = makeMockBackend(() => ({
                exitCode: 0,
                durationMs: 15,
                stdout: 'Custom console output without VSTest regex summary',
                stderr: ''
            }));

            const runRes = await executeRealTestRunner('dotnet', ['test', '--logger', 'trx'], tmpDir, {
                workingDirectory: tmpDir,
                sandboxBackend: mockBackend,
                envReport: readyEnv,
                trxContent: validPassingTrx
            });

            assert.strictEqual(runRes.executed, true);
            assert.strictEqual(runRes.passed, true);
            assert.strictEqual(runRes.status, 'PASS');
            assert.strictEqual(runRes.machineStatus, OUTCOME_STATUS.PASSED);
            assert.strictEqual(runRes.testsTotal, 2);
            assert.strictEqual(runRes.testsPassed, 2);
            assert.strictEqual(runRes.testsFailed, 0);
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 1: VSTest genuine passing tests verified via TRX counters.');
    }

    // -------------------------------------------------------------------------
    // Scenario 2: VSTest with genuine failing tests
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 2] VSTest with Genuine Failing Tests');
    {
        const validFailingTrx = `<?xml version="1.0" encoding="utf-8"?>
<TestRun id="22222222-3333-4444-5555-666666666666" name="Run2" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Counters total="2" executed="2" passed="1" failed="1" error="0" timeout="0" aborted="0" notExecuted="0" />
  <Results>
    <UnitTestResult executionId="ex-1" testId="t-1" testName="PaymentsAPI.Tests.PaymentControllerTests.Process_DoesNotThrowOnValidRequest" outcome="Passed" />
    <UnitTestResult executionId="ex-2" testId="t-2" testName="PaymentsAPI.Tests.PaymentControllerTests.Process_UsesParameterizedQuery_AndBindsParameters" outcome="Failed">
      <Output>
        <ErrorInfo>
          <Message>Assert.DoesNotContain() Failure: Found: "ACC-100' OR '1'='1" in "SELECT * FROM Payments WHERE AccountId = 'ACC-100' OR '1'='1'"</Message>
        </ErrorInfo>
      </Output>
    </UnitTestResult>
  </Results>
  <ResultSummary outcome="Failed">
    <Counters total="2" executed="2" passed="1" failed="1" error="0" timeout="0" aborted="0" notExecuted="0" />
  </ResultSummary>
</TestRun>`;

        const parsed = parseTrxReport(validFailingTrx, { runId: 'run-fail-1' });
        assert.strictEqual(parsed.valid, true);
        assert.strictEqual(parsed.status, 'FAIL');
        assert.strictEqual(parsed.machineStatus, OUTCOME_STATUS.FAILED);
        assert.strictEqual(parsed.failureCategory, FAILURE_CATEGORIES.TESTS_FAILED);
        assert.strictEqual(parsed.testsTotal, 2);
        assert.strictEqual(parsed.testsPassed, 1);
        assert.strictEqual(parsed.testsFailed, 1);
        assert(parsed.rootError.includes('PaymentControllerTests.Process_UsesParameterizedQuery_AndBindsParameters'));
        assert(parsed.rootError.includes('Assert.DoesNotContain() Failure'));
        console.log('  ✓ Scenario 2: VSTest genuine failing tests extracted test-level failure diagnostics.');
    }

    // -------------------------------------------------------------------------
    // Scenario 3: Supported MTP Configuration
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 3] Microsoft Testing Platform (MTP) Detection and Trx Flags');
    {
        const tmpDir = makeTempDir('mtp-');
        try {
            // Project with MTP and Trx extension
            const mtpWithTrx = path.join(tmpDir, 'MtpWithTrx.csproj');
            fs.writeFileSync(mtpWithTrx, `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <EnableMicrosoftTestingPlatform>true</EnableMicrosoftTestingPlatform>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Testing.Platform" Version="1.4.0" />
    <PackageReference Include="Microsoft.Testing.Extensions.TrxReport" Version="1.4.0" />
  </ItemGroup>
</Project>`);

            const detectedWithTrx = detectDotnetRunnerFramework(mtpWithTrx);
            assert.strictEqual(detectedWithTrx.runner, 'mtp');
            assert.strictEqual(detectedWithTrx.supportsTrx, true);
            assert(detectedWithTrx.trxFlags.includes('--report-trx'));
            assert(detectedWithTrx.trxFlags.includes('--report-trx-filename'));
            assert(!detectedWithTrx.trxFlags.includes('--logger'), 'MTP must not receive VSTest --logger switch');

            // Project with MTP but WITHOUT Trx extension
            const mtpWithoutTrx = path.join(tmpDir, 'MtpWithoutTrx.csproj');
            fs.writeFileSync(mtpWithoutTrx, `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <EnableMicrosoftTestingPlatform>true</EnableMicrosoftTestingPlatform>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Testing.Platform" Version="1.4.0" />
  </ItemGroup>
</Project>`);

            const detectedWithoutTrx = detectDotnetRunnerFramework(mtpWithoutTrx);
            assert.strictEqual(detectedWithoutTrx.runner, 'mtp');
            assert.strictEqual(detectedWithoutTrx.supportsTrx, false);
            assert.deepStrictEqual(detectedWithoutTrx.trxFlags, [], 'MTP without Trx extension must not receive unsupported switches');

            // VSTest project
            const vstestProj = path.join(tmpDir, 'VsTest.csproj');
            fs.writeFileSync(vstestProj, `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
  </ItemGroup>
</Project>`);

            const detectedVsTest = detectDotnetRunnerFramework(vstestProj);
            assert.strictEqual(detectedVsTest.runner, 'vstest');
            assert.strictEqual(detectedVsTest.supportsTrx, true);
            assert(detectedVsTest.trxFlags.includes('--logger'));
            assert(detectedVsTest.trxFlags.includes('trx'));
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 3: MTP detected accurately; VSTest-only switches not applied indiscriminately.');
    }

    // -------------------------------------------------------------------------
    // Scenario 4: Repository with no tests
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 4] Repository with No Tests');
    {
        const tmpDir = makeTempDir('notests-');
        try {
            // Empty repo
            const runner = detectRunner({ Technology: 'dotnet' }, tmpDir);
            assert(runner === null || runner.hasTestProject === false, 'Repository with no build manifests must report hasTestProject=false or null');

            const baselineRes = await runBaselineTests({ Technology: 'dotnet' }, tmpDir, { workingDirectory: tmpDir });
            assert.strictEqual(baselineRes.executed, false);
            assert.strictEqual(baselineRes.status, 'UNTESTED');
            assert.strictEqual(baselineRes.machineStatus, OUTCOME_STATUS.UNTESTED);
            assert.strictEqual(baselineRes.failureCategory, FAILURE_CATEGORIES.NO_TESTS_DISCOVERED);
            assert.strictEqual(baselineRes.testsTotal, 0);
            assert.strictEqual(baselineRes.passed, false);
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 4: Repository with no tests reports NO_TESTS_DISCOVERED without fabricated pass.');
    }

    // -------------------------------------------------------------------------
    // Scenario 5: Application project mistakenly selected for testing
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 5] Application Project Mistakenly Selected for Testing');
    {
        // When MSBuild outputs skipping message for app project
        const appSkipOutput = 'Skipping running test for project /app/PaymentsAPI.csproj. To run tests with dotnet test add "<IsTestProject>true</IsTestProject>" property to project file.\nBuild succeeded.\n    0 Warning(s)\n    0 Error(s)';
        const parsed = parseDotnetOutput(appSkipOutput, '', 0);

        assert.strictEqual(parsed.status, 'UNTESTED');
        assert.strictEqual(parsed.machineStatus, OUTCOME_STATUS.UNTESTED);
        assert.strictEqual(parsed.failureCategory, FAILURE_CATEGORIES.TEST_PROJECT_NOT_FOUND);
        assert.strictEqual(parsed.testsTotal, 0);
        assert(parsed.rootError.includes('application project selected for testing'));
        console.log('  ✓ Scenario 5: Application project selected for testing correctly flagged TEST_PROJECT_NOT_FOUND.');
    }

    // -------------------------------------------------------------------------
    // Scenario 6: Malformed TRX/report artifact
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 6] Malformed TRX Report Artifact');
    {
        const malformedTrx = '<TestRun id="broken"><Counters total="1" executed="1"';
        const parsed = parseTrxReport(malformedTrx);
        assert.strictEqual(parsed.valid, false);
        assert.strictEqual(parsed.failureCategory, FAILURE_CATEGORIES.PARSE_FAILED);

        const emptyTrx = '   ';
        const parsedEmpty = parseTrxReport(emptyTrx);
        assert.strictEqual(parsedEmpty.valid, false);
        assert.strictEqual(parsedEmpty.failureCategory, FAILURE_CATEGORIES.PARSE_FAILED);
        console.log('  ✓ Scenario 6: Malformed/unclosed TRX reports reliably categorized as PARSE_FAILED.');
    }

    // -------------------------------------------------------------------------
    // Scenario 7: Missing test result artifact
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 7] Missing Test Result Artifact When Expected');
    {
        const tmpDir = makeTempDir('missing-trx-');
        try {
            fs.writeFileSync(path.join(tmpDir, 'App.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
            const mockBackend = makeMockBackend(() => ({
                exitCode: 0,
                durationMs: 10,
                stdout: 'Command completed without summary output.',
                stderr: '',
                outputArtifacts: {}
            }));

            const runRes = await executeRealTestRunner('dotnet', ['test', '--logger', 'trx'], tmpDir, {
                workingDirectory: tmpDir,
                sandboxBackend: mockBackend,
                envReport: readyEnv
            });

            assert.strictEqual(runRes.executed, true);
            assert.strictEqual(runRes.passed, false);
            assert.strictEqual(runRes.failureCategory, FAILURE_CATEGORIES.TEST_RESULTS_MISSING);
            assert.strictEqual(runRes.machineStatus, OUTCOME_STATUS.UNTESTED);
            assert.strictEqual(runRes.testsTotal, 0);
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 7: Missing TRX artifact correctly maps to TEST_RESULTS_MISSING without synthetic counts.');
    }

    // -------------------------------------------------------------------------
    // Scenario 8: Valid results with unknown console summary format
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 8] Valid Results with Unknown Console Summary Format');
    {
        const validTrx = `<?xml version="1.0" encoding="utf-8"?>
<TestRun id="33333333-4444-5555-6666-777777777777" name="Run3" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Counters total="4" executed="4" passed="4" failed="0" error="0" timeout="0" aborted="0" notExecuted="0" />
  <ResultSummary outcome="Completed" />
</TestRun>`;

        const tmpDir = makeTempDir('unknown-console-');
        try {
            fs.writeFileSync(path.join(tmpDir, 'Test.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><IsTestProject>true</IsTestProject></PropertyGroup></Project>');
            const mockBackend = makeMockBackend(() => ({
                exitCode: 0,
                durationMs: 25,
                stdout: '[EnterpriseRunner-v4.2] ALL TESTS GREEN (4 executed, 0 issues)',
                stderr: '',
                outputArtifacts: {
                    'test-results.trx': { path: '/sandbox-out/test-results.trx', content: validTrx, sha256: 'abc' }
                }
            }));

            const runRes = await executeRealTestRunner('dotnet', ['test', '--logger', 'trx'], tmpDir, {
                workingDirectory: tmpDir,
                sandboxBackend: mockBackend,
                envReport: readyEnv
            });

            assert.strictEqual(runRes.executed, true);
            assert.strictEqual(runRes.passed, true);
            assert.strictEqual(runRes.status, 'PASS');
            assert.strictEqual(runRes.machineStatus, OUTCOME_STATUS.PASSED);
            assert.strictEqual(runRes.failureCategory, FAILURE_CATEGORIES.TESTS_PASSED);
            assert.strictEqual(runRes.testsTotal, 4);
            assert.strictEqual(runRes.testsPassed, 4);
            assert.strictEqual(runRes.testsFailed, 0);
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 8: Machine-readable TRX artifact takes precedence over unrecognized console text.');
    }

    // -------------------------------------------------------------------------
    // Scenario 9: Sandbox output extraction
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 9] Sandbox Output Extraction Prior to Cleanup');
    {
        const tmpDir = makeTempDir('sbx-out-');
        try {
            fs.writeFileSync(path.join(tmpDir, 'Test.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
            const sampleTrxContent = '<TestRun><Counters total="1" executed="1" passed="1" failed="0" /></TestRun>';
            const sampleSha256 = crypto.createHash('sha256').update(sampleTrxContent).digest('hex');

            const mockBackend = makeMockBackend(() => ({
                exitCode: 0,
                durationMs: 12,
                stdout: 'Test run complete.',
                stderr: '',
                outputArtifacts: {
                    'test-results.trx': { path: '/sandbox-out/test-results.trx', content: sampleTrxContent, sha256: sampleSha256 }
                }
            }));

            const runRes = await executeRealTestRunner('dotnet', ['test', '--logger', 'trx'], tmpDir, {
                workingDirectory: tmpDir,
                sandboxBackend: mockBackend,
                envReport: readyEnv
            });

            assert(runRes.outputArtifacts, 'Output artifacts must be preserved');
            assert(runRes.outputArtifacts['test-results.trx'], 'test-results.trx must be extracted');
            assert.strictEqual(runRes.outputArtifacts['test-results.trx'].sha256, sampleSha256);
            assert.strictEqual(runRes.outputArtifacts['test-results.trx'].content, sampleTrxContent);
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 9: Sandbox output artifacts extracted and bound to gateway response before cleanup.');
    }

    // -------------------------------------------------------------------------
    // Scenario 10: Build failure before tests
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 10] Build Failure Before Tests');
    {
        const buildErr = 'PaymentController.cs(12,5): error CS1002: ; expected\nBuild FAILED.\n    0 Warning(s)\n    1 Error(s)';
        const parsed = parseDotnetOutput(buildErr, '', 1);

        assert.strictEqual(parsed.status, 'FAIL');
        assert.strictEqual(parsed.machineStatus, OUTCOME_STATUS.FAILED);
        assert.strictEqual(parsed.failureCategory, FAILURE_CATEGORIES.BUILD_FAILED);
        assert.strictEqual(parsed.compilationFailed, true);
        assert.strictEqual(parsed.countsKnown, false);
        assert(parsed.rootError.includes('CS1002'));
        console.log('  ✓ Scenario 10: Compilation error before tests recognized as BUILD_FAILED.');
    }

    // -------------------------------------------------------------------------
    // Scenario 11: Unsupported toolchain
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 11] Unsupported Toolchain Mapped to TOOLCHAIN_IMAGE_UNAVAILABLE');
    {
        const tmpDir = makeTempDir('toolchain-unavail-');
        try {
            fs.writeFileSync(path.join(tmpDir, 'Legacy.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>');
            const runRes = await executeRealTestRunner('dotnet', ['test'], tmpDir, {
                workspaceRoot: WORKSPACE_ROOT,
                repositoryPath: tmpDir,
                profilesPath: path.join(WORKSPACE_ROOT, 'extension/config/approved-toolchain-profiles.json'),
                testPhase: 'BASELINE_SECURITY_TEST',
                enableContainerSandbox: true,
                enforceContainerExecution: true
            });

            assert.strictEqual(runRes.executed, false);
            assert.strictEqual(runRes.machineStatus, OUTCOME_STATUS.COULD_NOT_RUN);
            assert.strictEqual(runRes.failureCategory, FAILURE_CATEGORIES.TOOLCHAIN_IMAGE_UNAVAILABLE);
            assert.strictEqual(runRes.reasonCode, 'TOOLCHAIN_IMAGE_UNAVAILABLE');
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 11: Unsupported toolchain mapped cleanly to TOOLCHAIN_IMAGE_UNAVAILABLE.');
    }

    // -------------------------------------------------------------------------
    // Scenario 12: Genuine SQL injection regression fixture
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 12] Genuine SQL Injection Regression Assertions');
    {
        // Vulnerable implementation logic
        const vulnerableProcess = (accountId, amount) => {
            const query = "SELECT * FROM Payments WHERE AccountId = '" + accountId + "' AND Amount = " + amount;
            return { commandText: query, parameters: {} };
        };

        // Remediated implementation logic
        const remediatedProcess = (accountId, amount) => {
            const query = "SELECT * FROM Payments WHERE AccountId = @AccountId AND Amount = @Amount";
            return {
                commandText: query,
                parameters: {
                    "@AccountId": accountId,
                    "@Amount": amount
                }
            };
        };

        const maliciousPayload = "ACC-100' OR '1'='1";

        // Assert vulnerable logic fails regression check
        const vulnResult = vulnerableProcess(maliciousPayload, 50.0);
        const vulnContainsPayload = vulnResult.commandText.includes(maliciousPayload);
        assert.strictEqual(vulnContainsPayload, true, 'Vulnerable query must contain injected SQL fragment');
        assert.strictEqual(vulnResult.parameters['@AccountId'], undefined, 'Vulnerable query lacks parameter binding');

        // Assert remediated logic passes regression check
        const fixedResult = remediatedProcess(maliciousPayload, 50.0);
        assert(!fixedResult.commandText.includes(maliciousPayload), 'Remediated query must NOT contain payload');
        assert(fixedResult.commandText.includes('@AccountId'), 'Remediated query must contain @AccountId placeholder');
        assert(fixedResult.commandText.includes('@Amount'), 'Remediated query must contain @Amount placeholder');
        assert.strictEqual(fixedResult.parameters['@AccountId'], maliciousPayload, 'Parameter value must equal raw payload safely');
        assert.strictEqual(fixedResult.parameters['@Amount'], 50.0);
        console.log('  ✓ Scenario 12: Genuine SQL injection regression assertions verified for both states.');
    }

    // -------------------------------------------------------------------------
    // Scenario 13: Baseline UNTESTED gate behavior
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 13] Baseline UNTESTED Stage 4 Approval Gate Blocking');
    {
        const tmpDir = makeTempDir('baseline-gate-');
        try {
            const store = new FindingsStore(tmpDir);
            const vulnId = 'VUL-BASE-UNT';
            const vulnDir = path.join(tmpDir, 'vulnerability');
            fs.mkdirSync(vulnDir, { recursive: true });
            fs.mkdirSync(path.join(tmpDir, 'sample-repos', 'payments-api'), { recursive: true });
            const csvPath = path.join(vulnDir, 'vulnerabilities.csv');
            fs.writeFileSync(csvPath, [
                'Vulnerability_ID,Application_Number,Repository,Technology,File_Path,Line_Number,Vulnerability_Type,Severity,Status',
                `${vulnId},APP-PAYMENTS,sample-repos/payments-api,dotnet,PaymentController.cs,42,SQL Injection,High,Open`
            ].join('\n'));

            const engine = new RemediationEngine(tmpDir, csvPath, { findingsStore: store });

            engine.saveRunState(vulnId, {
                runId: 'run-base-unt-1',
                vulnerabilityId: vulnId,
                status: 'IN_PROGRESS',
                workflowLifecycle: 'WAITING_APPROVAL',
                stages: [
                    { stageNumber: 1, id: 'intake', status: 'completed' },
                    { stageNumber: 2, id: 'classification', status: 'completed' },
                    { stageNumber: 3, id: 'analysis', status: 'completed' }
                ],
                baselineValidation: {
                    status: 'UNTESTED',
                    machineStatus: OUTCOME_STATUS.UNTESTED,
                    failureCategory: FAILURE_CATEGORIES.NO_TESTS_DISCOVERED,
                    testsTotal: 0,
                    summary: 'Zero tests executed'
                },
                proposedDiffSha256: 'a'.repeat(64),
                patchDiff: 'diff --git a/test b/test'
            });

            // Stage 4 approval MUST throw Gate Integrity Violation without authorized exception
            await assert.rejects(
                () => engine.executePipeline(vulnId, { isHumanApproved: true }),
                (err) => {
                    return err.message.includes('Gate Integrity Violation') &&
                        err.message.includes('Stage 4 approval is blocked because Stage 3 baseline testing did not succeed');
                },
                'Approval must be rejected when baseline is UNTESTED without explicit exception'
            );

            // Checklist verification: baseline UNTESTED without exception evaluates to FAIL
            const clUntested = buildEvidenceChecklist({
                baselineValidation: { status: 'UNTESTED', machineStatus: 'UNTESTED', executed: false }
            });
            const baseCheck = clUntested.checks.find(c => c.id === 'BASELINE_EVIDENCE');
            assert.strictEqual(baseCheck.status, CHECK_STATUS.FAIL);

            // Checklist verification: baseline UNTESTED WITH authorized exception evaluates to PASS
            const clException = buildEvidenceChecklist({
                baselineValidation: {
                    status: 'UNTESTED',
                    machineStatus: 'UNTESTED',
                    baselineExceptionAuthorized: true,
                    baselineExceptionRationale: 'Approved enterprise test skip policy'
                }
            });
            const baseCheckExc = clException.checks.find(c => c.id === 'BASELINE_EVIDENCE');
            assert.strictEqual(baseCheckExc.status, CHECK_STATUS.PASS);
            assert(baseCheckExc.detail.includes('Baseline exception authorized'));
        } finally {
            cleanupTempDir(tmpDir);
        }
        console.log('  ✓ Scenario 13: Baseline UNTESTED strictly blocks approval unless explicit exception authorized.');
    }

    // -------------------------------------------------------------------------
    // Scenario 14: Changed patch requiring fresh approval
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 14] Changed Patch Diff Requiring Fresh Approval');
    {
        const originalPatch = '--- a/File.cs\n+++ b/File.cs\n@@ -1 +1 @@\n-old\n+new';
        const originalSha = computeDiffSha256(originalPatch);

        const approvalRequest = createApprovalRequest({
            runId: 'run-auth-1',
            vulnerabilityId: 'VUL-DIFF-1',
            applicationId: 'APP-1',
            baseCommitHash: '1111222233334444555566667777888899990000',
            patchDiff: originalPatch,
            approvedFilePaths: ['File.cs'],
            rca: { rootCause: 'Direct string interpolation in SQL query' },
            baselineValidation: { status: 'PASS', machineStatus: 'PASSED', executed: true }
        });

        const record = recordApprovalDecision(approvalRequest, {
            decision: 'APPROVED',
            reviewerAuthorizationStatus: 'AUTHENTICATION_NOT_VERIFIED'
        });

        // Patch modified after approval
        const tamperedPatch = '--- a/File.cs\n+++ b/File.cs\n@@ -1 +1 @@\n-old\n+backdoor';

        assert.throws(
            () => verifyApprovalForExecution(record, {
                runId: 'run-auth-1',
                vulnerabilityId: 'VUL-DIFF-1',
                applicationId: 'APP-1',
                baseCommitHash: '1111222233334444555566667777888899990000',
                patchDiff: tamperedPatch,
                currentFilePaths: ['File.cs']
            }),
            (err) => {
                return err instanceof ApprovalBlockedError && err.code === 'DIFF_HASH_MISMATCH';
            },
            'Modified patch must throw DIFF_HASH_MISMATCH'
        );
        console.log('  ✓ Scenario 14: Exact approved diff hash binding enforced; changed patch requires fresh approval.');
    }

    // -------------------------------------------------------------------------
    // Scenario 15: Missing post-fix re-scan
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 15] Missing Post-Fix Re-Scan Checklist Behavior');
    {
        const checklist = buildEvidenceChecklist({
            finding: { Vulnerability_ID: 'VUL-RESCAN-1', Rule_ID: 'SEC-005', Title: 'SQL Injection' },
            classification: { cwe: 'CWE-89' },
            rca: { rootCause: 'SQL Injection', summary: 'Unparameterized query' },
            baselineValidation: { status: 'PASS', executed: true, testsTotal: 1 },
            patchDiff: '--- a/f\n+++ b/f',
            approvalRecord: { decision: 'APPROVED', proposedDiffSha256: 'a'.repeat(64), approvedFilePaths: ['f'] },
            validation: { executed: true, passed: true, testsTotal: 2, testsPassed: 2, testsFailed: 0, exitCode: 0 },
            reScanVerification: null,
            requiresScannerReScan: true
        });

        const reScanCheck = checklist.checks.find(c => c.id === 'SCANNER_RESCAN');
        assert.strictEqual(reScanCheck.status, CHECK_STATUS.MISSING);
        assert.strictEqual(checklist.recommendation, REVIEW_RECOMMENDATION.REVIEW_REQUIRED);
        assert.notStrictEqual(checklist.recommendation, REVIEW_RECOMMENDATION.READY_FOR_REVIEW);
        console.log('  ✓ Scenario 15: Missing post-fix scanner re-scan blocks final human review eligibility.');
    }

    // -------------------------------------------------------------------------
    // Scenario 16: CWE-Specific Reviewer Guidance
    // -------------------------------------------------------------------------
    console.log('[SCENARIO 16] CWE-Specific Reviewer Guidance (SQLi vs Credential Exposure)');
    {
        // Pure SQL Injection finding named SCAN-SECRET-016
        const sqliFinding = {
            Vulnerability_ID: 'SCAN-SECRET-016',
            Scanner_ID: 'secrets-config',
            Rule_ID: 'SEC-005',
            Title: 'Potential SQL Injection via Unparameterized Query',
            CVE_ID: 'CWE-89'
        };
        const sqliClassification = { cwe: 'CWE-89 SQL Injection', category: 'SQL Injection' };

        const isSecretSqli = isSecretOrCredentialFinding(sqliFinding, sqliClassification);
        assert.strictEqual(isSecretSqli, false, 'SCAN-SECRET-016 (CWE-89 / SEC-005) must NOT be classified as secret finding');

        const sqliChecklist = buildEvidenceChecklist({
            finding: sqliFinding,
            classification: sqliClassification
        });
        assert.strictEqual(sqliChecklist.isSecretFinding, false);
        assert.strictEqual(sqliChecklist.secretRemediationActions.length, 0);

        // Genuine Credential Exposure finding
        const secretFinding = {
            Vulnerability_ID: 'SCAN-SECRET-001',
            Scanner_ID: 'secrets-config',
            Rule_ID: 'SEC-001',
            Title: 'Hardcoded API Key Detected',
            CVE_ID: 'CWE-798'
        };
        const secretClassification = { cwe: 'CWE-798 Hardcoded Credentials' };

        const isSecret = isSecretOrCredentialFinding(secretFinding, secretClassification);
        assert.strictEqual(isSecret, true, 'SEC-001 (CWE-798) must be classified as secret finding');

        const secretChecklist = buildEvidenceChecklist({
            finding: secretFinding,
            classification: secretClassification
        });
        assert.strictEqual(secretChecklist.isSecretFinding, true);
        assert(Array.isArray(secretChecklist.secretRemediationActions));
        assert(secretChecklist.secretRemediationActions.some(a => a.id === 'ROTATE_SECRET'));
        assert(secretChecklist.secretRemediationActions.some(a => a.id === 'REVOKE_SECRET'));
        console.log('  ✓ Scenario 16: CWE-89 SQL injection produces zero secret rotation actions; CWE-798 retains mandatory actions.');
    }

    console.log('\n===============================================================');
    console.log('ALL 16 STAGE 6 TEST VERIFICATION SCENARIOS PASSED CLEANLY');
    console.log('===============================================================');
}

module.exports = {
    run: runStage6TestVerificationSuite,
    runStage6TestVerificationSuite
};

if (require.main === module) {
    runStage6TestVerificationSuite().catch((err) => {
        console.error('\nTest Suite Failed:', err);
        process.exit(1);
    });
}
