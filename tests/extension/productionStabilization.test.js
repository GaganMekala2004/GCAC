'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '../..');

const { ScanController } = require('../../extension/scanning/scanController');
const { FindingsStore } = require('../../extension/scanning/findingsStore');
const { ScanCache } = require('../../extension/scanning/scanCache');
const { SecretsConfigScanner } = require('../../extension/scanning/adapters/secretsConfigScanner');
const { CodeQLScanner } = require('../../extension/scanning/adapters/codeqlScanner');
const { NormalizedFinding, SCANNER_STATUS } = require('../../extension/scanning/findingModel');
const { SANDBOX_READINESS } = require('../../extension/sandbox/environmentDiscovery');
const { OUTCOME_STATUS } = require('../../extension/outcomeContract');
const { RemediationEngine } = require('../../extension/remediationEngine');
const { loadVulnerabilityDetails } = require('../../extension/reportParser');
const { parseDotnetOutput, FAILURE_CATEGORIES } = require('../../extension/testRunner');
const {
    RunStateManager,
    RUN_STATE_SCHEMA_VERSION,
    WORKFLOW_LIFECYCLE,
    VALIDATION_OUTCOME,
    APPROVAL_DECISION,
    FORMAL_CLOSURE,
    FINDING_STATE,
    buildRunEvent
} = require('../../extension/runStateContract');
const {
    buildEvidenceChecklist,
    CHECK_STATUS,
    REVIEW_RECOMMENDATION
} = require('../../extension/evidenceChecklist');
const {
    EMOJI_AND_DECORATIVE_REGEX,
    formatHelpMarkdown,
    formatRunHeaderMarkdown,
    formatStageEventMarkdown,
    formatGateMarkdown,
    formatTerminalConclusionMarkdown,
    formatErrorMarkdown
} = require('../../extension/copilotOutputFormatter');
const { ReScanVerifier } = require('../../extension/scanning/reScanVerifier');
const { ALLOWED_IPC_COMMANDS, validateWebviewMessage } = require('../../extension/extension');
const dashboardHelpers = require('../../extension/media/dashboard');
const { server: previewServer } = require('../../scripts/preview-dashboard');

function initGitRepo(dir, files = {}) {
    fs.mkdirSync(dir, { recursive: true });
    for (const [rel, content] of Object.entries(files)) {
        const full = path.join(dir, rel);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content, 'utf8');
    }
    execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'test@gcac.local'], { cwd: dir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.name', 'GCAC Test'], { cwd: dir, stdio: 'ignore' });
    execFileSync('git', ['add', '-A'], { cwd: dir, stdio: 'ignore' });
    execFileSync('git', ['commit', '-m', 'Initial fixture'], { cwd: dir, stdio: 'ignore' });
    return dir;
}

function makeReadySandboxBackend(execBehavior) {
    return {
        backendType: 'local-container',
        checkAvailability: async () => ({
            available: true,
            status: SANDBOX_READINESS.SANDBOX_READY,
            backendType: 'local-container',
            runtime: 'docker',
            architecture: 'x64',
            linuxContainerMode: true,
            enforcedBoundaries: ['No network']
        }),
        validatePolicy: () => ({ valid: true }),
        prepareEnvironment: async (req) => ({ instanceId: req.instanceId, workDir: req.approvedWorkspaceReference, staged: {} }),
        executeApprovedOperation: async (req, operation) => execBehavior(req, operation),
        cancelOperation: async () => ({ cancelled: true }),
        collectEvidence: async () => ({}),
        cleanup: async () => ({ cleaned: true })
    };
}

function makeReadyEnvReport() {
    return {
        sandboxAvailable: true,
        sandboxStatus: SANDBOX_READINESS.SANDBOX_READY,
        selectedRuntime: 'docker',
        os: { platform: 'linux', arch: 'x64' },
        containers: { docker: { installed: true, daemonReachable: true }, podman: { installed: false, daemonReachable: false } },
        toolchains: { dotnet: { installed: true, activeVersion: '9.0.100' } }
    };
}

function httpGet(port, pathname) {
    return new Promise((resolve, reject) => {
        http.get({ hostname: '127.0.0.1', port, path: pathname }, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({ statusCode: res.statusCode, body }));
        }).on('error', reject);
    });
}

async function run() {
    console.log('[TEST SUITE] Production Workflow Stabilization & Reliability Tests');
    const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-stab-'));

    try {
        // =====================================================================
        // A. SCANNER PERFORMANCE, MODES, CACHE, CANCELLATION & TIMEOUTS
        // =====================================================================
        {
            const storeDir = path.join(tmpBase, 'scan-store');
            const store = new FindingsStore(tmpBase, storeDir);
            const ctrl = new ScanController(tmpBase, {
                findingsStore: store,
                authorizedRoots: [tmpBase]
            });

            // A1: Empty repository handled honestly
            const emptyRepo = path.join(tmpBase, 'empty-repo');
            fs.mkdirSync(emptyRepo, { recursive: true });
            const emptyRes = await ctrl.startScan({ targetRepo: emptyRepo, mode: 'quick' });
            assert.strictEqual(emptyRes.status, 'No Scannable Inputs');
            assert.strictEqual(emptyRes.noScannableInputs, true);
            assert.strictEqual(emptyRes.newFindings.length, 0);

            // A2: Quick vs Comprehensive mode disclosure & cache behavior
            const repoA = initGitRepo(path.join(tmpBase, 'repo-a'), {
                'Config/appsettings.json': JSON.stringify({ ApiKey: ['sk', 'live', 'FakeTestSecret9876543210'].join('_') }),
                'Program.cs': 'public class Program { public static void Main() {} }\n'
            });
            const quickRes = await ctrl.startScan({ targetRepo: repoA, mode: 'quick' });
            assert.strictEqual(quickRes.scanMode, 'quick');
            assert.strictEqual(quickRes.scannersExecuted, 1);
            assert(quickRes.omittedScanners.includes('dotnet-security'));
            assert(quickRes.coverageDisclosure.includes('not equivalent to a comprehensive'));
            assert.strictEqual(quickRes.fromCache, false);
            assert(quickRes.metrics && typeof quickRes.metrics.totalMs === 'number');

            // Second quick scan hits verified cache
            const quickCached = await ctrl.startScan({ targetRepo: repoA, mode: 'quick' });
            assert.strictEqual(quickCached.fromCache, true);
            assert.strictEqual(quickCached.cacheHits, 1);
            assert.strictEqual(quickCached.scannerResults[0].fromCache, true);
            assert.strictEqual(quickCached.scannerResults[0].freshnessStatus, 'CACHED_SOURCE_HASH_VERIFIED');
            assert.strictEqual(quickCached.newFindings.length, quickRes.newFindings.length);

            // Modify vulnerable source file -> cache invalidates immediately
            fs.writeFileSync(
                path.join(repoA, 'Program.cs'),
                'using System.Security.Cryptography;\npublic class Program { public static void Main() { var c = DES.Create(); } }\n',
                'utf8'
            );
            const quickAfterEdit = await ctrl.startScan({ targetRepo: repoA, mode: 'quick' });
            assert.strictEqual(quickAfterEdit.fromCache, false);
            assert.strictEqual(quickAfterEdit.cacheMisses, 1);
            assert(quickAfterEdit.newFindings.length >= 2, 'Modified vulnerable source file must invalidate cache and re-scan');

            // Different repository cannot receive Repo A's cached results even with identical file content
            const repoB = initGitRepo(path.join(tmpBase, 'repo-b'), {
                'Config/appsettings.json': fs.readFileSync(path.join(repoA, 'Config/appsettings.json'), 'utf8'),
                'Program.cs': 'public class Program { public static void Main() {} }\n'
            });
            const repoBRes = await ctrl.startScan({ targetRepo: repoB, mode: 'quick' });
            assert.strictEqual(repoBRes.fromCache, false, 'Different canonicalRepositoryId must never reuse cache from Repo A');

            // Expired NuGet advisory TTL cannot return cached hit
            const advCache = new ScanCache(path.join(tmpBase, 'adv-cache'), { advisoryTtlMs: 100 });
            const advDesc = {
                canonicalRepositoryId: 'repo-adv',
                targetRelativePath: '.',
                inputHash: 'abc',
                scannerId: 'nuget-audit',
                scannerVersion: '8.0.0'
            };
            advCache.set(advDesc, { status: SCANNER_STATUS.COMPLETED, findings: [] });
            const freshAdv = advCache.get(advDesc, { nowMs: Date.now() + 50 });
            const staleAdv = advCache.get(advDesc, { nowMs: Date.now() + 5000 });
            assert.strictEqual(freshAdv.hit, true);
            assert.strictEqual(staleAdv.hit, false);
            assert.strictEqual(staleAdv.reason, 'ADVISORY_DATA_EXPIRED');

            // Missing scanner reports unavailable cleanly
            const missingCodeql = new CodeQLScanner({ workspaceRoot: tmpBase });
            const origCodeqlEnv = process.env.CODEQL_PATH;
            process.env.CODEQL_PATH = path.join(tmpBase, 'nonexistent-codeql');
            missingCodeql._findCodeqlBinary = () => null;
            const missAvail = await missingCodeql.isAvailable(tmpBase);
            assert.strictEqual(missAvail.available, false);
            if (origCodeqlEnv !== undefined) process.env.CODEQL_PATH = origCodeqlEnv;
            else delete process.env.CODEQL_PATH;

            // Async CodeQL subprocess cancellation & timeout terminate child process
            const slowScript = path.join(tmpBase, 'slow-child.js');
            fs.writeFileSync(slowScript, 'setTimeout(() => {}, 10000);', 'utf8');
            const cancelScanner = new CodeQLScanner({ workspaceRoot: tmpBase });
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 80);
            await assert.rejects(
                () => cancelScanner._execCodeqlAsync(process.execPath, [slowScript], { abortSignal: ac.signal, timeout: 5000 }),
                /SCAN_CANCELLED/
            );
            assert.strictEqual(cancelScanner.activeProcess, null, 'Cancelled subprocess handle must be cleaned up');

            const timeoutScanner = new CodeQLScanner({ workspaceRoot: tmpBase });
            await assert.rejects(
                () => timeoutScanner._execCodeqlAsync(process.execPath, [slowScript], { timeout: 100 }),
                /ETIMEDOUT/
            );
            assert.strictEqual(timeoutScanner.activeProcess, null, 'Timed-out subprocess handle must be cleaned up');

            // Indeterminate progress on SCAN_STARTED (no fake 5% jump)
            const startedProg = dashboardHelpers.normalizeScanProgressEvent({ type: 'SCAN_STARTED', scanMode: 'quick' });
            assert.strictEqual(startedProg.indeterminate, true);
            assert.strictEqual(startedProg.percent, null);
            const fileProg = dashboardHelpers.normalizeScanProgressEvent({
                type: 'SCANNER_FILE_PROGRESS',
                scannerName: 'Secrets & Config',
                filesScanned: 50,
                totalEligibleFiles: 200
            });
            assert.strictEqual(fileProg.indeterminate, false);
            assert.strictEqual(fileProg.percent, 25);

            console.log('  ✓ Workstream A: Quick/Comprehensive modes, hash/repo-bound cache, TTL, cancel, timeout & progress verified');
        }

        // =====================================================================
        // B & E. SCAN-SECRET-005 BUILD FAILURE, SYNC, STAGE 8 BLOCKING & NO 40/100
        // =====================================================================
        {
            const sbxWs = initGitRepo(path.join(tmpBase, 'sec005-ws'), {
                'src/PaymentsAPI/Controllers/ReceiptController.cs': 'public class ReceiptController { private const string ApiKey = "' + ['sk', 'live', 'TestSecretValue123456'].join('_') + '"; }\n',
                'src/PaymentsAPI/Controllers/PaymentController.cs': 'using System.Data.SqlClient;\npublic class PaymentController { SqlCommand _cmd; }\n',
                'src/PaymentsAPI/PaymentsAPI.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><IsTestProject>true</IsTestProject></PropertyGroup></Project>'
            });
            const storeDir = path.join(sbxWs, 'output', 'scans');
            const fStore = new FindingsStore(sbxWs, storeDir);
            fStore.saveFindings([new NormalizedFinding({
                findingId: 'SCAN-SECRET-005',
                scanId: 'SCAN-005',
                scannerId: 'secrets-config',
                ruleId: 'SEC-001',
                title: 'Hardcoded Secret API Key in ReceiptController',
                description: 'Hardcoded secret API key detected in C# source code.',
                severity: 'Critical',
                cwe: 'CWE-798',
                filePath: 'src/PaymentsAPI/Controllers/ReceiptController.cs',
                line: 1,
                repository: sbxWs,
                repositoryRoot: sbxWs,
                applicationNumber: 'LOCAL-SEC005',
                applicationName: 'PaymentsAPI',
                technology: 'dotnet'
            })]);

            const buildFailOutput = [
                '  Determining projects to restore...',
                '/src/PaymentsAPI/Controllers/PaymentController.cs(16,29): error CS1069: The type name \'SqlCommand\' could not be found in the namespace \'System.Data.SqlClient\'.',
                'Build FAILED.',
                '    0 Warning(s)',
                '    1 Error(s)'
            ].join('\n');

            // Verify testRunner parses CS1069 accurately (0/0 tests + BUILD_FAILED, countsKnown: false)
            const parsedCs1069 = parseDotnetOutput(buildFailOutput, '', 1);
            assert.strictEqual(parsedCs1069.machineStatus, OUTCOME_STATUS.FAILED);
            assert.strictEqual(parsedCs1069.failureCategory, FAILURE_CATEGORIES.BUILD_FAILED);
            assert.strictEqual(parsedCs1069.countsKnown, false);
            assert(parsedCs1069.rootError.includes('CS1069'));

            const readyEnv = makeReadyEnvReport();
            let baselineInvocation = true;
            const backend = makeReadySandboxBackend((environment, operation) => {
                if (operation?.operation === 'DOTNET_BUILD') return { exitCode: 0, stdout: 'Build succeeded.', stderr: '', durationMs: 10 };
                if (baselineInvocation) {
                    baselineInvocation = false;
                    return { exitCode: 0, durationMs: 30, stdout: 'Passed! - Failed: 0, Passed: 1, Skipped: 0, Total: 1', stderr: '' };
                }
                return { exitCode: 1,
                durationMs: 30,
                stdout: buildFailOutput,
                stderr: ''
            };
            });
            const mockLlm = {
                getAvailableModels: async () => [{ id: 'copilot-gpt', name: 'Mock Copilot', vendor: 'copilot' }],
                generateJson: async (p) => {
                    if (p.includes('Classification Agent')) return { cwe: 'CWE-798', severity: 'Critical', route: 'SpecializedAction', strategy: 'Externalize secret', summary: 'Hardcoded secret' };
                    if (p.includes('Root Cause Analysis')) return { dataFlow: 'Literal key in class', rootCause: 'Plaintext secret', securityImpact: 'Credential exposure', proposedFix: 'Load from environment', affectedLines: 'Line 1', summary: 'Externalize secret' };
                    return { rating: 'FAIL', score: 40, summary: 'Validation failed due to CS1069 compilation failure.', auditChecks: ['Build failed CS1069'] };
                },
                generateCompletion: async () => JSON.stringify({ edits: [{
                    oldText: 'public class ReceiptController { private const string ApiKey = "<GCAC_REDACTED_1>"; }',
                    newText: 'public class ReceiptController { private string ApiKey => System.Environment.GetEnvironmentVariable("RECEIPT_API_KEY") ?? ""; }'
                }] })
            };

            const events = [];
            const engine = new RemediationEngine(sbxWs, null, {
                findingsStore: fStore,
                reScanVerifier: new ReScanVerifier(sbxWs, { scanners: new Map([['secrets-config', new SecretsConfigScanner()]]) }),
                llmClient: mockLlm,
                sandboxBackend: backend,
                envReport: readyEnv,
                authorizedRoots: [sbxWs],
                runsRoot: path.join(tmpBase, 'sec005-runs')
            });

            // A compiler failure in the baseline must stop before patch approval.
            baselineInvocation = false;
            await assert.rejects(() => engine.executePipeline('SCAN-SECRET-005', {
                onProgress: (event) => events.push(event)
            }), /BLOCKED \(BaselineTest\).*CS1069/);
            const blockedBaseline = engine.loadRunState('SCAN-SECRET-005');
            assert.strictEqual(blockedBaseline.status, 'BLOCKED');
            assert.strictEqual(blockedBaseline.stages[3].status, 'blocked_by_prerequisite');
            assert.strictEqual(blockedBaseline.securityValidationOutcome, 'NOT_EXECUTED');
            assert.strictEqual(blockedBaseline.proposedDiffSha256, null);
            assert(events.some(event => event.type === 'STAGE_BLOCKED' && event.stageNumber === 3));
            assert(events.some(event => event.type === 'WORKFLOW_FAILED' && event.executionState === 'BLOCKED'));
            baselineInvocation = true;

            // Stage 1-4 pause with an eligible baseline from the mock backend.
            const gate4Pause = await engine.executePipeline('SCAN-SECRET-005', {
                onProgress: (e) => events.push(e)
            });
            assert.strictEqual(gate4Pause.isAwaitingApproval, true);
            assert.strictEqual(gate4Pause.stage, 4);
            const gateMarkdown = formatGateMarkdown('SCAN-SECRET-005', gate4Pause);
            assert(gateMarkdown.includes('/approve SCAN-SECRET-005'), 'An eligible JSON proposal must expose the chat approval command');
            assert(require('../../extension/evidenceLedger').verifyEvidencePackage(path.join(sbxWs, 'remediation-output', 'SCAN-SECRET-005')).verified,
                'Stage 4 evidence must remain verified after state persistence');

            // Stage 4 approve -> Stage 5-9 concludes with Validation Failed & Stage 8 BLOCKED!
            const failedConcluded = await engine.executePipeline('SCAN-SECRET-005', {
                isHumanApproved: true,
                allowBaselineException: true,
                baselineExceptionRationale: 'Harness test with documented baseline exception',
                onProgress: (e) => events.push(e)
            });

            assert.strictEqual(failedConcluded.isAwaitingFinalApproval, false, 'Failed validation must NOT present Stage 8 sign-off');
            assert.strictEqual(failedConcluded.finalGateBlocked, true);
            assert.strictEqual(failedConcluded.isCompleted, false);
            assert.strictEqual(failedConcluded.isResolved, false);
            assert.strictEqual(failedConcluded.workflowLifecycle, WORKFLOW_LIFECYCLE.COMPLETED);
            assert.strictEqual(failedConcluded.securityValidationOutcome, VALIDATION_OUTCOME.FAILED);
            assert.strictEqual(failedConcluded.approvalDecision, APPROVAL_DECISION.BLOCKED_STAGE8);
            assert.strictEqual(failedConcluded.findingState, FINDING_STATE.VALIDATION_FAILED);
            assert.strictEqual(failedConcluded.terminalBanner, 'Workflow Ended — Validation Failed');
            assert.strictEqual(failedConcluded.securityReview.score, undefined, 'Must not expose arbitrary 40/100 score');
            assert.strictEqual(failedConcluded.evidenceChecklist.recommendation, REVIEW_RECOMMENDATION.BLOCKED);
            assert.strictEqual(failedConcluded.evidenceChecklist.finalReviewStatus, 'BLOCKED — Post-fix validation failed');

            // Stage 6 event MUST be terminal STAGE_FAILED (not Stage 6 active/completed)
            const stage6Evt = events.find(e => e.stageNumber === 6 && e.type === 'STAGE_FAILED');
            assert(stage6Evt, 'Stage 6 must emit terminal STAGE_FAILED event');
            assert(events.some(e => e.type === 'FINAL_GATE_BLOCKED'), 'Stage 8 must emit FINAL_GATE_BLOCKED');

            // Webview parser must reflect exact synchronized canonical state on reload
            const parsedDetails = loadVulnerabilityDetails(sbxWs, 'SCAN-SECRET-005');
            assert.strictEqual(parsedDetails.stages.length, 9);
            assert.strictEqual(parsedDetails.stages[5].id, 'bench-test');
            assert.strictEqual(parsedDetails.stages[5].status, 'failed');
            assert.strictEqual(parsedDetails.stages[7].id, 'final-human-gate');
            assert.strictEqual(parsedDetails.stages[7].status, 'blocked');
            assert.strictEqual(parsedDetails.findingState, FINDING_STATE.VALIDATION_FAILED);
            assert.strictEqual(parsedDetails.terminalBanner, 'Workflow Ended — Validation Failed');
            assert(!parsedDetails.reportMarkdown.includes('40/100'), 'Generated report must not contain 40/100 confidence score');
            assert(parsedDetails.reportMarkdown.includes('Security Review & Evidence Checklist'));
            assert(parsedDetails.reportMarkdown.includes('REVOKE_SECRET'));

            // Direct /final-approve attempt after failed validation must NOT close as RESOLVED
            const bypassFinalAttempt = await engine.executePipeline('SCAN-SECRET-005', {
                isHumanApproved: true,
                isFinalApproved: true
            });
            assert.strictEqual(bypassFinalAttempt.isCompleted, false);
            assert.strictEqual(bypassFinalAttempt.isResolved, false);
            assert.strictEqual(bypassFinalAttempt.finalGateBlocked, true);

            // Workstream F: Professional Copilot output check for failed validation
            const copilotGateMd = formatGateMarkdown('SCAN-SECRET-005', failedConcluded);
            assert.strictEqual(copilotGateMd, '', 'Blocked final gate must not emit approval prompt');
            const copilotEndMd = formatTerminalConclusionMarkdown('SCAN-SECRET-005', failedConcluded);
            assert(copilotEndMd.includes('Workflow Ended — Validation Failed'));
            assert(copilotEndMd.includes('BLOCKED'));
            assert(!copilotEndMd.includes('/final-approve'));
            assert(!copilotEndMd.includes('/100'));
            assert(!EMOJI_AND_DECORATIVE_REGEX.test(copilotEndMd), 'Copilot output must contain zero emojis');

            console.log('  ✓ Workstreams B/E/F: SCAN-SECRET-005 failed validation sync, Stage 8 blocking, zero 40/100 & professional output verified');
        }

        // =====================================================================
        // B4 & B6. COPILOT HANDOFF STATE & STALE/OUT-OF-ORDER EVENT PROTECTION
        // =====================================================================
        {
            const rsMgr = new RunStateManager(tmpBase, { outputBaseDir: path.join(tmpBase, 'rs-out') });
            const handoff = rsMgr.recordCopilotHandoff('VUL-HANDOFF-1', { repositoryId: 'repo-1', queryIssued: true });
            assert.strictEqual(handoff.state.workflowLifecycle, WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT);
            assert.strictEqual(handoff.state.findingState, FINDING_STATE.AWAITING_VERIFIED_RESULT);
            assert.strictEqual(handoff.state.stages[5].status, 'pending', 'Handoff must NOT fake Stage 6 active');

            // Apply monotonic events for run-A attempt 1
            const ev1 = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-A', findingId: 'VUL-HANDOFF-1', stageId: 'intake', stageNumber: 1,
                attemptNumber: 1, seq: 1, eventType: 'RUN_STARTED', origin: 'COPILOT_CHAT_PARTICIPANT'
            }));
            assert.strictEqual(ev1.accepted, true);

            const ev2 = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-A', findingId: 'VUL-HANDOFF-1', stageId: 'bench-test', stageNumber: 6,
                attemptNumber: 1, seq: 2, eventType: 'STAGE_START'
            }));
            assert.strictEqual(ev2.accepted, true);

            // Reject duplicate eventId / non-monotonic seq
            const dupEvt = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-A', findingId: 'VUL-HANDOFF-1', stageId: 'bench-test', stageNumber: 6,
                attemptNumber: 1, seq: 2, eventType: 'STAGE_COMPLETE'
            }));
            assert.strictEqual(dupEvt.accepted, false);

            // Reject stale event from another runId
            const wrongRun = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-OTHER', findingId: 'VUL-HANDOFF-1', stageId: 'bench-test', stageNumber: 6,
                attemptNumber: 1, seq: 3, eventType: 'STAGE_COMPLETE'
            }));
            assert.strictEqual(wrongRun.accepted, false);
            assert.strictEqual(wrongRun.reason, 'STALE_OR_MISMATCHED_RUN_ID');

            // Advance attempt to Attempt 2, then reject late event from Attempt 1 even with high seq
            const att2 = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-A', findingId: 'VUL-HANDOFF-1', stageId: 'bench-test', stageNumber: 6,
                attemptNumber: 2, seq: 1, eventType: 'STAGE_START'
            }));
            assert.strictEqual(att2.accepted, true);
            const lateAtt1 = rsMgr.applyEvent('VUL-HANDOFF-1', buildRunEvent({
                runId: 'RUN-A', findingId: 'VUL-HANDOFF-1', stageId: 'bench-test', stageNumber: 6,
                attemptNumber: 1, seq: 99, eventType: 'STAGE_COMPLETE'
            }));
            assert.strictEqual(lateAtt1.accepted, false);
            assert.strictEqual(lateAtt1.reason, 'STALE_ATTEMPT_EVENT');

            console.log('  ✓ Workstream B4/B6: Copilot handoff honesty & run/attempt/seq ordering guards verified');
        }

        // =====================================================================
        // C. RETRY STAGE NEGATIVE CHECKS & MISSING WORKTREE / EXPIRED APPROVAL
        // =====================================================================
        {
            const retryRepo = initGitRepo(path.join(tmpBase, 'retry-neg'), {
                'App.cs': 'public class App {}',
                'App.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><IsTestProject>true</IsTestProject></PropertyGroup></Project>'
            });
            fs.mkdirSync(path.join(retryRepo, 'vulnerability'), { recursive: true });
            const csvPath = path.join(retryRepo, 'vulnerability', 'vulnerabilities.csv');
            fs.writeFileSync(csvPath, 'Vulnerability_ID,Application_Number,Application_Name,Title,Severity,Technology,Repository,Location_Path\nVUL-NEG-1,APP-N1,NegApp,Test Finding,High,dotnet,.,App.cs\n', 'utf8');

            const eng = new RemediationEngine(retryRepo, csvPath, {
                authorizedRoots: [retryRepo],
                sandboxBackend: makeReadySandboxBackend(() => ({ exitCode: 0, durationMs: 5, stdout: 'Passed! - Failed: 0, Passed: 1, Skipped: 0, Total: 1', stderr: '' })),
                envReport: makeReadyEnvReport()
            });

            // Missing worktree blocks Stage 6 retry cleanly
            const deletedWt = path.join(tmpBase, 'missing-worktree-dir');
            eng.saveRunState('VUL-NEG-1', {
                runId: 'run-neg-1',
                vulnerabilityId: 'VUL-NEG-1',
                applicationNumber: 'APP-N1',
                stage: 6,
                failedStage: 6,
                status: 'FAILED',
                failureCategory: 'TIMED_OUT',
                stage4Approved: true,
                approvalRecord: { decision: 'APPROVED', expiresAt: new Date(Date.now() + 60000).toISOString() },
                isolatedWorkspace: { worktreeDir: deletedWt },
                findingContext: { applicationId: 'APP-N1', repositoryPath: retryRepo }
            });
            const wtCheck = eng.evaluateRetryEligibility('VUL-NEG-1', { targetStage: 6 });
            assert.strictEqual(wtCheck.retryEligible, false);
            assert.strictEqual(wtCheck.reasonCode, 'WORKTREE_MISSING');
            assert.strictEqual(wtCheck.canReviseFix, true);

            // Expired Stage 4 approval blocks Stage 6 retry cleanly
            fs.mkdirSync(deletedWt, { recursive: true });
            eng.saveRunState('VUL-NEG-1', {
                runId: 'run-neg-1',
                vulnerabilityId: 'VUL-NEG-1',
                applicationNumber: 'APP-N1',
                stage: 6,
                failedStage: 6,
                status: 'FAILED',
                failureCategory: 'TIMED_OUT',
                stage4Approved: true,
                approvalRecord: { decision: 'APPROVED', expiresAt: new Date(Date.now() - 60000).toISOString() },
                isolatedWorkspace: { worktreeDir: deletedWt },
                findingContext: { applicationId: 'APP-N1', repositoryPath: retryRepo }
            });
            const expCheck = eng.evaluateRetryEligibility('VUL-NEG-1', { targetStage: 6 });
            assert.strictEqual(expCheck.retryEligible, false);
            assert.strictEqual(expCheck.reasonCode, 'APPROVAL_EXPIRED');

            // Empty approvedFilePaths blocked
            eng.saveRunState('VUL-NEG-1', {
                runId: 'run-neg-1',
                vulnerabilityId: 'VUL-NEG-1',
                applicationNumber: 'APP-N1',
                stage: 6,
                failedStage: 6,
                status: 'FAILED',
                failureCategory: 'TIMED_OUT',
                stage4Approved: true,
                approvedFilePaths: [],
                approvalRecord: { decision: 'APPROVED', expiresAt: new Date(Date.now() + 60000).toISOString() },
                isolatedWorkspace: { worktreeDir: deletedWt },
                findingContext: { applicationId: 'APP-N1', repositoryPath: retryRepo }
            });
            const empManifest = eng.evaluateRetryEligibility('VUL-NEG-1', { targetStage: 6 });
            assert.strictEqual(empManifest.retryEligible, false);
            assert.strictEqual(empManifest.reasonCode, 'EMPTY_APPROVED_FILE_MANIFEST');

            console.log('  ✓ Workstream C: Missing worktree, expired approval & empty manifest checks verified');
        }

        // =====================================================================
        // D. FAKE EXECUTE REMOVAL & NEGATIVE IPC / PREVIEW SERVER CHECKS
        // =====================================================================
        {
            assert.strictEqual(ALLOWED_IPC_COMMANDS.has('runRemediation'), false);
            assert.strictEqual(validateWebviewMessage({ command: 'runRemediation', vulnerabilityId: 'SCAN-SECRET-005' }).valid, false);
            assert.strictEqual(validateWebviewMessage({ command: 'launchCopilot', vulnerabilityId: 'SCAN-SECRET-005' }).valid, true);
            assert.strictEqual(validateWebviewMessage({ command: 'syncRunState', vulnerabilityId: 'SCAN-SECRET-005' }).valid, true);

            const dashHtml = fs.readFileSync(path.join(REPO_ROOT, 'extension/media/dashboard.html'), 'utf8');
            const dashJs = fs.readFileSync(path.join(REPO_ROOT, 'extension/media/dashboard.js'), 'utf8');
            assert(!dashHtml.includes('btnRunRemediation'), 'dashboard.html must not contain btnRunRemediation');
            assert(!dashHtml.includes('btnHeaderQuickRun'), 'dashboard.html must not contain btnHeaderQuickRun');
            assert(!dashHtml.includes('Execute Engine'), 'dashboard.html must not contain Execute Engine');
            assert(!dashJs.includes('function startRemediation'), 'dashboard.js must not contain startRemediation');
            assert(!dashJs.includes("'runRemediation'"), 'dashboard.js must not post runRemediation command');

            // Preview /api/remediate-stream returns 403 by default even without approved=true
            await new Promise(resolve => previewServer.listen(0, '127.0.0.1', resolve));
            const port = previewServer.address().port;
            try {
                const streamResp = await httpGet(port, '/api/remediate-stream?id=SCAN-SECRET-005');
                assert.strictEqual(streamResp.statusCode, 403, '/api/remediate-stream must fail closed by default');
            } finally {
                await new Promise(r => previewServer.close(r));
            }

            console.log('  ✓ Workstream D: Fake Execute controls/IPC removed & preview simulation blocked by default');
        }

        // =====================================================================
        // E & F. EVIDENCE CHECKLIST DENOMINATOR, SECRET ROTATION & ZERO EMOJI VERIFICATION
        // =====================================================================
        {
            // Secret finding where code patch + tests PASS + re-scan PASS still flags manual secret actions MISSING
            const secPassedCode = buildEvidenceChecklist({
                finding: { Vulnerability_ID: 'SCAN-SECRET-009', Rule_ID: 'SEC-001', Title: 'Hardcoded Secret', Location_Path: 'Settings.cs' },
                classification: { cwe: 'CWE-798' },
                rca: { summary: 'Plaintext token in Settings.cs' },
                baselineValidation: { executed: true, summary: 'Baseline ran' },
                patchDiff: '+Environment.GetEnvironmentVariable("API_TOKEN")',
                proposedDiffSha256: 'abc123',
                approvalRecord: { decision: 'APPROVED', proposedDiffSha256: 'abc123' },
                validation: { executed: true, passed: true, testsTotal: 2, testsPassed: 2, testsFailed: 0, exitCode: 0 },
                reScanVerification: { machineStatus: 'RESOLVED', reason: 'Secret pattern removed' },
                requiresScannerReScan: true,
                securityReview: { rating: 'PASS', summary: 'Clean patch' },
                outcomeEvaluation: { isResolved: true }
            });
            assert.strictEqual(secPassedCode.isSecretFinding, true);
            assert.strictEqual(secPassedCode.recommendation, REVIEW_RECOMMENDATION.REVIEW_REQUIRED);
            assert.strictEqual(secPassedCode.missingCheckIds.includes('SECRET_REVOCATION_CONFIRMED'), true);
            assert.strictEqual(secPassedCode.missingCheckIds.includes('SECRET_ROTATION_CONFIRMED'), true);
            assert.strictEqual(secPassedCode.missingCheckIds.includes('EXPOSED_CREDENTIAL_INVALIDATED'), true);
            assert.strictEqual(secPassedCode.totalApplicable, 10, 'Secret findings exclude only S2S (N/A) and include all 4 secret checks');

            // Confirming secret revocation/rotation yields READY_FOR_REVIEW
            const secConfirmed = buildEvidenceChecklist({
                finding: { Vulnerability_ID: 'SCAN-SECRET-009', Rule_ID: 'SEC-001', Title: 'Hardcoded Secret', Location_Path: 'Settings.cs' },
                classification: { cwe: 'CWE-798' },
                rca: { summary: 'Plaintext token in Settings.cs' },
                baselineValidation: { executed: true, summary: 'Baseline ran' },
                patchDiff: '+Environment.GetEnvironmentVariable("API_TOKEN")',
                proposedDiffSha256: 'abc123',
                approvalRecord: { decision: 'APPROVED', proposedDiffSha256: 'abc123' },
                validation: { executed: true, passed: true, testsTotal: 2, testsPassed: 2, testsFailed: 0, exitCode: 0 },
                reScanVerification: { machineStatus: 'RESOLVED', reason: 'Secret pattern removed' },
                requiresScannerReScan: true,
                securityReview: { rating: 'PASS', summary: 'Clean patch' },
                outcomeEvaluation: { isResolved: true },
                secretRemediation: { revokedConfirmed: true, rotatedConfirmed: true, gitHistoryInvalidationConfirmed: true }
            });
            assert.strictEqual(secConfirmed.recommendation, REVIEW_RECOMMENDATION.READY_FOR_REVIEW);
            assert.strictEqual(secConfirmed.completionSummary, '10 of 10 required checks complete');

            // Non-secret finding excludes secret checks cleanly from denominator
            const nonSecret = buildEvidenceChecklist({
                finding: { Vulnerability_ID: 'VUL-SQLI-1', Detailed_Name: 'CWE-89 SQL Injection', Location_Path: 'OrderController.cs' },
                classification: { cwe: 'CWE-89' },
                rca: { summary: 'String concatenation in SQL' },
                sourceToSinkEvidence: { untrustedSource: { symbol: 'q' }, dangerousSink: { line: 10 }, analysisMethod: 'Heuristic', formalTaintProofSupplied: false },
                baselineValidation: { executed: true, summary: 'Baseline ran' },
                patchDiff: '+SqlParameter',
                proposedDiffSha256: 'def456',
                approvalRecord: { decision: 'APPROVED', proposedDiffSha256: 'def456' },
                validation: { executed: true, passed: true, testsTotal: 3, testsPassed: 3, testsFailed: 0, exitCode: 0 },
                requiresScannerReScan: false,
                securityReview: { rating: 'PASS', summary: 'SQL parameterized' },
                outcomeEvaluation: { isResolved: true }
            });
            assert.strictEqual(nonSecret.isSecretFinding, false);
            assert.strictEqual(nonSecret.notApplicableCount, 5, 'Should mark 4 secret checks + 1 optional re-scan as NOT_APPLICABLE');
            assert.strictEqual(nonSecret.completionSummary, '6 of 6 required checks complete');
            assert.strictEqual(nonSecret.recommendation, REVIEW_RECOMMENDATION.READY_FOR_REVIEW);

            // All Copilot formatter outputs & ReScanVerifier must contain ZERO emojis
            const formattedSamples = [
                formatHelpMarkdown(),
                formatRunHeaderMarkdown('SCAN-SECRET-009', 'Testing'),
                formatStageEventMarkdown({ type: 'STAGE_START', stageNumber: 6, stageId: 'bench-test' }),
                formatStageEventMarkdown({ type: 'STAGE_COMPLETE', stageNumber: 6, stageId: 'bench-test', summary: 'Passed' }),
                formatStageEventMarkdown({ type: 'STAGE_FAILED', stageNumber: 6, stageId: 'bench-test', failureCategory: 'BUILD_FAILED', summary: 'CS1069' }),
                formatGateMarkdown('VUL-1', { isAwaitingApproval: true, baselineValidation: { status: 'PASS' }, proposedDiffSha256: 'abc', patchDiff: '+ok' }),
                formatTerminalConclusionMarkdown('VUL-1', { isCompleted: true, securityValidationOutcome: 'PASSED', workflowLifecycle: 'COMPLETED', status: 'Remediated', evidenceChecklist: nonSecret }),
                formatErrorMarkdown('Stopped', 'Invalid input')
            ].join('\n');
            assert(!EMOJI_AND_DECORATIVE_REGEX.test(formattedSamples), 'Copilot formatter must not emit any emojis');
            const rv = new ReScanVerifier(tmpBase);
            const rvRes = await rv.verifyRemediation({ originalFinding: null });
            assert(!EMOJI_AND_DECORATIVE_REGEX.test(rvRes.evidenceMarkdown), 'ReScanVerifier output must contain zero emojis');

            console.log('  ✓ Workstreams E & F: Deterministic evidence checklist, secret rotation checks & zero-emoji formatter verified');
        }
    } finally {
        try { fs.rmSync(tmpBase, { recursive: true, force: true }); } catch {}
    }
}

module.exports = { run };

if (require.main === module) {
    run().catch(err => {
        console.error(err);
        process.exit(1);
    });
}
