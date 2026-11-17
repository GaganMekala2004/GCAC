const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { OUTCOME_STATUS } = require('./outcomeContract');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('./contentInjectionScreen');
const { SANDBOX_READINESS } = require('./sandbox/environmentDiscovery');
const {
    EXECUTION_POLICY_VERSION,
    OPERATION_TYPES,
    TrustedExecutionGateway
} = require('./sandbox/trustedExecutionGateway');
const { resolveProfileForRepository, ToolchainProfileError } = require('./sandbox/toolchainProfiles');
const { discoverProjectManifests } = require('./repositoryContext');

/**
 * Deterministic Test Runner for GCAC Vulnerability Remediation
 *
 * Strict Principle:
 * ZERO SYNTHETIC CONSOLE OUTPUT. ZERO FABRICATED TEST COUNTS.
 * Executes genuine compilers and test runners inside TrustedExecutionGateway.
 * Never falls back silently to unrestricted host shell execution.
 */

const ALLOWED_EXECUTABLES = new Set(['dotnet', 'mvn', 'npm']);
const DEFAULT_TIMEOUT_MS = 60000;

const FAILURE_CATEGORIES = Object.freeze({
    NONE: 'NONE',
    TESTS_PASSED: 'TESTS_PASSED',
    TESTS_FAILED: 'TESTS_FAILED',
    NO_TESTS_DISCOVERED: 'NO_TESTS_DISCOVERED',
    TEST_TOOL_MISSING: 'TEST_TOOL_MISSING',
    TEST_RUNNER_UNAVAILABLE: 'TEST_RUNNER_UNAVAILABLE',
    TEST_PROJECT_NOT_FOUND: 'TEST_PROJECT_NOT_FOUND',
    BUILD_FAILED: 'BUILD_FAILED',
    RESTORE_FAILED: 'RESTORE_FAILED',
    EXECUTION_FAILED: 'EXECUTION_FAILED',
    SANDBOX_UNAVAILABLE: 'SANDBOX_UNAVAILABLE',
    EXECUTION_BLOCKED: 'EXECUTION_BLOCKED',
    TOOLCHAIN_IMAGE_UNAVAILABLE: 'TOOLCHAIN_IMAGE_UNAVAILABLE',
    TIMED_OUT: 'TIMED_OUT',
    CANCELLED: 'CANCELLED',
    PARSE_FAILED: 'PARSE_FAILED',
    TEST_RESULTS_MISSING: 'TEST_RESULTS_MISSING'
});

function isExecutableAvailable(executableName) {
    if (!ALLOWED_EXECUTABLES.has(executableName)) {
        return false;
    }
    try {
        const lookupBin = process.platform === 'win32' ? 'where' : 'which';
        execFileSync(lookupBin, [executableName], { stdio: 'ignore', timeout: 3000, shell: false });
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Resolves working directory cleanly whether repoField is relative or absolute.
 */
function resolveRepoWorkingDirectory(finding, workspaceRoot, options = {}) {
    if (options.workingDirectory) return path.resolve(options.workingDirectory);
    const repoField = (finding?.Repository_Root || finding?.Repository || finding?.repositoryRoot || finding?.repository || '').trim();
    if (!repoField) return workspaceRoot;
    return path.isAbsolute(repoField)
        ? path.resolve(repoField)
        : path.resolve(workspaceRoot, repoField);
}

function inspectDotnetProjects(repoFullPath) {
    if (!repoFullPath || !fs.existsSync(repoFullPath)) {
        return { hasProjects: false, testProjects: [], appProjects: [] };
    }
    const { manifests } = discoverProjectManifests(repoFullPath, 4);
    const testProjects = [];
    const appProjects = [];

    for (const csproj of manifests.csprojFiles) {
        try {
            const content = fs.readFileSync(path.resolve(repoFullPath, csproj), 'utf8');
            const isTest = /<IsTestProject>\s*true\s*<\/IsTestProject>/i.test(content) ||
                /Microsoft\.NET\.Test\.Sdk|xunit|nunit|MSTest|Microsoft\.Testing\.Platform/i.test(content) ||
                /[\\/]tests?[\\/]|[._-]tests?\./i.test(csproj);
            if (isTest) {
                testProjects.push(csproj);
            } else {
                appProjects.push(csproj);
            }
        } catch {}
    }

    return {
        hasProjects: manifests.csprojFiles.length > 0 || manifests.slnFiles.length > 0,
        slnFiles: manifests.slnFiles,
        testProjects,
        appProjects
    };
}

function detectDotnetRunnerFramework(projectPath) {
    if (!projectPath || !fs.existsSync(projectPath)) {
        return { runner: 'vstest', supportsTrx: true, trxFlags: ['--logger', 'trx', '--results-directory', '/sandbox-out'] };
    }
    let content = '';
    try {
        if (fs.statSync(projectPath).isDirectory()) {
            const { manifests } = discoverProjectManifests(projectPath, 3);
            content = manifests.csprojFiles.map(f => {
                try { return fs.readFileSync(path.resolve(projectPath, f), 'utf8'); } catch { return ''; }
            }).join('\n');
        } else {
            content = fs.readFileSync(projectPath, 'utf8');
        }
    } catch {}

    const isMtp = /<EnableMicrosoftTestingPlatform>\s*true\s*<\/EnableMicrosoftTestingPlatform>/i.test(content) ||
        /<UseVSTest>\s*false\s*<\/UseVSTest>/i.test(content) ||
        /Microsoft\.Testing\.Platform/i.test(content);

    if (isMtp) {
        const hasTrxExtension = /Microsoft\.Testing\.Extensions\.TrxReport/i.test(content);
        return {
            runner: 'mtp',
            supportsTrx: hasTrxExtension,
            trxFlags: hasTrxExtension
                ? ['--report-trx', '--report-trx-filename', 'test-results.trx', '--results-directory', '/sandbox-out']
                : []
        };
    }

    return {
        runner: 'vstest',
        supportsTrx: true,
        trxFlags: ['--logger', 'trx', '--results-directory', '/sandbox-out']
    };
}

/**
 * Detects the appropriate test runner by inspecting actual repository manifests on disk first,
 * then consulting finding.Technology only when unambiguous. Never defaults blindly to dotnet.
 */
function detectRunner(finding, repoFullPath) {
    const tech = (finding?.Technology || finding?.technology || '').trim().toLowerCase();

    if (repoFullPath && fs.existsSync(repoFullPath)) {
        const { manifests } = discoverProjectManifests(repoFullPath, 4);

        // Honor explicit finding.Technology when matching manifest exists in target tree
        if ((tech === 'javascript' || tech === 'js' || tech === 'nodejs' || tech === 'node') && manifests.packageJsonFiles.length > 0) {
            return { tool: 'npm', args: ['test', '--', '--watchAll=false'], stack: 'nodejs', manifest: manifests.packageJsonFiles[0] };
        }
        if ((tech === 'java' || tech === 'java-spring' || tech === 'maven') && manifests.pomFiles.length > 0) {
            return { tool: 'mvn', args: ['test', '-B'], stack: 'java-maven', manifest: manifests.pomFiles[0] };
        }
        if ((tech === 'dotnet' || tech === 'csharp' || tech === '.net' || tech === 'c#') && (manifests.slnFiles.length > 0 || manifests.csprojFiles.length > 0)) {
            const inspection = inspectDotnetProjects(repoFullPath);
            const targetManifest = path.resolve(repoFullPath, manifests.slnFiles[0] || inspection.testProjects[0] || manifests.csprojFiles[0]);
            const runnerFw = detectDotnetRunnerFramework(targetManifest);
            const extraArgs = runnerFw.trxFlags || [];
            return {
                tool: 'dotnet',
                args: ['test', '--no-restore', '--nologo', '-v', 'normal', ...extraArgs],
                stack: 'dotnet',
                manifest: targetManifest,
                runnerType: runnerFw.runner,
                hasTestProject: inspection.testProjects.length > 0
            };
        }

        if (manifests.pomFiles.length > 0) {
            return { tool: 'mvn', args: ['test', '-B'], stack: 'java-maven', manifest: manifests.pomFiles[0] };
        }
        if (manifests.slnFiles.length > 0 || manifests.csprojFiles.length > 0) {
            const inspection = inspectDotnetProjects(repoFullPath);
            const targetManifest = path.resolve(repoFullPath, manifests.slnFiles[0] || inspection.testProjects[0] || manifests.csprojFiles[0]);
            const runnerFw = detectDotnetRunnerFramework(targetManifest);
            const extraArgs = runnerFw.trxFlags || [];
            return {
                tool: 'dotnet',
                args: ['test', '--no-restore', '--nologo', '-v', 'normal', ...extraArgs],
                stack: 'dotnet',
                manifest: targetManifest,
                runnerType: runnerFw.runner,
                hasTestProject: inspection.testProjects.length > 0
            };
        }
        if (manifests.packageJsonFiles.length > 0) {
            return { tool: 'npm', args: ['test', '--', '--watchAll=false'], stack: 'nodejs', manifest: manifests.packageJsonFiles[0] };
        }
        if (manifests.gradleFiles.length > 0 || manifests.antFiles.length > 0 || manifests.pythonFiles.length > 0) {
            return null;
        }
        // If repoFullPath exists and contains no supported build or test manifests, return null
        return null;
    }

    if (tech === 'dotnet' || tech === 'csharp' || tech === '.net' || tech === 'c#') {
        return { tool: 'dotnet', args: ['test', '--nologo', '-v', 'normal'], stack: 'dotnet', manifest: null, hasTestProject: false };
    }
    if (tech === 'java' || tech === 'java-spring' || tech === 'maven') {
        return { tool: 'mvn', args: ['test', '-B'], stack: 'java-maven', manifest: null };
    }
    if (tech === 'javascript' || tech === 'typescript' || tech === 'node' || tech === 'nodejs') {
        return { tool: 'npm', args: ['test', '--', '--watchAll=false'], stack: 'nodejs', manifest: null };
    }

    return null;
}

function parseTrxReport(xmlContent, context = {}) {
    if (!xmlContent || typeof xmlContent !== 'string' || !xmlContent.trim()) {
        return {
            valid: false,
            failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
            rootError: 'TRX test result artifact is empty or missing.'
        };
    }

    const trimmed = xmlContent.trim();
    if (!/<TestRun[\s>]/i.test(trimmed)) {
        return {
            valid: false,
            failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
            rootError: 'TRX test result artifact is not a valid TestRun document.'
        };
    }

    const isClosed = /<\/TestRun\s*>/i.test(trimmed) || /<TestRun[^>]*\/>/i.test(trimmed);
    if (!isClosed) {
        return {
            valid: false,
            failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
            rootError: 'TRX test result artifact is truncated or malformed XML.'
        };
    }

    if (trimmed.includes('<Counters') && !/<Counters\s+[^>]+?\/?>/i.test(trimmed)) {
        return {
            valid: false,
            failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
            rootError: 'TRX test result artifact contains malformed <Counters> element.'
        };
    }

    const countersMatch = /<Counters\s+([^>]+?)\/?>/i.exec(trimmed);
    let total = 0;
    let executed = 0;
    let passed = 0;
    let failed = 0;
    let skipped = 0;

    if (countersMatch) {
        const attrsStr = countersMatch[1];
        const getAttr = (name) => {
            const m = new RegExp(`\\b${name}=["'](\\d+)["']`, 'i').exec(attrsStr);
            return m ? parseInt(m[1], 10) : 0;
        };

        total = getAttr('total');
        executed = getAttr('executed');
        passed = getAttr('passed');
        const rawFailed = getAttr('failed');
        const error = getAttr('error');
        const timeout = getAttr('timeout');
        const aborted = getAttr('aborted');
        const notExecuted = getAttr('notExecuted');
        skipped = notExecuted;
        failed = rawFailed + error + timeout + aborted;
    } else {
        const unitTests = [...trimmed.matchAll(/<UnitTestResult\s+([^>]+?)(?:\/>|>.*?<\/UnitTestResult>)/gis)];
        if (unitTests.length > 0) {
            total = unitTests.length;
            executed = unitTests.length;
            for (const ut of unitTests) {
                const outM = /\boutcome=["']([^"']+)["']/i.exec(ut[1]);
                const out = outM ? outM[1].toLowerCase() : '';
                if (out === 'passed') passed++;
                else if (out === 'failed') failed++;
                else skipped++;
            }
        }
    }

    const summaryMatch = /<ResultSummary\s+[^>]*outcome=["']([^"']+)["']/i.exec(trimmed);
    const overallOutcome = summaryMatch ? summaryMatch[1] : (failed > 0 ? 'Failed' : (total > 0 ? 'Completed' : 'NotExecuted'));

    const testFailures = [];
    const testResultRe = /<UnitTestResult\s+([^>]+?)(?:\/>|>(.*?)<\/UnitTestResult>)/gis;
    let trMatch;
    while ((trMatch = testResultRe.exec(trimmed)) !== null) {
        const trAttrs = trMatch[1] || '';
        const trBody = trMatch[2] || '';
        const nameMatch = /\btestName=["']([^"']+)["']/i.exec(trAttrs);
        const outcomeMatch = /\boutcome=["']([^"']+)["']/i.exec(trAttrs);
        const testName = nameMatch ? nameMatch[1] : 'UnknownTest';
        const outcome = outcomeMatch ? outcomeMatch[1] : 'Unknown';

        if (outcome.toLowerCase() === 'failed') {
            const msgMatch = /<Message>(.*?)<\/Message>/is.exec(trBody);
            const msg = msgMatch ? msgMatch[1].trim() : '';
            testFailures.push({ testName, outcome, error: msg });
        }
    }

    let failureCategory = FAILURE_CATEGORIES.NONE;
    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;
    let rootError = '';

    if (total === 0 || executed === 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.NO_TESTS_DISCOVERED;
        rootError = 'Zero tests were executed in the test run.';
    } else if (failed > 0 || overallOutcome.toLowerCase() === 'failed') {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = FAILURE_CATEGORIES.TESTS_FAILED;
        rootError = testFailures.length > 0
            ? `${testFailures[0].testName}: ${testFailures[0].error || 'Assertion failed'}`
            : `${failed} test assertion(s) failed in TRX report.`;
    } else if (passed > 0 && failed === 0) {
        status = 'PASS';
        machineStatus = OUTCOME_STATUS.PASSED;
        failureCategory = FAILURE_CATEGORIES.NONE;
    }

    return {
        valid: true,
        countsKnown: true,
        testsTotal: total,
        testsPassed: passed,
        testsFailed: failed,
        testsSkipped: skipped,
        status,
        machineStatus,
        failureCategory,
        rootError,
        testFailures,
        provenance: {
            repositoryId: context.repositoryId || null,
            runId: context.runId || null,
            stageId: context.stageId || null,
            attemptId: context.attemptId || null,
            command: context.command || null
        }
    };
}

function aggregateTrxReports(reports, context = {}) {
    const parsed = reports.map(report => parseTrxReport(report, context));
    const invalid = parsed.find(result => !result.valid);
    if (invalid) return invalid;
    const aggregate = { ...parsed[0], testsTotal: 0, testsPassed: 0, testsFailed: 0, testsSkipped: 0, testFailures: [] };
    for (const result of parsed) {
        for (const key of ['testsTotal', 'testsPassed', 'testsFailed', 'testsSkipped']) aggregate[key] += result[key];
        aggregate.testFailures.push(...result.testFailures);
    }
    const failure = parsed.find(result => result.machineStatus === OUTCOME_STATUS.FAILED);
    const untested = parsed.find(result => result.machineStatus === OUTCOME_STATUS.UNTESTED);
    const verdict = failure || untested || parsed[0];
    for (const key of ['status', 'machineStatus', 'failureCategory', 'rootError']) aggregate[key] = verdict[key];
    return aggregate;
}

function extractFirstMatchingLine(text, patterns = []) {
    const lines = String(text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    for (const rx of patterns) {
        const found = lines.find(l => rx.test(l));
        if (found) return found.slice(0, 280);
    }
    return '';
}

function parseDotnetOutput(stdout, stderr, exitCode) {
    const combined = (stdout || '') + '\n' + (stderr || '');
    let testsPassed = 0;
    let testsFailed = 0;
    let testsSkipped = 0;
    let testsTotal = 0;
    let countsKnown = false;

    // 1. Sum all VSTest summary lines (handles multi-test-project solutions cleanly)
    const vsSummaryRe = /Failed:\s*(\d+),\s*Passed:\s*(\d+),\s*Skipped:\s*(\d+),\s*Total:\s*(\d+)/gi;
    let m;
    let vsMatches = 0;
    while ((m = vsSummaryRe.exec(combined)) !== null) {
        vsMatches++;
        testsFailed += parseInt(m[1], 10);
        testsPassed += parseInt(m[2], 10);
        testsSkipped += parseInt(m[3], 10);
        testsTotal += parseInt(m[4], 10);
    }

    if (vsMatches > 0) {
        countsKnown = true;
    } else {
        // 2. Fallback to older "Total tests: N. Passed: N. Failed: N. Skipped: N." lines
        const totalMatches = [...combined.matchAll(/Total tests:\s*(\d+)/gi)];
        const passMatches = [...combined.matchAll(/Passed:\s*(\d+)/gi)];
        const failMatches = [...combined.matchAll(/Failed:\s*(\d+)/gi)];
        const skipMatches = [...combined.matchAll(/Skipped:\s*(\d+)/gi)];

        if (totalMatches.length > 0 || passMatches.length > 0 || failMatches.length > 0) {
            countsKnown = true;
            for (const x of passMatches) testsPassed += parseInt(x[1], 10);
            for (const x of failMatches) testsFailed += parseInt(x[1], 10);
            for (const x of skipMatches) testsSkipped += parseInt(x[1], 10);
            if (totalMatches.length > 0) {
                for (const x of totalMatches) testsTotal += parseInt(x[1], 10);
            } else {
                testsTotal = testsPassed + testsFailed + testsSkipped;
            }
        }
    }

    const noTestsExplicit = /No test is available|Total tests:\s*0|\b0 tests found\b|Skipping running test for project/i.test(combined);
    if (noTestsExplicit && !countsKnown) {
        countsKnown = true;
        testsTotal = 0;
    }

    const toolMissing = /dotnet:\s*command not found|not recognized as an internal or external command|ENOENT.*dotnet/i.test(combined);
    const restoreFailed = /error NETSDK(?:1004|1064)|error NU110\d|error NU1301|Assets file .*project\.assets\.json.* not found|Unable to resolve/i.test(combined);
    const compilationFailed = /error (?:CS|MSB)\d{4}:/i.test(combined) || (/Build FAILED/i.test(combined) && testsFailed === 0);

    let failureCategory = FAILURE_CATEGORIES.NONE;
    let rootError = '';
    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;

    if (toolMissing) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.TEST_RUNNER_UNAVAILABLE;
        rootError = extractFirstMatchingLine(combined, [/not found|not recognized|ENOENT/i]) || 'dotnet CLI executable not available.';
    } else if (restoreFailed) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.RESTORE_FAILED;
        rootError = extractFirstMatchingLine(combined, [/NETSDK(?:1004|1064)|NU110\d|NU1301|project\.assets\.json|Unable to resolve/i]) || 'Offline NuGet dependency restore assets unavailable.';
    } else if (compilationFailed) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = FAILURE_CATEGORIES.BUILD_FAILED;
        rootError = extractFirstMatchingLine(combined, [/error (?:CS|MSB)\d+/i, /Build FAILED/i]) || 'C# / MSBuild compilation failed.';
    } else if (testsFailed > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = FAILURE_CATEGORIES.TESTS_FAILED;
        rootError = extractFirstMatchingLine(combined, [/Failed\s+\S+/i, /Assert\./i, /Expected:/i, /Exception/i]) || `${testsFailed} test assertion(s) failed.`;
    } else if (exitCode !== 0 && !countsKnown) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = compilationFailed ? FAILURE_CATEGORIES.BUILD_FAILED : FAILURE_CATEGORIES.EXECUTION_FAILED;
        rootError = extractFirstMatchingLine(combined, [/error\s+/i, /exception/i, /panic/i, /aborted/i, /failed/i]) || `dotnet test exited with code ${exitCode} and no parseable test summary.`;
    } else if (exitCode !== 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = testsTotal === 0 ? FAILURE_CATEGORIES.NO_TESTS_DISCOVERED : FAILURE_CATEGORIES.TESTS_FAILED;
        rootError = extractFirstMatchingLine(combined, [/error|failed|aborted/i]) || `dotnet test exited with code ${exitCode}.`;
    } else if (/Skipping running test for project/i.test(combined)) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.TEST_PROJECT_NOT_FOUND;
        rootError = 'Test runner skipped test execution (application project selected for testing or missing <IsTestProject>true</IsTestProject>).';
    } else if (!countsKnown) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.PARSE_FAILED;
        rootError = 'dotnet test exited 0 without recognizable test summary output.';
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.NO_TESTS_DISCOVERED;
        rootError = 'Zero tests were discovered or executed.';
    }

    return {
        status,
        machineStatus,
        failureCategory,
        rootError,
        countsKnown,
        testsPassed,
        testsFailed,
        testsSkipped,
        testsTotal,
        compilationFailed
    };
}

function parseMavenOutput(stdout, stderr, exitCode) {
    const combined = (stdout || '') + '\n' + (stderr || '');
    let testsPassed = 0;
    let testsFailed = 0;
    let testsErrors = 0;
    let testsSkipped = 0;
    let testsTotal = 0;
    let countsKnown = false;

    // Prefer the final "Results:" summary block if present; otherwise take the last summary line or sum class lines cleanly
    const resultsMatch = combined.match(/Results:\s*[\r\n]+(?:\[INFO\]\s*)?(?:\[ERROR\]\s*)?Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)/i);
    if (resultsMatch) {
        countsKnown = true;
        testsTotal = parseInt(resultsMatch[1], 10);
        testsFailed = parseInt(resultsMatch[2], 10);
        testsErrors = parseInt(resultsMatch[3], 10);
        testsSkipped = parseInt(resultsMatch[4], 10);
        testsPassed = Math.max(0, testsTotal - testsFailed - testsErrors - testsSkipped);
    } else {
        const allSummaries = [...combined.matchAll(/Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)/gi)];
        if (allSummaries.length > 0) {
            countsKnown = true;
            // Last summary in Surefire output is the aggregate when Results: header varies
            const last = allSummaries[allSummaries.length - 1];
            testsTotal = parseInt(last[1], 10);
            testsFailed = parseInt(last[2], 10);
            testsErrors = parseInt(last[3], 10);
            testsSkipped = parseInt(last[4], 10);
            testsPassed = Math.max(0, testsTotal - testsFailed - testsErrors - testsSkipped);
        }
    }

    const noTests = /No tests to run|There are no tests to run/i.test(combined);
    if (noTests && !countsKnown) {
        countsKnown = true;
        testsTotal = 0;
    }

    const toolMissing = /mvn:\s*command not found|not recognized as an internal or external command|ENOENT.*mvn/i.test(combined);
    const restoreFailed = /Could not resolve dependencies|Cannot access .* in offline mode|The following artifacts could not be resolved/i.test(combined);
    const buildFailure = /BUILD FAILURE/i.test(combined);
    const compilationFailed = /Compilation failure/i.test(combined) || /\[ERROR\] COMPILATION ERROR/i.test(combined);

    let failureCategory = FAILURE_CATEGORIES.NONE;
    let rootError = '';
    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;

    if (toolMissing) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.TEST_TOOL_MISSING;
        rootError = extractFirstMatchingLine(combined, [/not found|not recognized|ENOENT/i]) || 'Maven (mvn) executable not available.';
    } else if (restoreFailed) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.RESTORE_FAILED;
        rootError = extractFirstMatchingLine(combined, [/Could not resolve dependencies|offline mode|artifacts could not be resolved/i]) || 'Offline Maven dependencies missing from cache.';
    } else if (compilationFailed) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = FAILURE_CATEGORIES.BUILD_FAILED;
        rootError = extractFirstMatchingLine(combined, [/\[ERROR\]/, /Compilation failure/i]) || 'Maven Java compilation failed.';
    } else if (testsFailed > 0 || testsErrors > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = FAILURE_CATEGORIES.TESTS_FAILED;
        rootError = extractFirstMatchingLine(combined, [/\[ERROR\].*(?:Test|Failures|Errors)/i, /AssertionError/i]) || `${testsFailed + testsErrors} Maven test failure(s)/error(s).`;
    } else if (buildFailure || exitCode !== 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = countsKnown ? FAILURE_CATEGORIES.TESTS_FAILED : FAILURE_CATEGORIES.PARSE_FAILED;
        rootError = extractFirstMatchingLine(combined, [/\[ERROR\]/, /BUILD FAILURE/i]) || `mvn test exited with code ${exitCode}.`;
    } else if (!countsKnown) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.PARSE_FAILED;
        rootError = 'mvn test exited 0 without recognizable Surefire test summary.';
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.NO_TESTS_DISCOVERED;
        rootError = 'Zero Maven tests discovered or executed.';
    }

    return {
        status,
        machineStatus,
        failureCategory,
        rootError,
        countsKnown,
        testsPassed,
        testsFailed: testsFailed + testsErrors,
        testsSkipped,
        testsTotal,
        compilationFailed
    };
}

function parseNpmOutput(stdout, stderr, exitCode) {
    const combined = (stdout || '') + '\n' + (stderr || '');
    let testsPassed = 0;
    let testsFailed = 0;
    let testsSkipped = 0;
    let testsTotal = 0;
    let countsKnown = false;

    // 1. Jest / Vitest / GCAC suite format
    const passMatch = combined.match(/Tests:\s*(\d+)\s*passed/i) || combined.match(/Passed Suites:\s*(\d+)/i);
    const failMatch = combined.match(/Tests:\s*(\d+)\s*failed/i) || combined.match(/Failed Suites:\s*(\d+)/i);
    const totalMatch = combined.match(/Tests:\s*(\d+)\s*total/i) || combined.match(/Total Suites:\s*(\d+)/i);

    // 2. Node built-in test runner (node --test: both TAP '#' and spec 'ℹ')
    const nodeTestsMatch = combined.match(/^(?:#|ℹ)\s*tests\s+(\d+)/im);
    const nodePassMatch = combined.match(/^(?:#|ℹ)\s*pass\s+(\d+)/im);
    const nodeFailMatch = combined.match(/^(?:#|ℹ)\s*fail\s+(\d+)/im);
    const nodeSkipMatch = combined.match(/^(?:#|ℹ)\s*skipped\s+(\d+)/im);

    // 3. Mocha
    const mochaPassMatch = combined.match(/(\d+)\s+passing/i);
    const mochaFailMatch = combined.match(/(\d+)\s+failing/i);

    if (passMatch || failMatch || totalMatch) {
        countsKnown = true;
        if (passMatch) testsPassed = parseInt(passMatch[1], 10);
        if (failMatch) testsFailed = parseInt(failMatch[1], 10);
        testsTotal = totalMatch ? parseInt(totalMatch[1], 10) : (testsPassed + testsFailed);
    } else if (nodeTestsMatch || nodePassMatch || nodeFailMatch) {
        countsKnown = true;
        if (nodePassMatch) testsPassed = parseInt(nodePassMatch[1], 10);
        if (nodeFailMatch) testsFailed = parseInt(nodeFailMatch[1], 10);
        if (nodeSkipMatch) testsSkipped = parseInt(nodeSkipMatch[1], 10);
        testsTotal = nodeTestsMatch ? parseInt(nodeTestsMatch[1], 10) : (testsPassed + testsFailed + testsSkipped);
    } else if (mochaPassMatch || mochaFailMatch) {
        countsKnown = true;
        if (mochaPassMatch) testsPassed = parseInt(mochaPassMatch[1], 10);
        if (mochaFailMatch) testsFailed = parseInt(mochaFailMatch[1], 10);
        testsTotal = testsPassed + testsFailed;
    }

    const toolMissing = /npm:\s*command not found|not recognized|ENOENT.*npm/i.test(combined);
    const missingScript = /Missing script:\s*"test"|no test specified/i.test(combined);
    const restoreFailed = /ENOTCACHED|Cannot find module/i.test(combined);

    let failureCategory = FAILURE_CATEGORIES.NONE;
    let rootError = '';
    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;

    if (toolMissing) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.TEST_TOOL_MISSING;
        rootError = 'npm executable not available.';
    } else if (restoreFailed) {
        status = 'COULD NOT RUN';
        machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
        failureCategory = FAILURE_CATEGORIES.RESTORE_FAILED;
        rootError = extractFirstMatchingLine(combined, [/ENOTCACHED|Cannot find module/i]) || 'Node modules unavailable offline.';
    } else if (missingScript) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.NO_TESTS_DISCOVERED;
        rootError = 'package.json has no configured test script.';
    } else if (exitCode !== 0 || testsFailed > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
        failureCategory = countsKnown ? FAILURE_CATEGORIES.TESTS_FAILED : FAILURE_CATEGORIES.PARSE_FAILED;
        rootError = extractFirstMatchingLine(combined, [/AssertionError|Error:|FAIL\s+/i]) || `npm test exited with code ${exitCode}.`;
    } else if (!countsKnown) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.PARSE_FAILED;
        rootError = 'npm test exited 0 without recognizable test counts.';
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
        failureCategory = FAILURE_CATEGORIES.NO_TESTS_DISCOVERED;
        rootError = 'Zero npm tests discovered.';
    }

    return {
        status,
        machineStatus,
        failureCategory,
        rootError,
        countsKnown,
        testsPassed,
        testsFailed,
        testsSkipped,
        testsTotal,
        compilationFailed: exitCode !== 0 && testsTotal === 0
    };
}

function discoverTestReportArtifacts(repoDir) {
    if (!repoDir || !fs.existsSync(repoDir)) return null;
    const candidates = [];

    const walk = (dir, depth = 0) => {
        if (depth > 4) return;
        let entries = [];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (e.isSymbolicLink()) continue;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (['.git', 'node_modules'].includes(e.name)) continue;
                if (e.name === 'TestResults' || e.name === 'surefire-reports') {
                    try {
                        for (const f of fs.readdirSync(full)) {
                            if (f.endsWith('.trx') || (f.startsWith('TEST-') && f.endsWith('.xml'))) {
                                candidates.push(path.join(full, f));
                            }
                        }
                    } catch {}
                } else {
                    walk(full, depth + 1);
                }
            }
        }
    };
    walk(repoDir, 0);
    return candidates.length > 0 ? candidates[0] : null;
}

function redactSensitiveOutput(text) {
    if (!text) return '';
    return text
        .replace(/(?:api[_-]?key|secret|password|token|bearer\s+)["':= ]+([A-Za-z0-9_-]{12,})/gi, 'REDACTED_SECRET')
        .replace(/(?:ghp_[A-Za-z0-9]{36})/g, 'ghp_REDACTED');
}

function mapToolAndArgsToOperation(executable, args = []) {
    const firstArg = String(args[0] || '').toLowerCase();
    if (executable === 'dotnet') {
        const operation = firstArg === 'build' ? OPERATION_TYPES.DOTNET_BUILD : OPERATION_TYPES.DOTNET_TEST;
        const extraArgs = [];
        for (let i = 1; i < args.length; i++) {
            const tok = String(args[i] ?? '');
            if (tok === '--verbosity') {
                const next = String(args[i + 1] || '').toLowerCase();
                if (next === 'normal' || next === 'minimal') {
                    i++;
                    continue;
                }
            }
            if (tok === '--nologo' || tok === '--no-restore') continue;
            extraArgs.push(tok);
        }
        return { operation, extraArgs };
    }
    if (executable === 'mvn') {
        const operation = firstArg === 'compile' ? OPERATION_TYPES.MAVEN_COMPILE : OPERATION_TYPES.MAVEN_TEST;
        const extraArgs = [];
        for (let i = 1; i < args.length; i++) {
            const tok = String(args[i] ?? '');
            if (tok === '-B' || tok === '-o') continue;
            extraArgs.push(tok);
        }
        return { operation, extraArgs };
    }
    const extraArgs = [];
    for (let i = 1; i < args.length; i++) {
        const tok = String(args[i] ?? '');
        if (tok === '--ignore-scripts' || tok === '--offline') continue;
        extraArgs.push(tok);
    }
    return { operation: OPERATION_TYPES.NPM_TEST, extraArgs };
}

function buildDiagnosticGuidance(failureCategory, testPhase = 'POST_FIX_TEST') {
    const isBaseline = testPhase === 'BASELINE_SECURITY_TEST';
    switch (failureCategory) {
        case FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE:
            return {
                retryEligible: false,
                suggestedNextAction: 'Enable WSL2 + Docker Desktop (Linux container mode) or Podman v4+, pre-pull pinned toolchain images, then retry.'
            };
        case FAILURE_CATEGORIES.EXECUTION_BLOCKED:
            return {
                retryEligible: false,
                suggestedNextAction: 'Review security policy blockage (toolchain, feed credentials, or SEC-02 metadata) before proceeding.'
            };
        case FAILURE_CATEGORIES.TOOLCHAIN_IMAGE_UNAVAILABLE:
            return {
                retryEligible: false,
                suggestedNextAction: 'Required toolchain image is not present in local runtime cache. Provision the approved pinned image or migrate repository to a supported LTS framework (e.g., net10.0).'
            };
        case FAILURE_CATEGORIES.TIMED_OUT:
            return {
                retryEligible: true,
                suggestedNextAction: 'Transient timeout occurred; use Retry Stage to re-execute this stage.'
            };
        case FAILURE_CATEGORIES.CANCELLED:
            return {
                retryEligible: true,
                suggestedNextAction: 'Execution was cancelled; use Retry Stage when ready to resume.'
            };
        case FAILURE_CATEGORIES.TEST_TOOL_MISSING:
        case FAILURE_CATEGORIES.TEST_RUNNER_UNAVAILABLE:
            return {
                retryEligible: false,
                suggestedNextAction: 'Install or configure the required runtime/toolchain in the sandbox image, then retry.'
            };
        case FAILURE_CATEGORIES.TEST_PROJECT_NOT_FOUND:
            return {
                retryEligible: false,
                suggestedNextAction: 'Add or configure a genuine test project in the target repository; application projects cannot be executed as test suites.'
            };
        case FAILURE_CATEGORIES.EXECUTION_FAILED:
            return {
                retryEligible: false,
                suggestedNextAction: 'Test runner execution failed; check raw stdout/stderr for runtime failure diagnostics.'
            };
        case FAILURE_CATEGORIES.TEST_RESULTS_MISSING:
            return {
                retryEligible: false,
                suggestedNextAction: 'Test execution finished but test result report artifact was missing or unreadable; verify runner logging flags.'
            };
        case FAILURE_CATEGORIES.RESTORE_FAILED:
            return {
                retryEligible: false,
                suggestedNextAction: 'Pre-provision offline NuGet/Maven/npm package cache or approved internal mirror before retrying.'
            };
        case FAILURE_CATEGORIES.NO_TESTS_DISCOVERED:
            return {
                retryEligible: false,
                suggestedNextAction: 'Add automated unit/security tests in the target repository; zero discovered tests cannot certify PASS.'
            };
        case FAILURE_CATEGORIES.BUILD_FAILED:
        case FAILURE_CATEGORIES.TESTS_FAILED:
            return isBaseline
                ? {
                    retryEligible: false,
                    suggestedNextAction: 'Baseline tests failed prior to patch (expected if reproducing vulnerability); proceed to Stage 4 patch review.'
                }
                : {
                    retryEligible: false,
                    suggestedNextAction: 'Genuine post-fix build/test failure; use Review Failure / Revise Fix to generate a revised patch and re-approve at Stage 4.'
                };
        case FAILURE_CATEGORIES.PARSE_FAILED:
            return {
                retryEligible: false,
                suggestedNextAction: 'Inspect raw runner stdout/stderr and test report location to diagnose unrecognized runner output.'
            };
        default:
            return { retryEligible: false, suggestedNextAction: 'Review validation artifacts.' };
    }
}

async function executeRealTestRunner(executable, args = [], cwd, options = {}) {
    const startTime = new Date();
    const startTimeIso = startTime.toISOString();
    const safeArgs = Array.isArray(args) ? args : [];
    const testPhase = options.testPhase || 'POST_FIX_TEST';
    const stageLabel = options.stageLabel || (testPhase === 'BASELINE_SECURITY_TEST' ? 'Stage 3: Baseline Security Test' : 'Stage 5/6: Post-Fix Bench Test');
    const repoTested = options.repositoryTested || cwd || '';

    if (!ALLOWED_EXECUTABLES.has(executable)) {
        const endTime = new Date();
        const reason = `Unauthorized test runner executable: '${executable}'`;
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.EXECUTION_BLOCKED, testPhase);
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.BLOCKED,
            failureCategory: FAILURE_CATEGORIES.EXECUTION_BLOCKED,
            stage: stageLabel,
            testPhase,
            reason,
            rootError: reason,
            executable,
            command: `${executable} ${safeArgs.join(' ')}`,
            workingDirectory: cwd,
            repositoryTested: repoTested,
            startTime: startTimeIso,
            endTime: endTime.toISOString(),
            durationMs: 0,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: null,
            retryEligible: guide.retryEligible,
            suggestedNextAction: guide.suggestedNextAction,
            stdout: '',
            stderr: `Executable '${executable}' is not in the approved security allowlist.`,
            summary: `NOT EXECUTED — Unauthorized executable '${executable}'`
        };
    }

    if (!cwd || !fs.existsSync(cwd)) {
        const endTime = new Date();
        const reason = 'Working directory not found';
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.EXECUTION_BLOCKED, testPhase);
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            failureCategory: FAILURE_CATEGORIES.EXECUTION_BLOCKED,
            stage: stageLabel,
            testPhase,
            reason,
            rootError: `Working directory does not exist on disk: '${cwd}'`,
            executable,
            command: `${executable} ${safeArgs.join(' ')}`,
            workingDirectory: cwd,
            repositoryTested: repoTested,
            startTime: startTimeIso,
            endTime: endTime.toISOString(),
            durationMs: 0,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: null,
            retryEligible: guide.retryEligible,
            suggestedNextAction: guide.suggestedNextAction,
            stdout: '',
            stderr: `Working directory does not exist on disk: '${cwd}'`,
            summary: `NOT EXECUTED — Working directory not found: ${cwd}`
        };
    }

    const workspaceRoot = options.workspaceRoot || cwd;
    const gateway = options.executionGateway || new TrustedExecutionGateway({
        workspaceRoot,
        backend: options.sandboxBackend || null,
        envReport: options.envReport || null,
        profilesPath: options.profilesPath,
        lifecycleStateDir: options.lifecycleStateDir || null
    });

    let profile;
    if (options.toolchainProfileId) {
        profile = {
            profileId: options.toolchainProfileId,
            supportedStack: executable === 'dotnet' ? 'dotnet' : executable === 'mvn' ? 'java-maven' : 'nodejs',
            networkPolicy: options.networkPolicy || 'NO_NETWORK',
            outputArtifactPaths: [],
            runtimeLimits: { timeoutMs: options.timeoutMs || DEFAULT_TIMEOUT_MS, memoryMb: 2048, cpus: 2, pidsLimit: 128 }
        };
    } else {
        try {
            const techHint = options.finding?.Technology || (executable === 'dotnet' ? 'dotnet' : executable === 'mvn' ? 'java-maven' : 'nodejs');
            const isRealContainer = !options.sandboxBackend && options.allowTemplateDigests !== true && (!options.envReport || options.envReport.sandboxAvailable !== false);
            const shouldRequireProvisioned = options.requireProvisioned !== undefined ? Boolean(options.requireProvisioned) : isRealContainer;
            profile = resolveProfileForRepository(cwd, { Technology: techHint }, options.profilesPath, {
                requireProvisioned: shouldRequireProvisioned,
                repositoryLabel: repoTested
            });
        } catch (err) {
            const endTime = new Date();
            const code = err instanceof ToolchainProfileError ? err.code : 'TOOLCHAIN_PROFILE_BLOCKED';
            const isToolchainUnavail = code === 'UNPROVISIONED_TOOLCHAIN_PROFILE' ||
                code === 'TOOLCHAIN_UNAVAILABLE' ||
                code === 'TOOLCHAIN_IMAGE_UNAVAILABLE' ||
                /template placeholder|UNPROVISIONED_TOOLCHAIN_PROFILE/i.test(err.message);
            const failCat = isToolchainUnavail ? FAILURE_CATEGORIES.TOOLCHAIN_IMAGE_UNAVAILABLE : FAILURE_CATEGORIES.EXECUTION_BLOCKED;
            const machineStatus = isToolchainUnavail ? OUTCOME_STATUS.COULD_NOT_RUN : OUTCOME_STATUS.BLOCKED;
            const status = isToolchainUnavail ? 'COULD NOT RUN' : 'BLOCKED';
            const guide = buildDiagnosticGuidance(failCat, testPhase);
            return {
                executed: false,
                passed: false,
                status,
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus,
                failureCategory: failCat,
                stage: stageLabel,
                testPhase,
                reasonCode: isToolchainUnavail ? 'TOOLCHAIN_IMAGE_UNAVAILABLE' : code,
                reason: err.message,
                rootError: err.message,
                executable,
                command: `${executable} ${safeArgs.join(' ')}`,
                workingDirectory: cwd,
                repositoryTested: repoTested,
                startTime: startTimeIso,
                endTime: endTime.toISOString(),
                durationMs: 0,
                exitCode: null,
                countsKnown: false,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                testsSkipped: 0,
                testReportLocation: null,
                retryEligible: false,
                suggestedNextAction: guide.suggestedNextAction,
                stdout: '',
                stderr: err.message,
                summary: `${status} (${failCat}) — ${err.message}`
            };
        }
    }

    const { operation, extraArgs } = mapToolAndArgsToOperation(executable, safeArgs);
    const chosenOp = options.operation || operation;
    const finding = options.finding || {};
    const runId = options.runId || `run-${Date.now().toString(36)}`;
    const appId = options.applicationId || finding.Application_Number || 'UNMAPPED-LOCAL';
    const vulId = options.vulnerabilityId || finding.Vulnerability_ID || 'VUL-DEFAULT';

    const request = {
        runId,
        applicationId: String(appId),
        vulnerabilityId: String(vulId),
        workspaceRef: cwd,
        operation: chosenOp,
        toolchainProfileId: profile.profileId,
        requestedExecutable: executable,
        inputs: Array.isArray(options.inputs)
            ? options.inputs
            : (finding.Location_Path ? [String(finding.Location_Path)] : []),
        expectedOutputPaths: Array.isArray(profile.outputArtifactPaths) ? profile.outputArtifactPaths : [],
        extraArgs,
        policyVersion: EXECUTION_POLICY_VERSION,
        networkPolicy: options.networkPolicy || profile.networkPolicy || 'NO_NETWORK',
        isControlledRestoreOperation: options.isControlledRestoreOperation === true,
        requestedFeeds: options.requestedFeeds || [],
        resourcePolicy: {
            timeoutMs: options.timeoutMs || profile.runtimeLimits?.timeoutMs || DEFAULT_TIMEOUT_MS,
            memoryMb: options.memoryMb || profile.runtimeLimits?.memoryMb || 2048,
            cpus: options.cpus || profile.runtimeLimits?.cpus || 2,
            pidsLimit: options.pidsLimit || profile.runtimeLimits?.pidsLimit || 128
        }
    };

    const gwRes = await gateway.executeOperation(request, {
        ...options,
        originalWorkspaceRoot: workspaceRoot
    });

    // Only artifacts returned by this gateway execution may certify .NET tests.
    const discoveredArtifact = executable === 'dotnet' ? null : discoverTestReportArtifacts(cwd);

    if (gwRes.timedOut || gwRes.machineStatus === OUTCOME_STATUS.TIMED_OUT) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.TIMED_OUT, testPhase);
        return {
            ...gwRes,
            executed: true,
            passed: false,
            status: 'TIMED OUT',
            machineStatus: OUTCOME_STATUS.TIMED_OUT,
            failureCategory: FAILURE_CATEGORIES.TIMED_OUT,
            stage: stageLabel,
            testPhase,
            repositoryTested: repoTested,
            rootError: gwRes.reason || 'Sandbox execution exceeded timeout limit.',
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: discoveredArtifact,
            retryEligible: guide.retryEligible,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `TIMED OUT — ${gwRes.reason || 'Sandbox execution exceeded timeout limit.'}`
        };
    }

    if (gwRes.cancelled || gwRes.machineStatus === OUTCOME_STATUS.CANCELLED) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.CANCELLED, testPhase);
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status: 'CANCELLED',
            machineStatus: OUTCOME_STATUS.CANCELLED,
            failureCategory: FAILURE_CATEGORIES.CANCELLED,
            stage: stageLabel,
            testPhase,
            repositoryTested: repoTested,
            rootError: gwRes.reason || 'Sandbox execution cancelled by operator/user.',
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: discoveredArtifact,
            retryEligible: guide.retryEligible,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `CANCELLED — ${gwRes.reason || 'Sandbox execution cancelled by operator/user.'}`
        };
    }

    if (gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
        const cat = gwRes.reasonCode === 'DEPENDENCY_UNAVAILABLE'
            ? FAILURE_CATEGORIES.RESTORE_FAILED
            : FAILURE_CATEGORIES.TEST_TOOL_MISSING;
        const guide = buildDiagnosticGuidance(cat, testPhase);
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status: 'COULD NOT RUN',
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            failureCategory: cat,
            stage: stageLabel,
            testPhase,
            repositoryTested: repoTested,
            rootError: gwRes.reason || 'Required dependencies or artifacts unavailable offline.',
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: discoveredArtifact,
            retryEligible: guide.retryEligible,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `COULD NOT RUN — ${gwRes.reason || 'Required dependencies or artifacts unavailable offline.'}`
        };
    }

    if (!gwRes.executed || gwRes.machineStatus === OUTCOME_STATUS.BLOCKED || gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
        const isSbxUnavail = gwRes.reasonCode === SANDBOX_READINESS.SANDBOX_UNAVAILABLE;
        const isToolchainUnavail = gwRes.failureCategory === FAILURE_CATEGORIES.TOOLCHAIN_IMAGE_UNAVAILABLE
            || gwRes.reasonCode === 'TOOLCHAIN_IMAGE_MISSING'
            || gwRes.reasonCode === 'UNPROVISIONED_TOOLCHAIN_PROFILE'
            || gwRes.reasonCode === 'TOOLCHAIN_IMAGE_UNAVAILABLE'
            || gwRes.reasonCode === 'TOOLCHAIN_UNAVAILABLE'
            || /Approved digest-pinned image.*is not present/i.test(gwRes.reason || '');
        const cat = isToolchainUnavail
            ? FAILURE_CATEGORIES.TOOLCHAIN_IMAGE_UNAVAILABLE
            : (isSbxUnavail ? FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE : FAILURE_CATEGORIES.EXECUTION_BLOCKED);
        const machineStatus = isToolchainUnavail ? OUTCOME_STATUS.COULD_NOT_RUN : OUTCOME_STATUS.BLOCKED;
        const status = isToolchainUnavail ? 'COULD NOT RUN' : (isSbxUnavail ? 'SANDBOX UNAVAILABLE' : 'BLOCKED');
        const guide = buildDiagnosticGuidance(cat, testPhase);
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status,
            machineStatus,
            failureCategory: cat,
            stage: stageLabel,
            testPhase,
            repositoryTested: repoTested,
            rootError: gwRes.reason || gwRes.summary || 'Execution blocked by sandbox security policy.',
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            testReportLocation: discoveredArtifact,
            retryEligible: false,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `${status} (${cat}) — ${gwRes.reason || 'Toolchain unavailable'}`
        };
    }

    // Parse genuine stdout/stderr emitted by the sandboxed execution
    const stdout = gwRes.stdout || '';
    const stderr = gwRes.stderr || '';
    const code = gwRes.exitCode;
    let parsed = {
        status: code === 0 ? 'UNTESTED' : 'FAIL',
        machineStatus: code === 0 ? OUTCOME_STATUS.UNTESTED : OUTCOME_STATUS.FAILED,
        failureCategory: code === 0 ? FAILURE_CATEGORIES.NO_TESTS_DISCOVERED : FAILURE_CATEGORIES.PARSE_FAILED,
        rootError: '',
        countsKnown: false,
        testsPassed: 0,
        testsFailed: 0,
        testsSkipped: 0,
        testsTotal: 0,
        compilationFailed: false
    };
    if (executable === 'dotnet') {
        const trxReports = options.trxContent ? [options.trxContent] : Object.entries(gwRes.outputArtifacts || {})
            .filter(([name, data]) => name.toLowerCase().endsWith('.trx') && data?.content)
            .map(([, data]) => data.content);
        const trxContent = trxReports[0] || null;

        const trxRequested = safeArgs.some(a => String(a).includes('trx') || String(a).includes('--logger') || String(a).includes('--report-trx'));

        const buildFail = /MSBUILD\s*:\s*error|Compilation failed|error\s+(?:CS|MSB)\d{4}:/i.test(stdout + '\n' + stderr) || (!trxContent && /Build FAILED/i.test(stdout + '\n' + stderr) && !parseDotnetOutput(stdout, stderr, code).testsFailed);
        const restoreFailed = /error NETSDK(?:1004|1064)|error NU110\d|error NU1301|Assets file .*project\.assets\.json.* not found|Unable to resolve/i.test(stdout + '\n' + stderr);
        const toolMissing = /dotnet:\s*command not found|not recognized as an internal or external command|ENOENT.*dotnet/i.test(stdout + '\n' + stderr) || code === 127;

        if (toolMissing) {
            parsed = {
                status: 'COULD NOT RUN',
                machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
                failureCategory: FAILURE_CATEGORIES.TEST_TOOL_MISSING,
                rootError: extractFirstMatchingLine(stdout + '\n' + stderr, [/not found|not recognized|ENOENT/i]) || 'dotnet CLI executable not available.',
                countsKnown: false,
                testsPassed: 0,
                testsFailed: 0,
                testsSkipped: 0,
                testsTotal: 0
            };
        } else if (restoreFailed) {
            parsed = {
                status: 'COULD NOT RUN',
                machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
                failureCategory: FAILURE_CATEGORIES.RESTORE_FAILED,
                rootError: extractFirstMatchingLine(stdout + '\n' + stderr, [/NETSDK(?:1004|1064)|NU110\d|NU1301|project\.assets\.json|Unable to resolve/i]) || 'Offline NuGet dependency restore assets unavailable.',
                countsKnown: false,
                testsPassed: 0,
                testsFailed: 0,
                testsSkipped: 0,
                testsTotal: 0
            };
        } else if (buildFail) {
            parsed = {
                status: 'FAIL',
                machineStatus: OUTCOME_STATUS.FAILED,
                failureCategory: FAILURE_CATEGORIES.BUILD_FAILED,
                rootError: extractFirstMatchingLine(stdout + '\n' + stderr, [/error (?:CS|MSB)\d+/i, /Build FAILED/i]) || 'C# / MSBuild compilation failed.',
                countsKnown: false,
                testsPassed: 0,
                testsFailed: 0,
                testsSkipped: 0,
                testsTotal: 0,
                compilationFailed: true
            };
        } else if (trxContent) {
            const trxCtx = {
                repositoryId: repoTested,
                runId,
                stageId: stageLabel,
                attemptId: options.attemptId || 1,
                command: `${executable} ${safeArgs.join(' ')}`
            };
            const trxRes = aggregateTrxReports(trxReports, trxCtx);
            const consoleParsed = parseDotnetOutput(stdout, stderr, code);

            if (code !== 0 && (!trxRes.valid || trxRes.testsTotal === 0) && !consoleParsed.countsKnown) {
                parsed = {
                    status: 'FAIL',
                    machineStatus: OUTCOME_STATUS.FAILED,
                    failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
                    rootError: extractFirstMatchingLine(stdout + '\n' + stderr, [/panic|error|failed/i]) || `dotnet test exited ${code} without recognizable test summary output.`,
                    countsKnown: false,
                    testsPassed: 0,
                    testsFailed: 0,
                    testsSkipped: 0,
                    testsTotal: 0,
                    compilationFailed: false
                };
            } else if (trxRes.valid && (trxRes.testsTotal > 0 || !consoleParsed.countsKnown || consoleParsed.testsTotal === 0)) {
                parsed = {
                    status: trxRes.status,
                    machineStatus: trxRes.machineStatus,
                    failureCategory: trxRes.failureCategory === FAILURE_CATEGORIES.NONE ? FAILURE_CATEGORIES.TESTS_PASSED : trxRes.failureCategory,
                    rootError: trxRes.rootError,
                    countsKnown: trxRes.countsKnown,
                    testsPassed: trxRes.testsPassed,
                    testsFailed: trxRes.testsFailed,
                    testsSkipped: trxRes.testsSkipped,
                    testsTotal: trxRes.testsTotal,
                    compilationFailed: false,
                    testFailures: trxRes.testFailures,
                    provenance: trxRes.provenance
                };
            } else if (consoleParsed.countsKnown && consoleParsed.testsTotal > 0) {
                parsed = consoleParsed;
            } else if (trxRes.valid) {
                parsed = {
                    status: trxRes.status,
                    machineStatus: trxRes.machineStatus,
                    failureCategory: trxRes.failureCategory === FAILURE_CATEGORIES.NONE ? FAILURE_CATEGORIES.TESTS_PASSED : trxRes.failureCategory,
                    rootError: trxRes.rootError,
                    countsKnown: trxRes.countsKnown,
                    testsPassed: trxRes.testsPassed,
                    testsFailed: trxRes.testsFailed,
                    testsSkipped: trxRes.testsSkipped,
                    testsTotal: trxRes.testsTotal,
                    compilationFailed: false,
                    testFailures: trxRes.testFailures,
                    provenance: trxRes.provenance
                };
            } else {
                parsed = {
                    status: 'FAIL',
                    machineStatus: OUTCOME_STATUS.FAILED,
                    failureCategory: FAILURE_CATEGORIES.PARSE_FAILED,
                    rootError: trxRes.rootError,
                    countsKnown: false,
                    testsPassed: 0,
                    testsFailed: 0,
                    testsSkipped: 0,
                    testsTotal: 0,
                    compilationFailed: false
                };
            }
        } else if (trxRequested) {
            const consoleParsed = parseDotnetOutput(stdout, stderr, code);
            const skipped = /Skipping running test for project|No test projects found|No test is available|Total tests:\s*0|\b0 tests found\b/i.test(stdout + '\n' + stderr);
            const runnerError = /Unrecognized command or argument|Unknown option/i.test(stdout + '\n' + stderr);

            if (skipped) {
                parsed = {
                    status: 'UNTESTED',
                    machineStatus: OUTCOME_STATUS.UNTESTED,
                    failureCategory: FAILURE_CATEGORIES.NO_TESTS_DISCOVERED,
                    rootError: consoleParsed.rootError || 'No test project detected or project skipped by runner.',
                    countsKnown: true,
                    testsPassed: 0,
                    testsFailed: 0,
                    testsSkipped: 0,
                    testsTotal: 0
                };
            } else if (runnerError) {
                parsed = {
                    status: 'FAIL',
                    machineStatus: OUTCOME_STATUS.FAILED,
                    failureCategory: FAILURE_CATEGORIES.EXECUTION_FAILED,
                    rootError: extractFirstMatchingLine(stdout + '\n' + stderr, [/Unrecognized|Unknown option/i]) || 'Test runner argument error.',
                    countsKnown: false,
                    testsPassed: 0,
                    testsFailed: 0,
                    testsSkipped: 0,
                    testsTotal: 0
                };
            } else if (consoleParsed.countsKnown && consoleParsed.testsTotal > 0) {
                parsed = consoleParsed;
            } else if (code !== 0) {
                parsed = consoleParsed;
            } else {
                parsed = {
                    status: code === 0 ? 'UNTESTED' : 'FAIL',
                    machineStatus: code === 0 ? OUTCOME_STATUS.UNTESTED : OUTCOME_STATUS.FAILED,
                    failureCategory: FAILURE_CATEGORIES.TEST_RESULTS_MISSING,
                    rootError: 'Test runner was invoked with TRX logger but no test results artifact was produced.',
                    countsKnown: false,
                    testsPassed: 0,
                    testsFailed: 0,
                    testsSkipped: 0,
                    testsTotal: 0
                };
            }
        } else {
            parsed = parseDotnetOutput(stdout, stderr, code);
        }
    } else if (executable === 'mvn') {
        parsed = parseMavenOutput(stdout, stderr, code);
    } else if (executable === 'npm') {
        parsed = parseNpmOutput(stdout, stderr, code);
    }

    if (parsed.machineStatus === OUTCOME_STATUS.PASSED && code !== 0) {
        parsed = { ...parsed, status: 'FAIL', machineStatus: OUTCOME_STATUS.FAILED,
            failureCategory: FAILURE_CATEGORIES.EXECUTION_FAILED,
            rootError: `Test process exited with code ${code} despite passing report counters.` };
    }

    const guide = buildDiagnosticGuidance(parsed.failureCategory, testPhase);
    let summary;
    let reason;
    if (parsed.machineStatus === OUTCOME_STATUS.PASSED) {
        summary = `PASS — Tests passed (${parsed.testsPassed}/${parsed.testsTotal}) via ${gwRes.backendType}, Exit Code: ${code}`;
        reason = 'All assertions passed inside isolated execution backend';
    } else if (parsed.machineStatus === OUTCOME_STATUS.UNTESTED) {
        summary = `UNTESTED — ${parsed.failureCategory === FAILURE_CATEGORIES.PARSE_FAILED ? 'Test summary could not be parsed' : 'Zero tests discovered/executed'} (Exit Code: ${code})`;
        reason = parsed.rootError || 'Zero tests executed where validation requires test coverage';
    } else if (parsed.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
        summary = `COULD NOT RUN (${parsed.failureCategory}) — ${parsed.rootError}`;
        reason = parsed.rootError;
    } else {
        const countPart = parsed.countsKnown
            ? `Passed: ${parsed.testsPassed}, Failed: ${parsed.testsFailed}, Skipped: ${parsed.testsSkipped}`
            : 'Test counts unknown (check root diagnostic)';
        summary = `FAIL (${parsed.failureCategory}) — ${countPart}, Exit Code: ${code}${parsed.rootError ? ` — ${parsed.rootError}` : ''}`;
        reason = parsed.rootError || (parsed.compilationFailed ? 'Compilation failed inside sandbox' : 'Test assertions failed inside sandbox');
    }

    return {
        ...gwRes,
        executed: parsed.machineStatus !== OUTCOME_STATUS.COULD_NOT_RUN,
        passed: parsed.machineStatus === OUTCOME_STATUS.PASSED,
        status: parsed.status,
        machineStatus: parsed.machineStatus,
        failureCategory: parsed.failureCategory,
        stage: stageLabel,
        testPhase,
        repositoryTested: repoTested,
        rootError: parsed.rootError || '',
        reason,
        countsKnown: parsed.countsKnown,
        testsTotal: parsed.testsTotal,
        testsPassed: parsed.testsPassed,
        testsFailed: parsed.testsFailed,
        testsSkipped: parsed.testsSkipped || 0,
        testReportLocation: executable === 'dotnet' ? (Object.keys(gwRes.outputArtifacts || {}).find(name => name.toLowerCase().endsWith('.trx')) || null) : discoveredArtifact,
        testFailures: parsed.testFailures || [],
        provenance: parsed.provenance || null,
        retryEligible: guide.retryEligible,
        suggestedNextAction: parsed.machineStatus === OUTCOME_STATUS.PASSED ? null : guide.suggestedNextAction,
        summary
    };
}

async function runBaselineTests(finding, workspaceRoot, options = {}) {
    const repoFull = resolveRepoWorkingDirectory(finding, workspaceRoot, options);

    if (options.envReport && options.envReport.sandboxAvailable === false) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE, 'BASELINE_SECURITY_TEST');
        return {
            executed: false,
            passed: false,
            status: 'SANDBOX UNAVAILABLE',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.BLOCKED,
            failureCategory: FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE,
            stage: 'Stage 3: Baseline Security Test',
            testPhase: 'BASELINE_SECURITY_TEST',
            repositoryTested: repoFull,
            workingDirectory: repoFull,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            reasonCode: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            reason: options.envReport.summary || 'Container runtime unavailable (SANDBOX_UNAVAILABLE)',
            rootError: options.envReport.summary || 'Container runtime unavailable (SANDBOX_UNAVAILABLE)',
            testReportLocation: null,
            retryEligible: false,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `SANDBOX UNAVAILABLE — ${options.envReport.summary || 'Container runtime unavailable'}`
        };
    }

    const runner = detectRunner(finding, repoFull);

    if (!runner) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.NO_TESTS_DISCOVERED, 'BASELINE_SECURITY_TEST');
        return {
            executed: false,
            passed: false,
            status: 'UNTESTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.UNTESTED,
            failureCategory: FAILURE_CATEGORIES.NO_TESTS_DISCOVERED,
            stage: 'Stage 3: Baseline Security Test',
            testPhase: 'BASELINE_SECURITY_TEST',
            repositoryTested: repoFull,
            workingDirectory: repoFull,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            rootError: `No supported build/test manifest (.sln/.csproj, pom.xml, package.json) detected for technology '${finding.Technology || 'unknown'}'.`,
            reason: 'No compatible test runner detected',
            testReportLocation: null,
            retryEligible: false,
            suggestedNextAction: guide.suggestedNextAction,
            summary: 'UNTESTED — No supported test runner detected for technology ' + (finding.Technology || 'unknown')
        };
    }

    if (runner.tool === 'dotnet' && !runner.hasTestProject) {
        return { executed: false, passed: false, status: 'UNTESTED', machineStatus: OUTCOME_STATUS.UNTESTED,
            failureCategory: FAILURE_CATEGORIES.TEST_PROJECT_NOT_FOUND, exitCode: null,
            countsKnown: true, testsTotal: 0, testsPassed: 0, testsFailed: 0, testsSkipped: 0,
            repositoryTested: repoFull, workingDirectory: repoFull, testReportLocation: null,
            rootError: 'No .NET test project was detected. A solution or stale TestResults directory is not a test suite.',
            summary: 'UNTESTED — No .NET test project detected.', retryEligible: false,
            suggestedNextAction: 'Add genuine tests, or acknowledge the separate development baseline exception where policy permits.' };
    }

    return await executeRealTestRunner(runner.tool, runner.args, repoFull, {
        ...options,
        workspaceRoot,
        finding,
        repositoryTested: repoFull,
        testPhase: 'BASELINE_SECURITY_TEST',
        stageLabel: 'Stage 3: Baseline Security Test'
    });
}

async function runPostFixTests(finding, workspaceRoot, options = {}) {
    const repoFull = resolveRepoWorkingDirectory(finding, workspaceRoot, options);

    if (options.envReport && options.envReport.sandboxAvailable === false) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE, 'POST_FIX_TEST');
        return {
            executed: false,
            passed: false,
            status: 'SANDBOX UNAVAILABLE',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.BLOCKED,
            failureCategory: FAILURE_CATEGORIES.SANDBOX_UNAVAILABLE,
            stage: 'Stage 5/6: Post-Fix Bench Test',
            testPhase: 'POST_FIX_TEST',
            repositoryTested: repoFull,
            workingDirectory: repoFull,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            reasonCode: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            reason: options.envReport.summary || 'Container runtime unavailable (SANDBOX_UNAVAILABLE)',
            rootError: options.envReport.summary || 'Container runtime unavailable (SANDBOX_UNAVAILABLE)',
            testReportLocation: null,
            retryEligible: false,
            suggestedNextAction: guide.suggestedNextAction,
            summary: `SANDBOX UNAVAILABLE — ${options.envReport.summary || 'Container runtime unavailable'}`
        };
    }

    const runner = detectRunner(finding, repoFull);

    if (!runner) {
        const guide = buildDiagnosticGuidance(FAILURE_CATEGORIES.NO_TESTS_DISCOVERED, 'POST_FIX_TEST');
        return {
            executed: false,
            passed: false,
            status: 'UNTESTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.UNTESTED,
            failureCategory: FAILURE_CATEGORIES.NO_TESTS_DISCOVERED,
            stage: 'Stage 5/6: Post-Fix Bench Test',
            testPhase: 'POST_FIX_TEST',
            repositoryTested: repoFull,
            workingDirectory: repoFull,
            exitCode: null,
            countsKnown: false,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            testsSkipped: 0,
            rootError: `No supported build/test manifest (.sln/.csproj, pom.xml, package.json) detected for technology '${finding.Technology || 'unknown'}'.`,
            reason: 'No compatible test runner detected',
            testReportLocation: null,
            retryEligible: false,
            suggestedNextAction: guide.suggestedNextAction,
            summary: 'UNTESTED — No supported test runner detected for technology ' + (finding.Technology || 'unknown')
        };
    }

    if (runner.tool === 'dotnet' && !runner.hasTestProject) {
        return { executed: false, passed: false, status: 'UNTESTED', machineStatus: OUTCOME_STATUS.UNTESTED,
            failureCategory: FAILURE_CATEGORIES.TEST_PROJECT_NOT_FOUND, exitCode: null,
            countsKnown: true, testsTotal: 0, testsPassed: 0, testsFailed: 0, testsSkipped: 0,
            repositoryTested: repoFull, workingDirectory: repoFull, testReportLocation: null,
            rootError: 'No .NET test project was detected. A solution or stale TestResults directory is not a test suite.',
            summary: 'UNTESTED — No .NET test project detected.', retryEligible: false,
            suggestedNextAction: 'Add genuine tests, or acknowledge the separate development baseline exception where policy permits.' };
    }

    return await executeRealTestRunner(runner.tool, runner.args, repoFull, {
        ...options,
        workspaceRoot,
        finding,
        repositoryTested: repoFull,
        testPhase: 'POST_FIX_TEST',
        stageLabel: 'Stage 5/6: Post-Fix Bench Test'
    });
}

function screenTestOutput(text, options = {}) {
    const screen = options.injectionScreen || new ContentInjectionScreen();
    return screen.screen({
        text: typeof text === 'string' ? text : '',
        contentSource: options.contentSource || 'testRunner:output',
        trustClass: options.trustClass || TRUST_CLASSES.UNTRUSTED_BUILD_TEST_OUTPUT,
        runId: options.runId || 'test-runner',
        filePath: options.filePath || 'test-output'
    });
}

module.exports = {
    FAILURE_CATEGORIES,
    isExecutableAvailable,
    detectRunner,
    inspectDotnetProjects,
    detectDotnetRunnerFramework,
    parseTrxReport,
    aggregateTrxReports,
    parseDotnetOutput,
    parseMavenOutput,
    parseNpmOutput,
    discoverTestReportArtifacts,
    executeRealTestRunner,
    runBaselineTests,
    runPostFixTests,
    screenTestOutput
};
