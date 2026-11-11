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

/**
 * Deterministic Test Runner for GCAC Vulnerability Remediation
 * 
 * Strict Principle:
 * ZERO SYNTHETIC CONSOLE OUTPUT. ZERO FABRICATED TEST COUNTS.
 * Executes genuine compilers and test runners installed on the developer machine.
 * If the required runtime is unavailable, records:
 * "NOT EXECUTED — Required runtime unavailable"
 */

const ALLOWED_EXECUTABLES = new Set(['dotnet', 'mvn', 'npm']);
const DEFAULT_TIMEOUT_MS = 60000; // 60 seconds

/**
 * Checks whether an executable exists on the system PATH
 * @param {string} executableName 
 * @returns {boolean}
 */
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
 * Detects the appropriate test runner for a given finding and repository
 * @param {object} finding 
 * @param {string} repoFullPath 
 * @returns {{ tool: string, args: string[] } | null}
 */
function detectRunner(finding, repoFullPath) {
    const tech = (finding?.Technology || '').toLowerCase();

    // 1. Check technology declaration
    if (tech === 'dotnet' || tech === 'csharp' || tech === '.net') {
        return { tool: 'dotnet', args: ['test', '--nologo', '-v', 'normal'] };
    }
    if (tech === 'java' || tech === 'java-spring') {
        return { tool: 'mvn', args: ['test', '-B'] };
    }
    if (tech === 'javascript' || tech === 'typescript' || tech === 'node') {
        return { tool: 'npm', args: ['test', '--', '--watchAll=false'] };
    }

    // 2. Inspect repository files on disk if repo path exists
    if (repoFullPath && fs.existsSync(repoFullPath)) {
        if (fs.existsSync(path.join(repoFullPath, 'pom.xml'))) {
            return { tool: 'mvn', args: ['test', '-B'] };
        }
        if (fs.existsSync(path.join(repoFullPath, 'package.json'))) {
            return { tool: 'npm', args: ['test'] };
        }
        try {
            const files = fs.readdirSync(repoFullPath);
            if (files.some(f => f.endsWith('.sln') || f.endsWith('.csproj'))) {
                return { tool: 'dotnet', args: ['test', '--nologo', '-v', 'normal'] };
            }
        } catch (e) {}
    }

    // Default fallback based on finding technology
    return { tool: 'dotnet', args: ['test', '--nologo', '-v', 'normal'] };
}

/**
 * Parses test output for dotnet test
 */
function parseDotnetOutput(stdout, stderr, exitCode) {
    const combined = stdout + '\n' + stderr;
    let testsPassed = 0;
    let testsFailed = 0;
    let testsSkipped = 0;
    let testsTotal = 0;

    const totalMatch = combined.match(/Total tests:\s*(\d+)/i) || combined.match(/Total:\s*(\d+)/i);
    const passedMatch = combined.match(/Passed:\s*(\d+)/i);
    const failedMatch = combined.match(/Failed:\s*(\d+)/i);
    const skippedMatch = combined.match(/Skipped:\s*(\d+)/i);

    if (passedMatch) testsPassed = parseInt(passedMatch[1], 10);
    if (failedMatch) testsFailed = parseInt(failedMatch[1], 10);
    if (skippedMatch) testsSkipped = parseInt(skippedMatch[1], 10);

    if (totalMatch) {
        testsTotal = parseInt(totalMatch[1], 10);
    } else {
        testsTotal = testsPassed + testsFailed + testsSkipped;
    }

    const compilationFailed = /Build FAILED/i.test(combined) || /CS\d{4}:/i.test(combined);

    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;
    if (compilationFailed || exitCode !== 0 || testsFailed > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
    }

    return {
        status,
        machineStatus,
        testsPassed,
        testsFailed,
        testsSkipped,
        testsTotal,
        compilationFailed
    };
}

/**
 * Parses test output for Maven (mvn test)
 */
function parseMavenOutput(stdout, stderr, exitCode) {
    const combined = stdout + '\n' + stderr;
    let testsPassed = 0;
    let testsFailed = 0;
    let testsErrors = 0;
    let testsSkipped = 0;
    let testsTotal = 0;

    const summaryMatch = combined.match(/Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)/i);
    if (summaryMatch) {
        testsTotal = parseInt(summaryMatch[1], 10);
        testsFailed = parseInt(summaryMatch[2], 10);
        testsErrors = parseInt(summaryMatch[3], 10);
        testsSkipped = parseInt(summaryMatch[4], 10);
        testsPassed = Math.max(0, testsTotal - testsFailed - testsErrors - testsSkipped);
    }

    const buildFailure = /BUILD FAILURE/i.test(combined);
    const compilationFailed = /Compilation failure/i.test(combined) || /\[ERROR\] COMPILATION ERROR/i.test(combined);

    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;
    if (buildFailure || compilationFailed || exitCode !== 0 || testsFailed > 0 || testsErrors > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
    }

    return {
        status,
        machineStatus,
        testsPassed,
        testsFailed: testsFailed + testsErrors,
        testsSkipped,
        testsTotal,
        compilationFailed
    };
}

/**
 * Parses test output for npm test
 */
function parseNpmOutput(stdout, stderr, exitCode) {
    const combined = stdout + '\n' + stderr;
    let testsPassed = 0;
    let testsFailed = 0;
    let testsTotal = 0;

    const passMatch = combined.match(/Tests:\s*(\d+)\s*passed/i) || combined.match(/Passed Suites:\s*(\d+)/i);
    const failMatch = combined.match(/Tests:\s*(\d+)\s*failed/i) || combined.match(/Failed Suites:\s*(\d+)/i);
    const totalMatch = combined.match(/Tests:\s*(\d+)\s*total/i) || combined.match(/Total Suites:\s*(\d+)/i);

    if (passMatch) testsPassed = parseInt(passMatch[1], 10);
    if (failMatch) testsFailed = parseInt(failMatch[1], 10);
    if (totalMatch) testsTotal = parseInt(totalMatch[1], 10);
    else testsTotal = testsPassed + testsFailed;

    const compilationFailed = exitCode !== 0 && testsTotal === 0;
    let status = 'PASS';
    let machineStatus = OUTCOME_STATUS.PASSED;

    if (exitCode !== 0 || testsFailed > 0) {
        status = 'FAIL';
        machineStatus = OUTCOME_STATUS.FAILED;
    } else if (testsTotal <= 0) {
        status = 'UNTESTED';
        machineStatus = OUTCOME_STATUS.UNTESTED;
    }

    return {
        status,
        machineStatus,
        testsPassed,
        testsFailed,
        testsSkipped: 0,
        testsTotal,
        compilationFailed
    };
}

/**
 * Redacts common sensitive information patterns from console outputs
 */
function redactSensitiveOutput(text) {
    if (!text) return '';
    return text
        .replace(/(?:api[_-]?key|secret|password|token|bearer\s+)["':= ]+([A-Za-z0-9_-]{12,})/gi, 'REDACTED_SECRET')
        .replace(/(?:ghp_[A-Za-z0-9]{36})/g, 'ghp_REDACTED');
}

/**
 * Safely executes a genuine test command in the repository workspace
 * @param {string} executable Allowlisted executable ('dotnet', 'mvn', 'npm')
 * @param {string[]} args Command arguments
 * @param {string} cwd Working directory
 * @param {object} options Optional execution parameters { timeoutMs, cancellationToken }
 * @returns {Promise<object>} Structured execution result
 */
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

/**
 * Safely executes an approved test/build operation via TrustedExecutionGateway.
 * Never falls back silently to host shell execution when sandbox is unavailable.
 * @param {string} executable Allowlisted executable ('dotnet', 'mvn', 'npm')
 * @param {string[]} args Command arguments
 * @param {string} cwd Working directory
 * @param {object} options Optional execution parameters { timeoutMs, cancellationToken, executionGateway, sandboxBackend, envReport, finding }
 * @returns {Promise<object>} Structured execution result
 */
async function executeRealTestRunner(executable, args = [], cwd, options = {}) {
    const startTime = new Date();
    const startTimeIso = startTime.toISOString();
    const safeArgs = Array.isArray(args) ? args : [];

    // 1. Enforce executable allowlist (preserves Phase 1/2 security assertion)
    if (!ALLOWED_EXECUTABLES.has(executable)) {
        const endTime = new Date();
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.BLOCKED,
            reason: `Unauthorized test runner executable: '${executable}'`,
            executable,
            command: `${executable} ${safeArgs.join(' ')}`,
            workingDirectory: cwd,
            startTime: startTimeIso,
            endTime: endTime.toISOString(),
            durationMs: 0,
            exitCode: null,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            stdout: '',
            stderr: `Executable '${executable}' is not in the approved security allowlist.`,
            summary: `NOT EXECUTED — Unauthorized executable '${executable}'`
        };
    }

    // 2. Verify working directory exists
    if (!cwd || !fs.existsSync(cwd)) {
        const endTime = new Date();
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            reason: 'Working directory not found',
            executable,
            command: `${executable} ${safeArgs.join(' ')}`,
            workingDirectory: cwd,
            startTime: startTimeIso,
            endTime: endTime.toISOString(),
            durationMs: 0,
            exitCode: null,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            stdout: '',
            stderr: `Working directory does not exist on disk: '${cwd}'`,
            summary: `NOT EXECUTED — Working directory not found: ${cwd}`
        };
    }

    // 3. Resolve approved declarative toolchain profile (no host fallback)
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
            profile = resolveProfileForRepository(cwd, { Technology: techHint }, options.profilesPath);
        } catch (err) {
            const endTime = new Date();
            const code = err instanceof ToolchainProfileError ? err.code : 'TOOLCHAIN_PROFILE_BLOCKED';
            return {
                executed: false,
                passed: false,
                status: 'BLOCKED',
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode: code,
                reason: err.message,
                executable,
                command: `${executable} ${safeArgs.join(' ')}`,
                workingDirectory: cwd,
                startTime: startTimeIso,
                endTime: endTime.toISOString(),
                durationMs: 0,
                exitCode: null,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                stdout: '',
                stderr: err.message,
                summary: `BLOCKED (${code}) — ${err.message}`
            };
        }
    }

    // 4. Construct typed ExecutionRequest and dispatch strictly through TrustedExecutionGateway
    const { operation, extraArgs } = mapToolAndArgsToOperation(executable, safeArgs);
    const chosenOp = options.operation || operation;
    const finding = options.finding || {};
    const runId = options.runId || `run-${Date.now().toString(36)}`;
    const appId = options.applicationId || finding.Application_Number || 'APP-DEFAULT';
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

    // Preserve explicit cancel / timeout / blocked / could_not_run classifications cleanly
    if (gwRes.timedOut || gwRes.machineStatus === OUTCOME_STATUS.TIMED_OUT) {
        return {
            ...gwRes,
            executed: true,
            passed: false,
            status: 'TIMED OUT',
            machineStatus: OUTCOME_STATUS.TIMED_OUT,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            summary: `TIMED OUT — ${gwRes.reason || 'Sandbox execution exceeded timeout limit.'}`
        };
    }

    if (gwRes.cancelled || gwRes.machineStatus === OUTCOME_STATUS.CANCELLED) {
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status: 'CANCELLED',
            machineStatus: OUTCOME_STATUS.CANCELLED,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            summary: `CANCELLED — ${gwRes.reason || 'Sandbox execution cancelled by operator/user.'}`
        };
    }

    if (gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status: 'COULD NOT RUN',
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0,
            summary: `COULD NOT RUN — ${gwRes.reason || 'Required dependencies or artifacts unavailable offline.'}`
        };
    }

    if (!gwRes.executed || gwRes.machineStatus === OUTCOME_STATUS.BLOCKED) {
        return {
            ...gwRes,
            executed: false,
            passed: false,
            status: gwRes.reasonCode === SANDBOX_READINESS.SANDBOX_UNAVAILABLE ? 'SANDBOX UNAVAILABLE' : 'BLOCKED',
            machineStatus: OUTCOME_STATUS.BLOCKED,
            testsTotal: 0,
            testsPassed: 0,
            testsFailed: 0
        };
    }

    // 5. Parse real stdout/stderr emitted by the sandboxed execution
    const stdout = gwRes.stdout || '';
    const stderr = gwRes.stderr || '';
    const code = gwRes.exitCode;
    let parsed = {
        status: code === 0 ? 'UNTESTED' : 'FAIL',
        machineStatus: code === 0 ? OUTCOME_STATUS.UNTESTED : OUTCOME_STATUS.FAILED,
        testsPassed: 0,
        testsFailed: 0,
        testsTotal: 0
    };
    if (executable === 'dotnet') {
        parsed = parseDotnetOutput(stdout, stderr, code);
    } else if (executable === 'mvn') {
        parsed = parseMavenOutput(stdout, stderr, code);
    } else if (executable === 'npm') {
        parsed = parseNpmOutput(stdout, stderr, code);
    }

    let summary;
    let reason;
    if (parsed.machineStatus === OUTCOME_STATUS.PASSED) {
        summary = `PASS — Tests passed (${parsed.testsPassed}/${parsed.testsTotal}) via ${gwRes.backendType}, Exit Code: ${code}`;
        reason = 'All assertions passed inside isolated execution backend';
    } else if (parsed.machineStatus === OUTCOME_STATUS.UNTESTED) {
        summary = `UNTESTED — Sandbox process exited 0 but zero tests executed (${parsed.testsPassed}/${parsed.testsTotal})`;
        reason = 'Zero tests executed where validation requires test coverage';
    } else {
        summary = `FAIL — Test run failed (Passed: ${parsed.testsPassed}, Failed: ${parsed.testsFailed}), Exit Code: ${code}`;
        reason = parsed.compilationFailed ? 'Compilation failed inside sandbox' : 'Test assertions failed inside sandbox';
    }

    return {
        ...gwRes,
        executed: true,
        passed: parsed.machineStatus === OUTCOME_STATUS.PASSED,
        status: parsed.status,
        machineStatus: parsed.machineStatus,
        reason,
        testsTotal: parsed.testsTotal,
        testsPassed: parsed.testsPassed,
        testsFailed: parsed.testsFailed,
        summary
    };
}

/**
 * Runs genuine baseline tests on the target repository before code changes are applied
 * @param {object} finding Finding from vulnerabilities.csv
 * @param {string} workspaceRoot Workspace root directory
 * @returns {Promise<object>} Baseline test results
 */
async function runBaselineTests(finding, workspaceRoot, options = {}) {
    const repoRel = finding.Repository || '';
    const repoFull = options.workingDirectory || (repoRel ? path.join(workspaceRoot, repoRel) : workspaceRoot);
    const runner = detectRunner(finding, repoFull);

    if (!runner) {
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            reason: 'No compatible test runner detected',
            summary: 'NOT EXECUTED — No test runner detected for technology ' + (finding.Technology || 'unknown')
        };
    }

    return await executeRealTestRunner(runner.tool, runner.args, repoFull, {
        ...options,
        workspaceRoot,
        finding
    });
}

/**
 * Runs genuine post-fix tests on the target repository after code changes are applied
 * @param {object} finding Finding from vulnerabilities.csv
 * @param {string} workspaceRoot Workspace root directory
 * @returns {Promise<object>} Post-fix test results
 */
async function runPostFixTests(finding, workspaceRoot, options = {}) {
    const repoRel = finding.Repository || '';
    const repoFull = options.workingDirectory || (repoRel ? path.join(workspaceRoot, repoRel) : workspaceRoot);
    const runner = detectRunner(finding, repoFull);

    if (!runner) {
        return {
            executed: false,
            passed: false,
            status: 'NOT EXECUTED',
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
            reason: 'No compatible test runner detected',
            summary: 'NOT EXECUTED — No test runner detected for technology ' + (finding.Technology || 'unknown')
        };
    }

    return await executeRealTestRunner(runner.tool, runner.args, repoFull, {
        ...options,
        workspaceRoot,
        finding
    });
}

/**
 * Screens untrusted test output or test names via ContentInjectionScreen.
 */
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
    isExecutableAvailable,
    detectRunner,
    parseDotnetOutput,
    parseMavenOutput,
    parseNpmOutput,
    executeRealTestRunner,
    runBaselineTests,
    runPostFixTests,
    screenTestOutput
};
