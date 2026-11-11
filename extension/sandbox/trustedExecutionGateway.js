'use strict';

const fs = require('fs');
const path = require('path');
const { OUTCOME_STATUS } = require('../outcomeContract');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('../contentInjectionScreen');
const { SANDBOX_READINESS } = require('./environmentDiscovery');
const {
    SANDBOX_LIFECYCLE_STATES,
    BACKEND_TYPES,
    selectExecutionBackend
} = require('./executionBackend');
const {
    getApprovedProfile,
    resolveProfileForRepository,
    isTemplateDigestProfile,
    ToolchainProfileError
} = require('./toolchainProfiles');
const { evaluateNetworkPolicy, NetworkPolicyError } = require('./networkPolicy');
const { assessDependencyGovernance, detectDependencyRestoreFailure } = require('./dependencyGovernance');
const { SandboxLifecycleManager } = require('./sandboxLifecycleManager');

const EXECUTION_POLICY_VERSION = 'GCAC-PH3-GW-1.0';

const OPERATION_TYPES = Object.freeze({
    DOTNET_BUILD: 'DOTNET_BUILD',
    DOTNET_TEST: 'DOTNET_TEST',
    MAVEN_COMPILE: 'MAVEN_COMPILE',
    MAVEN_TEST: 'MAVEN_TEST',
    NPM_TEST: 'NPM_TEST',
    SECURITY_SCAN: 'SECURITY_SCAN',
    TARGETED_RESCAN: 'TARGETED_RESCAN',
    NUGET_AUDIT: 'NUGET_AUDIT',
    SBOM_GENERATION: 'SBOM_GENERATION'
});

const UNTRUSTED_ARG_METACHARS = /[;&|`$<>!\r\n\0]/;

class ExecutionGatewayError extends Error {
    constructor(reason, code = 'EXECUTION_GATEWAY_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'ExecutionGatewayError';
        this.code = code;
        this.machineStatus = OUTCOME_STATUS.BLOCKED;
        this.details = details;
    }
}

function redactSensitiveOutput(text) {
    if (!text) return '';
    return String(text)
        .replace(/(?:api[_-]?key|secret|password|token|bearer\s+)["':= ]+([A-Za-z0-9_-]{8,})/gi, 'REDACTED_SECRET')
        .replace(/(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, 'ghp_REDACTED')
        .replace(/\b[sr]k_(?:live|test)_[0-9A-Za-z]{8,}\b/g, 'sk_REDACTED')
        .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'AKIA_REDACTED');
}

/**
 * Single application-controlled Trusted Execution Gateway for GCAC Phase 3.
 * Enforces typed operations, declarative approved toolchain profiles,
 * network policy, dependency governance, isolated backend availability,
 * and audit logging.
 *
 * Security Boundary Disclosure:
 * This gateway enforces all extension-originated build, test, and build-backed scan
 * operations. It does NOT intercept native GitHub Copilot Chat built-in terminal tools.
 */
class TrustedExecutionGateway {
    constructor(options = {}) {
        this.workspaceRoot = options.workspaceRoot || process.cwd();
        this.profilesPath = options.profilesPath || undefined;
        this.backend = options.backend || null;
        this.envReport = options.envReport || null;
        this.lifecycleManager = options.lifecycleManager || new SandboxLifecycleManager({
            stateDir: options.lifecycleStateDir || null
        });
        this.injectionScreen = options.injectionScreen || new ContentInjectionScreen();
        this.auditDecisions = [];
        this.gatewayBoundaryNote =
            'TrustedExecutionGateway governs application-controlled build, test, and scan subprocesses; ' +
            'native Copilot Chat agent tools operate outside VS Code Extension Host interception.';
    }

    _recordAuditDecision(entry) {
        const sanitized = {
            timestamp: new Date().toISOString(),
            runId: entry.runId || 'unbound',
            instanceId: entry.instanceId || null,
            vulnerabilityId: entry.vulnerabilityId || null,
            operation: entry.operation || null,
            toolchainProfileId: entry.toolchainProfileId || null,
            decision: entry.decision,
            reasonCode: entry.reasonCode,
            reason: redactSensitiveOutput(entry.reason || ''),
            backendType: entry.backendType || 'NONE',
            policyVersion: EXECUTION_POLICY_VERSION
        };
        this.auditDecisions.push(sanitized);
        if (this.auditDecisions.length > 500) this.auditDecisions.shift();
        return sanitized;
    }

    getAuditDecisions(runId = null) {
        if (!runId) return [...this.auditDecisions];
        return this.auditDecisions.filter(d => d.runId === runId);
    }

    /**
     * Strictly validates typed execution request schema and rejects free-form commands or injection.
     */
    validateExecutionRequest(request) {
        if (!request || typeof request !== 'object') {
            throw new ExecutionGatewayError('Execution request must be a structured object.', 'MALFORMED_REQUEST');
        }

        if (request.rawCommand || request.shellCommand || request.commandLine) {
            throw new ExecutionGatewayError(
                'Arbitrary shell commands / free-form command strings are rejected by TrustedExecutionGateway.',
                'FREEFORM_COMMAND_REJECTED'
            );
        }

        const requiredStrings = ['runId', 'applicationId', 'vulnerabilityId', 'workspaceRef', 'operation', 'toolchainProfileId', 'policyVersion'];
        for (const field of requiredStrings) {
            if (!request[field] || typeof request[field] !== 'string' || !request[field].trim()) {
                throw new ExecutionGatewayError(`Mandatory execution request field '${field}' is missing or empty.`, 'MISSING_REQUIRED_FIELD', { field });
            }
        }

        if (!/^[A-Za-z0-9_.-]{6,128}$/.test(request.runId.trim())) {
            throw new ExecutionGatewayError('Invalid runId format.', 'INVALID_RUN_ID');
        }
        if (!/^[A-Za-z0-9_.-]{3,64}$/.test(request.vulnerabilityId.trim()) || /^(?:ALL|ANY|BATCH|MULTI)/i.test(request.vulnerabilityId.trim())) {
            throw new ExecutionGatewayError(`SEC-02: Invalid or multi-finding vulnerabilityId '${request.vulnerabilityId}'.`, 'INVALID_VULNERABILITY_ID');
        }
        if (request.applicationId.includes(',')) {
            throw new ExecutionGatewayError('SEC-02: Multiple application IDs in single execution request are prohibited.', 'AMBIGUOUS_APPLICATION_ID');
        }
        if (!Object.values(OPERATION_TYPES).includes(request.operation)) {
            throw new ExecutionGatewayError(`Unknown or unsupported operation '${request.operation}'.`, 'UNKNOWN_OPERATION');
        }
        if (request.policyVersion !== EXECUTION_POLICY_VERSION) {
            throw new ExecutionGatewayError(
                `Unsupported execution policy version '${request.policyVersion}'. Expected '${EXECUTION_POLICY_VERSION}'.`,
                'POLICY_VERSION_MISMATCH'
            );
        }
        if (!Array.isArray(request.inputs)) {
            throw new ExecutionGatewayError('Execution request field "inputs" must be an array.', 'INVALID_INPUTS');
        }
        for (const inp of request.inputs) {
            if (typeof inp !== 'string' || inp.includes('\0') || inp.includes('..') || path.isAbsolute(inp)) {
                throw new ExecutionGatewayError(`Unsafe input path '${inp}' rejected.`, 'UNSAFE_INPUT_PATH');
            }
        }
        if (!Array.isArray(request.expectedOutputPaths)) {
            throw new ExecutionGatewayError('Execution request field "expectedOutputPaths" must be an array.', 'INVALID_OUTPUT_PATHS');
        }
        for (const outP of request.expectedOutputPaths) {
            if (typeof outP !== 'string' || outP.includes('\0') || outP.includes('..')) {
                throw new ExecutionGatewayError(`Unsafe expected output path '${outP}' rejected.`, 'UNSAFE_OUTPUT_PATH');
            }
        }
        if (!request.resourcePolicy || typeof request.resourcePolicy !== 'object') {
            throw new ExecutionGatewayError('Execution request field "resourcePolicy" is required.', 'MISSING_RESOURCE_POLICY');
        }
        if (!fs.existsSync(request.workspaceRef)) {
            throw new ExecutionGatewayError(`Approved workspace reference does not exist: '${request.workspaceRef}'.`, 'WORKSPACE_NOT_FOUND');
        }

        // Validate against approved, tamper-checked declarative toolchain profile
        const profile = getApprovedProfile(request.toolchainProfileId, this.profilesPath);
        const cmdTemplate = profile.approvedCommands?.[request.operation];
        if (!cmdTemplate) {
            throw new ExecutionGatewayError(
                `Operation '${request.operation}' is not permitted by toolchain profile '${profile.profileId}'.`,
                'OPERATION_NOT_SUPPORTED_BY_PROFILE'
            );
        }

        if (request.requestedExecutable && request.requestedExecutable !== cmdTemplate.executable) {
            throw new ExecutionGatewayError(
                `Unauthorized executable '${request.requestedExecutable}' rejected; profile '${profile.profileId}' requires '${cmdTemplate.executable}'.`,
                'UNAPPROVED_EXECUTABLE'
            );
        }

        const extraArgs = Array.isArray(request.extraArgs) ? request.extraArgs : [];
        const permittedSet = new Set(profile.permittedArguments || []);
        for (const arg of extraArgs) {
            const s = String(arg ?? '');
            if (UNTRUSTED_ARG_METACHARS.test(s)) {
                throw new ExecutionGatewayError(`Shell metacharacter / control character detected in argument '${s}'.`, 'COMMAND_INJECTION_BLOCKED');
            }
            if (!permittedSet.has(s)) {
                throw new ExecutionGatewayError(`Unapproved argument '${s}' rejected for profile '${profile.profileId}'.`, 'UNAPPROVED_ARGUMENT');
            }
        }

        const finalArgs = [...cmdTemplate.baseArgs, ...extraArgs];
        const limits = {
            timeoutMs: Math.min(Number(request.resourcePolicy.timeoutMs || profile.runtimeLimits.timeoutMs), profile.runtimeLimits.timeoutMs),
            memoryMb: Math.min(Number(request.resourcePolicy.memoryMb || profile.runtimeLimits.memoryMb), profile.runtimeLimits.memoryMb),
            cpus: Math.min(Number(request.resourcePolicy.cpus || profile.runtimeLimits.cpus), profile.runtimeLimits.cpus),
            pidsLimit: Math.min(Number(request.resourcePolicy.pidsLimit || profile.runtimeLimits.pidsLimit), profile.runtimeLimits.pidsLimit)
        };

        return {
            profile,
            executable: cmdTemplate.executable,
            approvedArgs: finalArgs,
            limits
        };
    }

    /**
     * Executes an approved typed operation inside an isolated execution backend.
     * Strictly blocks execution with SANDBOX_UNAVAILABLE when no approved sandbox exists
     * — never falls back silently to host shell.
     */
    async executeOperation(request = {}, options = {}) {
        let validated;
        try {
            validated = this.validateExecutionRequest(request);
        } catch (err) {
            const reasonCode = err.code || 'VALIDATION_FAILED';
            this._recordAuditDecision({
                runId: request?.runId,
                vulnerabilityId: request?.vulnerabilityId,
                operation: request?.operation,
                toolchainProfileId: request?.toolchainProfileId,
                decision: 'DENIED',
                reasonCode,
                reason: err.message
            });
            return {
                executed: false,
                passed: false,
                status: 'BLOCKED',
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode,
                reason: err.message,
                executable: request?.requestedExecutable || null,
                command: 'BLOCKED',
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                exitCode: null,
                durationMs: 0,
                stdout: '',
                stderr: err.message,
                summary: `BLOCKED (${reasonCode}) — ${err.message}`
            };
        }

        const { profile, executable, approvedArgs, limits } = validated;

        // Evaluate network egress policy
        let netPolicy;
        try {
            netPolicy = evaluateNetworkPolicy(
                {
                    workspaceRef: request.workspaceRef,
                    networkPolicy: request.networkPolicy || profile.networkPolicy || 'NO_NETWORK',
                    isControlledRestoreOperation: request.isControlledRestoreOperation === true,
                    requestedFeeds: request.requestedFeeds || []
                },
                options
            );
        } catch (err) {
            const code = err instanceof NetworkPolicyError ? err.code : 'NETWORK_POLICY_BLOCKED';
            this._recordAuditDecision({
                runId: request.runId,
                vulnerabilityId: request.vulnerabilityId,
                operation: request.operation,
                toolchainProfileId: profile.profileId,
                decision: 'DENIED',
                reasonCode: code,
                reason: err.message
            });
            return {
                executed: false,
                passed: false,
                status: 'BLOCKED',
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode: code,
                reason: err.message,
                executable,
                command: `${executable} ${approvedArgs.join(' ')}`,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                exitCode: null,
                durationMs: 0,
                stdout: '',
                stderr: err.message,
                summary: `BLOCKED (${code}) — ${err.message}`
            };
        }

        // Evaluate dependency governance
        const depGov = assessDependencyGovernance(request.workspaceRef, profile.supportedStack, options);
        if (!depGov.allowed) {
            this._recordAuditDecision({
                runId: request.runId,
                vulnerabilityId: request.vulnerabilityId,
                operation: request.operation,
                toolchainProfileId: profile.profileId,
                decision: 'DENIED',
                reasonCode: 'DEPENDENCY_POLICY_BLOCKED',
                reason: depGov.reason
            });
            return {
                executed: false,
                passed: false,
                status: 'BLOCKED',
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode: 'DEPENDENCY_POLICY_BLOCKED',
                reason: depGov.reason,
                dependencyStatus: depGov.dependencyStatus,
                executable,
                command: `${executable} ${approvedArgs.join(' ')}`,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                exitCode: null,
                durationMs: 0,
                stdout: '',
                stderr: depGov.reason,
                summary: `BLOCKED (DEPENDENCY_POLICY_BLOCKED) — ${depGov.reason}`
            };
        }

        // Check approved ExecutionBackend availability (fail closed on SANDBOX_UNAVAILABLE)
        const selected = await selectExecutionBackend({
            backend: options.backend || this.backend,
            envReport: options.envReport || this.envReport,
            workspaceRoot: this.workspaceRoot,
            preferEphemeralCiAdapter: options.preferEphemeralCiAdapter === true
        });
        const backend = selected.backend;
        const avail = selected.availability;

        const instance = this.lifecycleManager.createInstance({
            runId: request.runId,
            vulnerabilityId: request.vulnerabilityId,
            applicationId: request.applicationId,
            operation: request.operation,
            backendType: avail.backendType || BACKEND_TYPES.NONE,
            toolchainProfileId: profile.profileId
        });

        if (!avail.available) {
            const blockMsg = `SANDBOX_UNAVAILABLE: ${avail.reason} Host-shell fallback is prohibited.`;
            this.lifecycleManager.transition(instance.instanceId, SANDBOX_LIFECYCLE_STATES.BLOCKED, blockMsg, {
                reasonCode: SANDBOX_READINESS.SANDBOX_UNAVAILABLE
            });
            this._recordAuditDecision({
                runId: request.runId,
                instanceId: instance.instanceId,
                vulnerabilityId: request.vulnerabilityId,
                operation: request.operation,
                toolchainProfileId: profile.profileId,
                decision: 'DENIED',
                reasonCode: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                reason: blockMsg,
                backendType: avail.backendType
            });
            return {
                executed: false,
                passed: false,
                status: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                reason: blockMsg,
                prerequisites: avail.prerequisites || [],
                instanceId: instance.instanceId,
                runId: request.runId,
                operationId: request.operation,
                backendType: avail.backendType || BACKEND_TYPES.NONE,
                toolchainProfileId: profile.profileId,
                toolchainProfileHash: profile.profileSha256,
                imageDigest: profile.imageDigest,
                networkPolicy: netPolicy.policyMode,
                dependencyStatus: depGov.dependencyStatus,
                executable,
                approvedArgs,
                command: `${executable} ${approvedArgs.join(' ')}`,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                exitCode: null,
                durationMs: 0,
                stdout: '',
                stderr: blockMsg,
                lifecycleHistory: instance.history,
                gatewayBoundaryNote: this.gatewayBoundaryNote,
                summary: `SANDBOX_UNAVAILABLE — ${avail.reason}`
            };
        }

        // Prepare sandbox environment
        let preparedEnv;
        try {
            this.lifecycleManager.transition(instance.instanceId, SANDBOX_LIFECYCLE_STATES.PREPARING, 'Staging credential-free source snapshot.');
            preparedEnv = await backend.prepareEnvironment(
                {
                    ...request,
                    instanceId: instance.instanceId,
                    originalWorkspaceRoot: options.originalWorkspaceRoot || this.workspaceRoot,
                    memoryMb: limits.memoryMb,
                    cpus: limits.cpus,
                    pidsLimit: limits.pidsLimit,
                    timeoutMs: limits.timeoutMs
                },
                {
                    imageRef: profile.imageRef,
                    approvedDigests: [profile.imageDigest],
                    networkMode: netPolicy.containerNetworkMode,
                    allowIsolatedMirrorNetwork: netPolicy.allowIsolatedMirrorNetwork,
                    memoryMb: limits.memoryMb,
                    cpus: limits.cpus,
                    pidsLimit: limits.pidsLimit,
                    timeoutMs: limits.timeoutMs,
                    requirePrePulledImage: options.requirePrePulledImage !== false,
                    allowGitMetadata: false,
                    allowCacheReuse: options.allowCacheReuse === true || Boolean(options.appCacheDir || options.preprovisionedCacheDir),
                    appCacheDir: options.appCacheDir || options.preprovisionedCacheDir || null,
                    platform: options.platform,
                    allowEmulation: options.allowEmulation === true,
                    uidGid: options.uidGid,
                    env: options.containerEnv || {},
                    workMountMode: request.readOnlyWorkMount ? 'ro' : 'rw',
                    cacheMountMode: request.isControlledRestoreOperation ? 'rw' : 'ro'
                }
            );
            this.lifecycleManager.transition(instance.instanceId, SANDBOX_LIFECYCLE_STATES.RUNNING, `Executing ${request.operation} via ${avail.backendType}.`, {
                stagingDir: preparedEnv.staged?.instanceDir || null,
                containerName: preparedEnv.containerName || null
            });
        } catch (err) {
            const code = err.code || 'PREPARE_FAILED';
            this.lifecycleManager.transition(instance.instanceId, SANDBOX_LIFECYCLE_STATES.BLOCKED, err.message, { reasonCode: code });
            this._recordAuditDecision({
                runId: request.runId,
                instanceId: instance.instanceId,
                vulnerabilityId: request.vulnerabilityId,
                operation: request.operation,
                toolchainProfileId: profile.profileId,
                decision: 'DENIED',
                reasonCode: code,
                reason: err.message,
                backendType: avail.backendType
            });
            return {
                executed: false,
                passed: false,
                status: 'BLOCKED',
                sandboxStatus: avail.status,
                machineStatus: OUTCOME_STATUS.BLOCKED,
                reasonCode: code,
                reason: err.message,
                instanceId: instance.instanceId,
                runId: request.runId,
                operationId: request.operation,
                backendType: avail.backendType,
                toolchainProfileId: profile.profileId,
                toolchainProfileHash: profile.profileSha256,
                imageDigest: profile.imageDigest,
                executable,
                approvedArgs,
                command: `${executable} ${approvedArgs.join(' ')}`,
                testsTotal: 0,
                testsPassed: 0,
                testsFailed: 0,
                exitCode: null,
                durationMs: 0,
                stdout: '',
                stderr: err.message,
                lifecycleHistory: instance.history,
                summary: `BLOCKED (${code}) — ${err.message}`
            };
        }

        this._recordAuditDecision({
            runId: request.runId,
            instanceId: instance.instanceId,
            vulnerabilityId: request.vulnerabilityId,
            operation: request.operation,
            toolchainProfileId: profile.profileId,
            decision: 'ALLOWED',
            reasonCode: 'POLICY_SATISFIED',
            reason: `Approved operation ${request.operation} dispatched to ${avail.backendType}.`,
            backendType: avail.backendType
        });

        // Support cancellation token
        if (options.cancellationToken && typeof options.cancellationToken.onCancel === 'function') {
            options.cancellationToken.onCancel(() => {
                backend.cancelOperation(instance.instanceId).catch(() => {});
            });
        }

        let execResult;
        try {
            execResult = await backend.executeApprovedOperation(preparedEnv, {
                ...request,
                operationId: request.operation,
                executable,
                args: approvedArgs
            });
        } finally {
            const cleanRes = await backend.cleanup(instance.instanceId);
            if (cleanRes && cleanRes.cleaned === false) {
                this.lifecycleManager.transition(instance.instanceId, SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED, cleanRes.error || 'Cleanup failed.');
            }
        }

        const cleanOut = redactSensitiveOutput(execResult.stdout || '');
        const cleanErr = redactSensitiveOutput(execResult.stderr || '');
        const combinedClean = (cleanOut + (cleanErr ? '\n' + cleanErr : '')).trim();

        // Screen untrusted build/test stdout/stderr via Phase 2 ContentInjectionScreen
        const screenRes = this.injectionScreen.screen({
            text: combinedClean,
            contentSource: `sandbox:${request.operation}`,
            trustClass: TRUST_CLASSES.UNTRUSTED_BUILD_TEST_OUTPUT,
            runId: request.runId,
            filePath: request.workspaceRef
        });

        const depFail = detectDependencyRestoreFailure(cleanOut, cleanErr);
        const finalDependencyStatus = depFail.missingDependencies ? depFail.dependencyStatus : depGov.dependencyStatus;

        let finalState = execResult.lifecycleState || SANDBOX_LIFECYCLE_STATES.COMPLETED;
        let machineStatus = execResult.machineStatus || (execResult.exitCode === 0 ? OUTCOME_STATUS.PASSED : OUTCOME_STATUS.FAILED);
        let reason = execResult.reason || '';

        if (screenRes.outcome === SCREEN_OUTCOME.BLOCK || screenRes.outcome === SCREEN_OUTCOME.QUARANTINE) {
            finalState = SANDBOX_LIFECYCLE_STATES.BLOCKED;
            machineStatus = OUTCOME_STATUS.BLOCKED;
            reason = `Untrusted build/test output blocked by ContentInjectionScreen (${screenRes.ruleId}): ${screenRes.reason}`;
        } else if (depFail.missingDependencies) {
            finalState = SANDBOX_LIFECYCLE_STATES.FAILED;
            machineStatus = OUTCOME_STATUS.COULD_NOT_RUN;
            reason = depFail.reason;
        }

        if (this.lifecycleManager.getInstance(instance.instanceId).state !== SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED) {
            this.lifecycleManager.transition(instance.instanceId, finalState, reason || `Completed with exitCode=${execResult.exitCode}`);
        }

        return {
            executed: execResult.exitCode !== null && !execResult.reasonCode,
            passed: machineStatus === OUTCOME_STATUS.PASSED,
            status: machineStatus,
            sandboxStatus: avail.status,
            lifecycleState: finalState,
            machineStatus,
            reasonCode: execResult.reasonCode || (depFail.missingDependencies ? 'DEPENDENCY_UNAVAILABLE' : null),
            reason,
            instanceId: instance.instanceId,
            runId: request.runId,
            operationId: request.operation,
            backendType: avail.backendType,
            runtime: avail.runtime,
            toolchainProfileId: profile.profileId,
            toolchainProfileHash: profile.profileSha256,
            imageDigest: profile.imageDigest,
            digestStatus: profile.digestStatus || (isTemplateDigestProfile(profile) ? 'TEMPLATE_PLACEHOLDER' : 'VERIFIED_IMAGE_DIGEST'),
            executable,
            approvedArgs,
            command: `${executable} ${approvedArgs.join(' ')}`,
            workingDirectory: request.workspaceRef,
            startTime: execResult.startTime,
            endTime: execResult.endTime,
            durationMs: execResult.durationMs,
            exitCode: execResult.exitCode,
            timedOut: Boolean(execResult.timedOut),
            cancelled: Boolean(execResult.cancelled),
            networkPolicy: netPolicy.policyMode,
            networkEnforcementSummary: netPolicy.enforcementSummary,
            dependencyStatus: finalDependencyStatus,
            dependencyWarnings: depGov.warnings,
            resourceLimits: limits,
            stdout: cleanOut,
            stderr: cleanErr,
            consoleOutput: combinedClean,
            outputArtifactHashes: execResult.outputArtifactHashes || {},
            injectionScreening: screenRes.record,
            lifecycleHistory: this.lifecycleManager.getInstance(instance.instanceId)?.history || [],
            gatewayBoundaryNote: this.gatewayBoundaryNote
        };
    }

    /**
     * Convenience helper that resolves an approved toolchain profile for a finding/repo
     * and constructs a validated ExecutionRequest.
     */
    buildRequestForFinding({ runId, finding, repoRoot, operation, extraArgs = [], networkPolicy = null, resourceOverrides = {} }) {
        const profile = resolveProfileForRepository(repoRoot, finding, this.profilesPath);
        const chosenOp = operation || (
            profile.supportedStack === 'dotnet' ? OPERATION_TYPES.DOTNET_TEST :
            profile.supportedStack === 'java-maven' ? OPERATION_TYPES.MAVEN_TEST :
            OPERATION_TYPES.NPM_TEST
        );
        return {
            runId,
            applicationId: finding.Application_Number || finding.applicationId || 'APP-UNKNOWN',
            vulnerabilityId: finding.Vulnerability_ID || finding.vulnerabilityId || 'VUL-UNKNOWN',
            workspaceRef: repoRoot,
            operation: chosenOp,
            toolchainProfileId: profile.profileId,
            inputs: finding.Location_Path ? [finding.Location_Path] : [],
            expectedOutputPaths: profile.outputArtifactPaths || [],
            extraArgs,
            policyVersion: EXECUTION_POLICY_VERSION,
            networkPolicy: networkPolicy || profile.networkPolicy,
            resourcePolicy: {
                timeoutMs: resourceOverrides.timeoutMs || profile.runtimeLimits.timeoutMs,
                memoryMb: resourceOverrides.memoryMb || profile.runtimeLimits.memoryMb,
                cpus: resourceOverrides.cpus || profile.runtimeLimits.cpus,
                pidsLimit: resourceOverrides.pidsLimit || profile.runtimeLimits.pidsLimit
            }
        };
    }
}

module.exports = {
    EXECUTION_POLICY_VERSION,
    OPERATION_TYPES,
    ExecutionGatewayError,
    redactSensitiveOutput,
    TrustedExecutionGateway
};

