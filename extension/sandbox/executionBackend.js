'use strict';

const { SANDBOX_READINESS, discoverEnvironment } = require('./environmentDiscovery');

const SANDBOX_LIFECYCLE_STATES = Object.freeze({
    PENDING: 'PENDING',
    PREPARING: 'PREPARING',
    RUNNING: 'RUNNING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
    CANCELLED: 'CANCELLED',
    TIMED_OUT: 'TIMED_OUT',
    BLOCKED: 'BLOCKED',
    CLEANUP_FAILED: 'CLEANUP_FAILED'
});

const BACKEND_TYPES = Object.freeze({
    LOCAL_CONTAINER: 'local-container',
    EPHEMERAL_CI_ADAPTER: 'ephemeral-ci-runner',
    NONE: 'none'
});

/**
 * Abstract execution-backend interface for GCAC Phase 3 secure execution isolation.
 * Every governed build, test, or build-invoking scan must pass through an ExecutionBackend.
 */
class ExecutionBackend {
    constructor(backendType = BACKEND_TYPES.NONE) {
        this.backendType = backendType;
    }

    async checkAvailability(_options = {}) {
        throw new Error('ExecutionBackend.checkAvailability() must be implemented.');
    }

    validatePolicy(_request, _policy = {}) {
        throw new Error('ExecutionBackend.validatePolicy() must be implemented.');
    }

    async prepareEnvironment(_request, _stagingSpec = {}) {
        throw new Error('ExecutionBackend.prepareEnvironment() must be implemented.');
    }

    async executeApprovedOperation(_preparedEnv, _request) {
        throw new Error('ExecutionBackend.executeApprovedOperation() must be implemented.');
    }

    async cancelOperation(_instanceId) {
        throw new Error('ExecutionBackend.cancelOperation() must be implemented.');
    }

    async collectEvidence(_instanceId) {
        throw new Error('ExecutionBackend.collectEvidence() must be implemented.');
    }

    async cleanup(_instanceId) {
        throw new Error('ExecutionBackend.cleanup() must be implemented.');
    }
}

/**
 * Design adapter for a future enterprise-approved ephemeral CI/VM runner (e.g., GitHub Actions
 * ephemeral runner / Azure VMSS / isolated Kubernetes pod). Intentionally does NOT connect to
 * an external remote service without explicit authorization; fails closed as SANDBOX_UNAVAILABLE.
 */
class EphemeralCiRunnerBackend extends ExecutionBackend {
    constructor(options = {}) {
        super(BACKEND_TYPES.EPHEMERAL_CI_ADAPTER);
        this.endpointConfigured = Boolean(options.authorizedRunnerEndpoint);
    }

    async checkAvailability() {
        return {
            available: false,
            status: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            backendType: this.backendType,
            runtime: null,
            reason: 'Ephemeral CI/VM runner adapter is a design interface only; no remote runner service is provisioned or authorized in local Phase 3.',
            prerequisites: [
                'Provision an enterprise-approved ephemeral CI/VM runner service with workload identity federation.',
                'Configure an authorized, mutually-authenticated runner endpoint in enterprise policy.'
            ],
            enforcedBoundaries: [
                'Dedicated ephemeral VM/runner kernel isolation per job (when provisioned)',
                'Hardware/hypervisor isolation beyond local workstation container boundaries'
            ]
        };
    }

    validatePolicy(request) {
        if (!request || !request.runId || !request.operation) {
            return { valid: false, reason: 'Execution request lacks runId or operation.' };
        }
        return {
            valid: false,
            reason: 'Remote ephemeral CI/VM execution is not authorized in this local Phase 3 environment.'
        };
    }

    async prepareEnvironment() {
        throw new Error('SANDBOX_UNAVAILABLE: Remote ephemeral CI/VM runner is not provisioned.');
    }

    async executeApprovedOperation() {
        return {
            executed: false,
            sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
            lifecycleState: SANDBOX_LIFECYCLE_STATES.BLOCKED,
            backendType: this.backendType,
            reason: 'SANDBOX_UNAVAILABLE: Ephemeral CI/VM runner is not provisioned or authorized.'
        };
    }

    async cancelOperation(instanceId) {
        return { instanceId, cancelled: false, reason: 'No active ephemeral CI instance.' };
    }

    async collectEvidence(instanceId) {
        return { instanceId, available: false, artifacts: [] };
    }

    async cleanup(instanceId) {
        return { instanceId, cleaned: true };
    }
}

/**
 * Selects an approved execution backend based on real environment discovery or explicit override.
 * Never returns an unisolated host-shell runner when a sandbox is unavailable.
 */
async function selectExecutionBackend(options = {}) {
    if (options.backend && typeof options.backend.checkAvailability === 'function') {
        const avail = await options.backend.checkAvailability(options);
        return { backend: options.backend, availability: avail };
    }

    const { ContainerSandboxBackend } = require('./containerSandboxBackend');
    const envReport = options.envReport || discoverEnvironment({ workspaceRoot: options.workspaceRoot });
    const localBackend = new ContainerSandboxBackend({
        envReport,
        runtimeOverride: options.runtimeOverride || null
    });
    const avail = await localBackend.checkAvailability(options);
    if (avail.available) {
        return { backend: localBackend, availability: avail, envReport };
    }

    if (options.preferEphemeralCiAdapter) {
        const ciAdapter = new EphemeralCiRunnerBackend(options);
        const ciAvail = await ciAdapter.checkAvailability();
        return { backend: ciAdapter, availability: ciAvail, envReport };
    }

    return {
        backend: localBackend,
        availability: avail,
        envReport
    };
}

module.exports = {
    SANDBOX_LIFECYCLE_STATES,
    BACKEND_TYPES,
    ExecutionBackend,
    EphemeralCiRunnerBackend,
    selectExecutionBackend
};

