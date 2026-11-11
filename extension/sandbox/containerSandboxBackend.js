'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const { SANDBOX_READINESS, discoverEnvironment } = require('./environmentDiscovery');
const { ExecutionBackend, BACKEND_TYPES, SANDBOX_LIFECYCLE_STATES } = require('./executionBackend');
const { WorkspaceStagingManager, buildSanitizedContainerEnv } = require('./workspaceStaging');
const { OUTCOME_STATUS } = require('../outcomeContract');

const FORBIDDEN_MOUNT_PATTERNS = [
    /docker\.sock/i,
    /podman\.sock/i,
    /docker_engine/i,
    /(?:^|[\\/])\.(?:ssh|aws|azure|kube|gnupg)(?:[\\/]|$)/i,
    /(?:^|[\\/])\.git-credentials$/i,
    /(?:^|[\\/])\.gitconfig$/i,
    /(?:^|[\\/])\.netrc$/i,
    /(?:^|[\\/])vulnerability(?:[\\/]|$)/i
];

const IMMUTABLE_DIGEST_REGEX = /^[a-z0-9._/-]+(?:\/[a-z0-9._-]+)*@sha256:[0-9a-f]{64}$/i;
const SAFE_UID_GID_REGEX = /^[1-9]\d{1,5}:[1-9]\d{1,5}$/;

class SandboxPolicyError extends Error {
    constructor(reason, code = 'SANDBOX_POLICY_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'SandboxPolicyError';
        this.code = code;
        this.machineStatus = OUTCOME_STATUS.BLOCKED;
        this.details = details;
    }
}

function mapHostArchToContainerPlatform(arch = process.arch) {
    if (arch === 'x64' || arch === 'amd64' || arch === 'x86_64') return 'linux/amd64';
    if (arch === 'arm64' || arch === 'aarch64') return 'linux/arm64';
    return null;
}

function isPinnedImageReference(imageRef) {
    return typeof imageRef === 'string' && IMMUTABLE_DIGEST_REGEX.test(imageRef.trim());
}

function isHostHomePath(mountSource) {
    if (!mountSource || typeof mountSource !== 'string') return false;
    const norm = path.resolve(mountSource).toLowerCase();
    const candidates = [
        process.env.USERPROFILE,
        process.env.HOME,
        '/root',
        '/home',
        '/users',
        'c:\\users'
    ].filter(Boolean).map(p => path.resolve(p).toLowerCase());

    return candidates.some(c => norm === c);
}

/**
 * Local container sandbox executor supporting Docker Engine/Desktop and Podman.
 * Enforces immutable image digests, non-root user, dropped capabilities,
 * no-new-privileges, read-only rootfs, network=none default, and CPU/memory/PID/time bounds.
 */
class ContainerSandboxBackend extends ExecutionBackend {
    constructor(options = {}) {
        super(BACKEND_TYPES.LOCAL_CONTAINER);
        this.envReport = options.envReport || null;
        this.runtimeOverride = options.runtimeOverride || null;
        this.stagingManager = options.stagingManager || new WorkspaceStagingManager(options.stagingOptions);
        this.activeInstances = new Map();
        this.collectedEvidence = new Map();
        this.execFileFn = options.execFileFn || execFileSync;
        this.spawnFn = options.spawnFn || spawn;
    }

    async checkAvailability(options = {}) {
        if (this.runtimeOverride && this.runtimeOverride.available === true) {
            return {
                available: true,
                status: SANDBOX_READINESS.SANDBOX_READY,
                backendType: this.backendType,
                runtime: this.runtimeOverride.runtime || 'docker',
                binaryPath: this.runtimeOverride.binaryPath || 'docker',
                architecture: this.runtimeOverride.architecture || process.arch,
                linuxContainerMode: true,
                rootless: Boolean(this.runtimeOverride.rootless),
                reason: 'Approved container runtime override configured.',
                prerequisites: [],
                enforcedBoundaries: [
                    'Digest-pinned image, non-root UID:GID, --cap-drop=ALL, no-new-privileges',
                    'Read-only rootfs, credential-free staging, --network=none default'
                ],
                limitations: [
                    'Local containers share host Linux/WSL2 VM kernel.'
                ]
            };
        }

        const report = options.refresh
            ? discoverEnvironment({ workspaceRoot: options.workspaceRoot })
            : (this.envReport || discoverEnvironment({ workspaceRoot: options.workspaceRoot }));
        this.envReport = report;

        if (!report.sandboxAvailable || !report.selectedRuntime) {
            return {
                available: false,
                status: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                backendType: this.backendType,
                runtime: null,
                binaryPath: null,
                architecture: report.os.arch,
                linuxContainerMode: false,
                rootless: false,
                reason: report.containers.docker.installed || report.containers.podman.installed
                    ? (report.containers.docker.reason || report.containers.podman.reason)
                    : 'No approved local container runtime (Docker or Podman) is installed or reachable.',
                prerequisites: report.prerequisites,
                enforcedBoundaries: report.boundaryDisclosure.enforcedBoundaries,
                limitations: report.boundaryDisclosure.limitations
            };
        }

        const runtimeMeta = report.selectedRuntime === 'docker'
            ? report.containers.docker
            : report.containers.podman;

        return {
            available: true,
            status: SANDBOX_READINESS.SANDBOX_READY,
            backendType: this.backendType,
            runtime: report.selectedRuntime,
            binaryPath: runtimeMeta.binaryPath,
            architecture: runtimeMeta.architecture || report.os.arch,
            linuxContainerMode: runtimeMeta.linuxContainerMode,
            rootless: runtimeMeta.rootless,
            reason: runtimeMeta.reason,
            prerequisites: [],
            enforcedBoundaries: report.boundaryDisclosure.enforcedBoundaries,
            limitations: report.boundaryDisclosure.limitations
        };
    }

    /**
     * Validates container security policy strictly before creating or running a container.
     */
    validatePolicy(request = {}, policy = {}) {
        const errors = [];
        const imageRef = policy.imageRef || request.imageRef || '';
        const uidGid = policy.uidGid || '65532:65532';
        const networkMode = policy.networkMode || 'none';
        const targetPlatform = policy.platform || mapHostArchToContainerPlatform(process.arch);
        const hostPlatform = mapHostArchToContainerPlatform(process.arch);

        if (!isPinnedImageReference(imageRef)) {
            errors.push(`Image reference '${imageRef || 'empty'}' is unpinned or malformed; immutable '@sha256:<64-hex>' digest is mandatory.`);
        }

        if (Array.isArray(policy.approvedDigests) && policy.approvedDigests.length > 0) {
            const digestPart = imageRef.split('@')[1] || '';
            if (!policy.approvedDigests.includes(digestPart)) {
                errors.push(`Image digest '${digestPart}' is not in approved digest allowlist.`);
            }
        }

        if (!SAFE_UID_GID_REGEX.test(String(uidGid))) {
            errors.push(`Container user '${uidGid}' must be explicit non-root numeric UID:GID (e.g. 65532:65532).`);
        }

        if (policy.privileged === true) {
            errors.push('Privileged container mode is strictly prohibited.');
        }
        if (policy.hostPid === true || policy.hostIpc === true || networkMode === 'host') {
            errors.push('Sharing host PID, IPC, or network namespaces is strictly prohibited.');
        }

        if (networkMode !== 'none' && policy.allowIsolatedMirrorNetwork !== true) {
            errors.push(`Network mode '${networkMode}' is denied for untrusted build/test execution; 'none' is required.`);
        }

        if (!targetPlatform || (hostPlatform && targetPlatform !== hostPlatform && policy.allowEmulation !== true)) {
            errors.push(`Container target platform '${targetPlatform || 'unknown'}' does not match host architecture '${hostPlatform || process.arch}'.`);
        }

        const memMb = Number(policy.memoryMb ?? request.memoryMb ?? 1024);
        const cpus = Number(policy.cpus ?? request.cpus ?? 1.0);
        const pidsLimit = Number(policy.pidsLimit ?? request.pidsLimit ?? 128);
        const timeoutMs = Number(policy.timeoutMs ?? request.timeoutMs ?? 60000);

        if (!Number.isFinite(memMb) || memMb < 128 || memMb > 4096) {
            errors.push(`Memory limit ${memMb}MB outside approved bounds [128..4096].`);
        }
        if (!Number.isFinite(cpus) || cpus <= 0 || cpus > 4) {
            errors.push(`CPU limit ${cpus} outside approved bounds (0..4].`);
        }
        if (!Number.isFinite(pidsLimit) || pidsLimit < 16 || pidsLimit > 512) {
            errors.push(`PID limit ${pidsLimit} outside approved bounds [16..512].`);
        }
        if (!Number.isFinite(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000) {
            errors.push(`Timeout ${timeoutMs}ms outside approved bounds [1000..300000].`);
        }

        const mounts = Array.isArray(policy.mounts) ? policy.mounts : [];
        for (const m of mounts) {
            const src = typeof m === 'string' ? m : (m.source || '');
            if (!src) continue;
            if (FORBIDDEN_MOUNT_PATTERNS.some(rx => rx.test(src))) {
                errors.push(`Forbidden credential or socket mount detected: '${src}'.`);
            }
            if (isHostHomePath(src)) {
                errors.push(`Mounting developer home directory '${src}' into sandbox is prohibited.`);
            }
            if (policy.originalWorkspaceRoot && path.resolve(src).toLowerCase() === path.resolve(policy.originalWorkspaceRoot).toLowerCase()) {
                errors.push('Mounting original developer workspace directly into sandbox is prohibited; stage an isolated snapshot first.');
            }
        }

        return {
            valid: errors.length === 0,
            errors,
            reason: errors.join(' | ')
        };
    }

    /**
     * Builds deterministic container CLI arguments without shell interpolation.
     */
    buildContainerRunArgs(spec) {
        const validation = this.validatePolicy(spec.request || {}, spec.policy || {});
        if (!validation.valid) {
            throw new SandboxPolicyError(validation.reason, 'CONTAINER_POLICY_VIOLATION', { errors: validation.errors });
        }

        const {
            containerName,
            instanceId,
            runId,
            vulnerabilityId,
            imageRef,
            platform = mapHostArchToContainerPlatform(process.arch),
            uidGid = '65532:65532',
            networkMode = 'none',
            memoryMb = 1024,
            cpus = 1.0,
            pidsLimit = 128,
            readOnlyRoot = true,
            workMountMode = 'rw',
            cacheMountMode = 'ro',
            workDirHost,
            outDirHost,
            homeDirHost,
            cacheDirHost,
            env = {},
            executable,
            args = []
        } = spec;

        if (!executable || typeof executable !== 'string' || /[\s;&|`$<>]/.test(executable)) {
            throw new SandboxPolicyError(`Invalid container command executable '${executable}'.`, 'UNAPPROVED_EXECUTABLE');
        }

        const safeEnv = buildSanitizedContainerEnv(env);
        const containerArgs = [
            'run',
            '--name', containerName,
            '--rm',
            '--init',
            '--label', 'gcac.managed=true',
            '--label', `gcac.instanceId=${instanceId}`,
            '--label', `gcac.runId=${runId}`,
            '--label', `gcac.vulnerabilityId=${vulnerabilityId}`,
            '--platform', platform,
            '--user', uidGid,
            '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true',
            '--network', networkMode,
            '--memory', `${memoryMb}m`,
            '--memory-swap', `${memoryMb}m`,
            '--cpus', String(cpus),
            '--pids-limit', String(pidsLimit)
        ];

        if (readOnlyRoot) {
            containerArgs.push('--read-only');
            containerArgs.push('--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m');
        }

        containerArgs.push('-w', '/sandbox-work');
        containerArgs.push('-v', `${workDirHost}:/sandbox-work:${workMountMode}`);
        containerArgs.push('-v', `${outDirHost}:/sandbox-out:rw`);
        containerArgs.push('-v', `${homeDirHost}:/sandbox-home:rw`);
        containerArgs.push('-v', `${cacheDirHost}:/sandbox-cache:${cacheMountMode}`);

        for (const [k, v] of Object.entries(safeEnv)) {
            containerArgs.push('-e', `${k}=${v}`);
        }

        containerArgs.push(imageRef);
        containerArgs.push(executable);
        for (const a of args) {
            const s = String(a ?? '');
            if (s.includes('\0')) {
                throw new SandboxPolicyError('Null byte in command argument.', 'MALFORMED_ARGUMENT');
            }
            containerArgs.push(s);
        }

        return containerArgs;
    }

    async prepareEnvironment(request = {}, policy = {}) {
        const avail = await this.checkAvailability({ workspaceRoot: request.workspaceRoot });
        if (!avail.available) {
            throw new SandboxPolicyError(avail.reason || 'Container runtime unavailable.', SANDBOX_READINESS.SANDBOX_UNAVAILABLE, {
                prerequisites: avail.prerequisites
            });
        }

        const instanceId = request.instanceId || `gcac-${crypto.randomBytes(6).toString('hex')}`;
        const containerName = `gcac-${instanceId.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 48)}`;

        const staged = this.stagingManager.stageWorkspace({
            instanceId,
            runId: request.runId,
            sourceRoot: request.workspaceRef,
            allowGitMetadata: policy.allowGitMetadata === true,
            allowCacheReuse: policy.allowCacheReuse === true,
            appCacheDir: policy.appCacheDir || null
        });

        const policyMounts = [
            { source: staged.workDir, target: '/sandbox-work' },
            { source: staged.outDir, target: '/sandbox-out' },
            { source: staged.homeDir, target: '/sandbox-home' },
            { source: staged.cacheDir, target: '/sandbox-cache' }
        ];

        const mergedPolicy = {
            ...policy,
            mounts: policyMounts,
            originalWorkspaceRoot: request.originalWorkspaceRoot || null
        };

        const check = this.validatePolicy(request, mergedPolicy);
        if (!check.valid) {
            this.stagingManager.cleanupStaging(staged.instanceDir);
            throw new SandboxPolicyError(check.reason, 'CONTAINER_POLICY_VIOLATION', { errors: check.errors });
        }

        const prepared = {
            instanceId,
            containerName,
            runId: request.runId,
            vulnerabilityId: request.vulnerabilityId,
            applicationId: request.applicationId,
            runtime: avail.runtime,
            binaryPath: avail.binaryPath,
            staged,
            policy: mergedPolicy,
            lifecycleState: SANDBOX_LIFECYCLE_STATES.PREPARING,
            preparedAt: new Date().toISOString()
        };
        this.activeInstances.set(instanceId, prepared);
        return prepared;
    }

    async executeApprovedOperation(preparedEnv, request = {}) {
        const startTs = new Date();
        const startMs = Date.now();
        const timeoutMs = Number(preparedEnv.policy?.timeoutMs || request.timeoutMs || 60000);

        const runArgs = this.buildContainerRunArgs({
            containerName: preparedEnv.containerName,
            instanceId: preparedEnv.instanceId,
            runId: preparedEnv.runId,
            vulnerabilityId: preparedEnv.vulnerabilityId,
            imageRef: preparedEnv.policy.imageRef,
            platform: preparedEnv.policy.platform || mapHostArchToContainerPlatform(process.arch),
            uidGid: preparedEnv.policy.uidGid || '65532:65532',
            networkMode: preparedEnv.policy.networkMode || 'none',
            memoryMb: preparedEnv.policy.memoryMb || 1024,
            cpus: preparedEnv.policy.cpus || 1.0,
            pidsLimit: preparedEnv.policy.pidsLimit || 128,
            readOnlyRoot: preparedEnv.policy.readOnlyRoot !== false,
            workMountMode: preparedEnv.policy.workMountMode || 'rw',
            cacheMountMode: preparedEnv.policy.cacheMountMode || 'ro',
            workDirHost: preparedEnv.staged.workDir,
            outDirHost: preparedEnv.staged.outDir,
            homeDirHost: preparedEnv.staged.homeDir,
            cacheDirHost: preparedEnv.staged.cacheDir,
            env: preparedEnv.policy.env || {},
            executable: request.executable,
            args: request.args || []
        });

        preparedEnv.lifecycleState = SANDBOX_LIFECYCLE_STATES.RUNNING;

        // Verify pinned image exists locally so we never download unapproved images silently
        if (preparedEnv.policy.requirePrePulledImage !== false) {
            try {
                this.execFileFn(preparedEnv.binaryPath, ['image', 'inspect', preparedEnv.policy.imageRef], {
                    timeout: 5000,
                    stdio: 'ignore',
                    shell: false
                });
            } catch {
                const endTs = new Date();
                const evidence = {
                    instanceId: preparedEnv.instanceId,
                    runId: preparedEnv.runId,
                    operationId: request.operationId || request.operation,
                    backendType: this.backendType,
                    runtime: preparedEnv.runtime,
                    sandboxStatus: SANDBOX_READINESS.SANDBOX_READY,
                    lifecycleState: SANDBOX_LIFECYCLE_STATES.BLOCKED,
                    machineStatus: OUTCOME_STATUS.BLOCKED,
                    reasonCode: 'TOOLCHAIN_IMAGE_MISSING',
                    reason: `Approved digest-pinned image '${preparedEnv.policy.imageRef}' is not present in local runtime cache; auto-pull disabled.`,
                    imageDigest: preparedEnv.policy.imageRef,
                    executable: request.executable,
                    args: request.args || [],
                    containerArgs: runArgs,
                    startTime: startTs.toISOString(),
                    endTime: endTs.toISOString(),
                    durationMs: Date.now() - startMs,
                    exitCode: null,
                    timedOut: false,
                    cancelled: false,
                    stdout: '',
                    stderr: '',
                    outputArtifactHashes: {}
                };
                this.collectedEvidence.set(preparedEnv.instanceId, evidence);
                return evidence;
            }
        }

        return await new Promise((resolve) => {
            let stdout = '';
            let stderr = '';
            let timedOut = false;
            let cancelled = false;
            const MAX_OUT = 256 * 1024;

            let child;
            try {
                child = this.spawnFn(preparedEnv.binaryPath, runArgs, {
                    shell: false,
                    env: { PATH: process.env.PATH || '' },
                    stdio: ['ignore', 'pipe', 'pipe']
                });
            } catch (err) {
                const endTs = new Date();
                const res = {
                    instanceId: preparedEnv.instanceId,
                    runId: preparedEnv.runId,
                    operationId: request.operationId || request.operation,
                    backendType: this.backendType,
                    runtime: preparedEnv.runtime,
                    sandboxStatus: SANDBOX_READINESS.SANDBOX_READY,
                    lifecycleState: SANDBOX_LIFECYCLE_STATES.FAILED,
                    machineStatus: OUTCOME_STATUS.COULD_NOT_RUN,
                    reasonCode: 'CONTAINER_SPAWN_ERROR',
                    reason: `Container spawn failed: ${err.message}`,
                    imageDigest: preparedEnv.policy.imageRef,
                    executable: request.executable,
                    args: request.args || [],
                    containerArgs: runArgs,
                    startTime: startTs.toISOString(),
                    endTime: endTs.toISOString(),
                    durationMs: Date.now() - startMs,
                    exitCode: null,
                    timedOut: false,
                    cancelled: false,
                    stdout: '',
                    stderr: err.message,
                    outputArtifactHashes: {}
                };
                this.collectedEvidence.set(preparedEnv.instanceId, res);
                resolve(res);
                return;
            }

            preparedEnv.childProcess = child;
            preparedEnv.markCancelled = () => { cancelled = true; };

            const timer = setTimeout(() => {
                timedOut = true;
                this._forceStopOwnedContainer(preparedEnv);
                try { child.kill('SIGTERM'); } catch {}
            }, timeoutMs);

            if (child.stdout) {
                child.stdout.on('data', chunk => {
                    if (stdout.length < MAX_OUT) stdout += chunk.toString();
                });
            }
            if (child.stderr) {
                child.stderr.on('data', chunk => {
                    if (stderr.length < MAX_OUT) stderr += chunk.toString();
                });
            }

            child.on('close', (code) => {
                clearTimeout(timer);
                const endTs = new Date();
                const outputArtifactHashes = this._collectOutputHashes(preparedEnv.staged.outDir);

                let lifecycleState = SANDBOX_LIFECYCLE_STATES.COMPLETED;
                let machineStatus = OUTCOME_STATUS.PASSED;
                if (cancelled) {
                    lifecycleState = SANDBOX_LIFECYCLE_STATES.CANCELLED;
                    machineStatus = OUTCOME_STATUS.CANCELLED;
                } else if (timedOut) {
                    lifecycleState = SANDBOX_LIFECYCLE_STATES.TIMED_OUT;
                    machineStatus = OUTCOME_STATUS.TIMED_OUT;
                } else if (code !== 0) {
                    lifecycleState = SANDBOX_LIFECYCLE_STATES.FAILED;
                    machineStatus = OUTCOME_STATUS.FAILED;
                }

                preparedEnv.lifecycleState = lifecycleState;
                const result = {
                    instanceId: preparedEnv.instanceId,
                    runId: preparedEnv.runId,
                    operationId: request.operationId || request.operation,
                    backendType: this.backendType,
                    runtime: preparedEnv.runtime,
                    sandboxStatus: SANDBOX_READINESS.SANDBOX_READY,
                    lifecycleState,
                    machineStatus,
                    imageDigest: preparedEnv.policy.imageRef,
                    executable: request.executable,
                    args: request.args || [],
                    containerArgs: runArgs,
                    networkPolicy: preparedEnv.policy.networkMode || 'none',
                    resourceLimits: {
                        memoryMb: preparedEnv.policy.memoryMb || 1024,
                        cpus: preparedEnv.policy.cpus || 1.0,
                        pidsLimit: preparedEnv.policy.pidsLimit || 128,
                        timeoutMs
                    },
                    startTime: startTs.toISOString(),
                    endTime: endTs.toISOString(),
                    durationMs: Date.now() - startMs,
                    exitCode: code,
                    timedOut,
                    cancelled,
                    stdout,
                    stderr,
                    outputArtifactHashes
                };
                this.collectedEvidence.set(preparedEnv.instanceId, result);
                resolve(result);
            });

            child.on('error', (err) => {
                clearTimeout(timer);
                const endTs = new Date();
                preparedEnv.lifecycleState = SANDBOX_LIFECYCLE_STATES.FAILED;
                const result = {
                    instanceId: preparedEnv.instanceId,
                    runId: preparedEnv.runId,
                    operationId: request.operationId || request.operation,
                    backendType: this.backendType,
                    runtime: preparedEnv.runtime,
                    sandboxStatus: SANDBOX_READINESS.SANDBOX_READY,
                    lifecycleState: SANDBOX_LIFECYCLE_STATES.FAILED,
                    machineStatus: OUTCOME_STATUS.FAILED,
                    reason: err.message,
                    imageDigest: preparedEnv.policy.imageRef,
                    executable: request.executable,
                    args: request.args || [],
                    containerArgs: runArgs,
                    startTime: startTs.toISOString(),
                    endTime: endTs.toISOString(),
                    durationMs: Date.now() - startMs,
                    exitCode: null,
                    timedOut,
                    cancelled,
                    stdout,
                    stderr: stderr || err.message,
                    outputArtifactHashes: {}
                };
                this.collectedEvidence.set(preparedEnv.instanceId, result);
                resolve(result);
            });
        });
    }

    _forceStopOwnedContainer(preparedEnv) {
        if (!preparedEnv || !preparedEnv.binaryPath || !preparedEnv.containerName) return;
        try {
            // Verify ownership label before terminating
            const inspectOut = this.execFileFn(
                preparedEnv.binaryPath,
                ['inspect', '--format', '{{index .Config.Labels "gcac.managed"}}|{{index .Config.Labels "gcac.instanceId"}}', preparedEnv.containerName],
                { encoding: 'utf8', timeout: 3000, shell: false }
            ).trim();
            if (inspectOut === `true|${preparedEnv.instanceId}`) {
                this.execFileFn(preparedEnv.binaryPath, ['rm', '-f', preparedEnv.containerName], {
                    timeout: 5000,
                    stdio: 'ignore',
                    shell: false
                });
            }
        } catch {
            // Container may already have exited via --rm
        }
    }

    _collectOutputHashes(outDir) {
        const hashes = {};
        if (!outDir || !fs.existsSync(outDir)) return hashes;
        try {
            const files = fs.readdirSync(outDir);
            for (const f of files.sort()) {
                const full = path.join(outDir, f);
                if (fs.statSync(full).isFile()) {
                    const buf = fs.readFileSync(full);
                    hashes[f] = {
                        sha256: crypto.createHash('sha256').update(buf).digest('hex'),
                        bytes: buf.length
                    };
                }
            }
        } catch {}
        return hashes;
    }

    async cancelOperation(instanceId) {
        const prep = this.activeInstances.get(instanceId);
        if (!prep) {
            return { instanceId, cancelled: false, reason: 'Instance not active.' };
        }
        if (typeof prep.markCancelled === 'function') {
            prep.markCancelled();
        }
        this._forceStopOwnedContainer(prep);
        if (prep.childProcess && !prep.childProcess.killed) {
            try { prep.childProcess.kill('SIGTERM'); } catch {}
        }
        prep.lifecycleState = SANDBOX_LIFECYCLE_STATES.CANCELLED;
        return { instanceId, cancelled: true };
    }

    async collectEvidence(instanceId) {
        return this.collectedEvidence.get(instanceId) || null;
    }

    async cleanup(instanceId) {
        const prep = this.activeInstances.get(instanceId);
        if (!prep) {
            return { instanceId, cleaned: true, note: 'No active staging handle.' };
        }
        try {
            this._forceStopOwnedContainer(prep);
            this.stagingManager.cleanupStaging(prep.staged.instanceDir);
            this.activeInstances.delete(instanceId);
            return { instanceId, cleaned: true };
        } catch (err) {
            prep.lifecycleState = SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED;
            return { instanceId, cleaned: false, lifecycleState: SANDBOX_LIFECYCLE_STATES.CLEANUP_FAILED, error: err.message };
        }
    }

    /**
     * Safely removes orphaned GCAC-owned containers only (never touches unrelated containers/volumes).
     */
    async cleanupOrphanedContainers(options = {}) {
        const avail = await this.checkAvailability(options);
        if (!avail.available) {
            return { executed: false, removedContainers: [], reason: avail.reason };
        }
        const removed = [];
        try {
            const raw = this.execFileFn(
                avail.binaryPath,
                ['ps', '-a', '--filter', 'label=gcac.managed=true', '--format', '{{.ID}}|{{.Names}}|{{.Label "gcac.instanceId"}}'],
                { encoding: 'utf8', timeout: 5000, shell: false }
            ).trim();
            for (const line of raw.split(/\r?\n/).filter(Boolean)) {
                const [id, name, instId] = line.split('|');
                if (id && instId && !this.activeInstances.has(instId)) {
                    this.execFileFn(avail.binaryPath, ['rm', '-f', id], { timeout: 5000, stdio: 'ignore', shell: false });
                    removed.push({ id, name, instanceId: instId });
                }
            }
            return { executed: true, removedContainers: removed };
        } catch (err) {
            return { executed: false, removedContainers: removed, error: err.message };
        }
    }
}

module.exports = {
    FORBIDDEN_MOUNT_PATTERNS,
    IMMUTABLE_DIGEST_REGEX,
    SAFE_UID_GID_REGEX,
    SandboxPolicyError,
    mapHostArchToContainerPlatform,
    isPinnedImageReference,
    isHostHomePath,
    ContainerSandboxBackend
};

