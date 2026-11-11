'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const SANDBOX_READINESS = Object.freeze({
    SANDBOX_READY: 'SANDBOX_READY',
    SANDBOX_UNAVAILABLE: 'SANDBOX_UNAVAILABLE'
});

function safeExecProbe(bin, args = [], opts = {}) {
    if (!bin || typeof bin !== 'string' || bin.includes('\0')) {
        return { ok: false, stdout: '', stderr: 'Invalid executable name', error: 'Invalid executable name' };
    }
    try {
        const stdout = execFileSync(bin, args, {
            encoding: 'utf8',
            timeout: opts.timeoutMs || 4000,
            shell: false,
            windowsHide: true,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return { ok: true, stdout: (stdout || '').replace(/\0/g, '').trim(), stderr: '' };
    } catch (err) {
        return {
            ok: false,
            stdout: err.stdout ? String(err.stdout).replace(/\0/g, '').trim() : '',
            stderr: err.stderr ? String(err.stderr).replace(/\0/g, '').trim() : '',
            error: (err.message || String(err)).replace(/\0/g, '')
        };
    }
}

function findExecutableOnPath(exeNames = [], extraPaths = []) {
    const lookupTool = process.platform === 'win32' ? 'where' : 'which';
    for (const exe of exeNames) {
        const res = safeExecProbe(lookupTool, [exe], { timeoutMs: 2500 });
        if (res.ok && res.stdout) {
            const first = res.stdout.split(/\r?\n/)[0].trim();
            if (first && fs.existsSync(first)) return first;
        }
    }
    for (const candidate of extraPaths) {
        if (candidate && fs.existsSync(candidate)) return candidate;
    }
    return null;
}

function probeDocker(execProbe = safeExecProbe, pathFinder = findExecutableOnPath) {
    const extra = process.platform === 'win32'
        ? ['C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe']
        : ['/usr/bin/docker', '/usr/local/bin/docker'];
    const bin = pathFinder(['docker'], extra);
    if (!bin) {
        return {
            installed: false,
            binaryPath: null,
            daemonReachable: false,
            clientVersion: null,
            serverVersion: null,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            securityOptions: [],
            reason: 'Docker CLI not found in PATH or standard installation paths.'
        };
    }

    const verRes = execProbe(bin, ['version', '--format', '{{json .}}'], { timeoutMs: 4000 });
    const infoRes = execProbe(bin, ['info', '--format', '{{json .}}'], { timeoutMs: 5000 });

    let clientVersion = null;
    let serverVersion = null;
    if (verRes.stdout) {
        try {
            const v = JSON.parse(verRes.stdout);
            clientVersion = v.Client?.Version || null;
            serverVersion = v.Server?.Version || null;
        } catch {}
    }

    if (!infoRes.ok || !infoRes.stdout) {
        return {
            installed: true,
            binaryPath: bin,
            daemonReachable: false,
            clientVersion,
            serverVersion,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            securityOptions: [],
            reason: infoRes.stderr || infoRes.error || 'Docker daemon is not reachable.'
        };
    }

    let info = {};
    try {
        info = JSON.parse(infoRes.stdout);
    } catch {
        return {
            installed: true,
            binaryPath: bin,
            daemonReachable: false,
            clientVersion,
            serverVersion,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            securityOptions: [],
            reason: 'Unable to parse docker info output.'
        };
    }

    const secOpts = Array.isArray(info.SecurityOptions) ? info.SecurityOptions : [];
    const osType = (info.OSType || '').toLowerCase() || null;
    const rootless = secOpts.some(s => String(s).toLowerCase().includes('rootless'));
    const linuxContainerMode = osType === 'linux';

    return {
        installed: true,
        binaryPath: bin,
        daemonReachable: true,
        clientVersion,
        serverVersion: serverVersion || info.ServerVersion || null,
        osType,
        architecture: info.Architecture || null,
        linuxContainerMode,
        rootless,
        securityOptions: secOpts,
        reason: linuxContainerMode
            ? 'Docker daemon connected in Linux container mode.'
            : `Docker daemon connected in '${osType || 'unknown'}' mode; Linux container mode is required for approved GCAC images.`
    };
}

function probePodman(execProbe = safeExecProbe, pathFinder = findExecutableOnPath) {
    const extra = process.platform === 'win32'
        ? ['C:\\Program Files\\RedHat\\Podman\\podman.exe']
        : ['/usr/bin/podman', '/usr/local/bin/podman'];
    const bin = pathFinder(['podman'], extra);
    if (!bin) {
        return {
            installed: false,
            binaryPath: null,
            daemonReachable: false,
            version: null,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            reason: 'Podman CLI not found in PATH or standard installation paths.'
        };
    }

    const infoRes = execProbe(bin, ['info', '--format', 'json'], { timeoutMs: 5000 });
    if (!infoRes.ok || !infoRes.stdout) {
        return {
            installed: true,
            binaryPath: bin,
            daemonReachable: false,
            version: null,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            reason: infoRes.stderr || infoRes.error || 'Podman machine/service is not running or reachable.'
        };
    }

    let info = {};
    try {
        info = JSON.parse(infoRes.stdout);
    } catch {
        return {
            installed: true,
            binaryPath: bin,
            daemonReachable: false,
            version: null,
            osType: null,
            architecture: null,
            linuxContainerMode: false,
            rootless: false,
            reason: 'Unable to parse podman info JSON.'
        };
    }

    const osType = (info.host?.os || info.version?.Os || 'linux').toLowerCase();
    const arch = info.host?.arch || info.version?.Arch || null;
    const rootless = Boolean(info.host?.security?.rootless);
    const linuxContainerMode = osType === 'linux';

    return {
        installed: true,
        binaryPath: bin,
        daemonReachable: true,
        version: info.version?.Version || null,
        osType,
        architecture: arch,
        linuxContainerMode,
        rootless,
        reason: linuxContainerMode
            ? 'Podman engine reachable in Linux container mode.'
            : `Podman connected in '${osType}' mode.`
    };
}

function probeWsl(execProbe = safeExecProbe) {
    if (process.platform !== 'win32') {
        return { applicable: false, installed: false, reason: 'Not Windows' };
    }
    const statusRes = execProbe('wsl', ['--status'], { timeoutMs: 3000 });
    if (!statusRes.ok) {
        return {
            applicable: true,
            installed: false,
            reason: statusRes.stderr || statusRes.stdout || statusRes.error || 'WSL2 is not installed.'
        };
    }
    return {
        applicable: true,
        installed: true,
        reason: 'WSL2 available.'
    };
}

function probeDotnet(execProbe = safeExecProbe, pathFinder = findExecutableOnPath, workspaceRoot = null) {
    const bin = pathFinder(['dotnet']);
    if (!bin) {
        return { installed: false, binaryPath: null, activeVersion: null, sdks: [], globalJsonSdk: null };
    }
    const verRes = execProbe(bin, ['--version'], { timeoutMs: 4000 });
    const sdksRes = execProbe(bin, ['--list-sdks'], { timeoutMs: 4000 });
    const sdks = sdksRes.ok && sdksRes.stdout
        ? sdksRes.stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => l.split(/\s+/)[0])
        : [];

    let globalJsonSdk = null;
    if (workspaceRoot) {
        const gjPath = path.join(workspaceRoot, 'global.json');
        if (fs.existsSync(gjPath)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(gjPath, 'utf8'));
                globalJsonSdk = parsed.sdk?.version || null;
            } catch {}
        }
    }

    return {
        installed: true,
        binaryPath: bin,
        activeVersion: verRes.ok ? verRes.stdout : null,
        sdks,
        globalJsonSdk
    };
}

function probeJavaAndMaven(execProbe = safeExecProbe, pathFinder = findExecutableOnPath) {
    const javaBin = pathFinder(['java']);
    const mvnBin = pathFinder(['mvn']);
    let javaVersion = null;
    let mavenVersion = null;
    if (javaBin) {
        const res = execProbe(javaBin, ['-version'], { timeoutMs: 3000 });
        javaVersion = (res.stdout || res.stderr || '').split(/\r?\n/)[0] || null;
    }
    if (mvnBin) {
        const res = execProbe(mvnBin, ['-version'], { timeoutMs: 3000 });
        mavenVersion = res.ok ? (res.stdout.split(/\r?\n/)[0] || null) : null;
    }
    return {
        javaInstalled: Boolean(javaBin),
        javaBinaryPath: javaBin,
        javaVersion,
        mavenInstalled: Boolean(mvnBin),
        mavenBinaryPath: mvnBin,
        mavenVersion
    };
}

function probeNodeAndGit(execProbe = safeExecProbe, pathFinder = findExecutableOnPath) {
    const npmBin = pathFinder(process.platform === 'win32' ? ['npm.cmd', 'npm'] : ['npm']);
    const gitBin = pathFinder(['git']);
    const npmRes = npmBin ? execProbe(npmBin, ['-v'], { timeoutMs: 3000 }) : { ok: false };
    const gitRes = gitBin ? execProbe(gitBin, ['--version'], { timeoutMs: 3000 }) : { ok: false };
    return {
        nodeVersion: process.version,
        npmInstalled: Boolean(npmBin),
        npmVersion: npmRes.ok ? npmRes.stdout : null,
        gitInstalled: Boolean(gitBin),
        gitVersion: gitRes.ok ? gitRes.stdout : null
    };
}

function probeScannersAndSbom(execProbe = safeExecProbe, pathFinder = findExecutableOnPath, workspaceRoot = null) {
    const codeqlExtra = workspaceRoot
        ? [path.join(workspaceRoot, 'tools', 'codeql', process.platform === 'win32' ? 'codeql.exe' : 'codeql')]
        : [];
    const codeqlBin = pathFinder(['codeql'], codeqlExtra);
    const syftBin = pathFinder(['syft']);
    const trivyBin = pathFinder(['trivy']);
    const cdxgenBin = pathFinder(['cdxgen']);
    const cyclonedxBin = pathFinder(['cyclonedx', 'dotnet-cyclonedx']);

    return {
        codeqlInstalled: Boolean(codeqlBin),
        codeqlBinaryPath: codeqlBin,
        sbomTools: {
            syft: Boolean(syftBin),
            trivy: Boolean(trivyBin),
            cdxgen: Boolean(cdxgenBin),
            cyclonedx: Boolean(cyclonedxBin),
            anyExternalSbomCliAvailable: Boolean(syftBin || trivyBin || cdxgenBin || cyclonedxBin)
        }
    };
}

function inspectWorkspaceToolchainsAndConfigs(workspaceRoot) {
    const result = {
        csprojTargets: [],
        hasPomXml: false,
        hasPackageJson: false,
        hasLockfiles: {
            nugetPackagesLock: false,
            directoryPackagesProps: false,
            npmPackageLock: false
        },
        existingSandboxOrCiConfigs: []
    };

    if (!workspaceRoot || !fs.existsSync(workspaceRoot)) return result;

    const ciCandidates = [
        '.devcontainer/devcontainer.json',
        'Dockerfile',
        '.github/workflows'
    ];
    for (const rel of ciCandidates) {
        if (fs.existsSync(path.join(workspaceRoot, rel))) {
            result.existingSandboxOrCiConfigs.push(rel);
        }
    }

    result.hasPomXml = fs.existsSync(path.join(workspaceRoot, 'pom.xml'));
    result.hasPackageJson = fs.existsSync(path.join(workspaceRoot, 'package.json'));
    result.hasLockfiles.npmPackageLock = fs.existsSync(path.join(workspaceRoot, 'package-lock.json'));
    result.hasLockfiles.directoryPackagesProps = fs.existsSync(path.join(workspaceRoot, 'Directory.Packages.props'));
    result.hasLockfiles.nugetPackagesLock = fs.existsSync(path.join(workspaceRoot, 'packages.lock.json'));

    const scanTargets = (dir, depth = 0) => {
        if (depth > 3) return;
        let entries = [];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (['.git', 'node_modules', 'bin', 'obj', 'remediation-output', 'evidence', 'output'].includes(e.name)) continue;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                scanTargets(full, depth + 1);
            } else if (e.isFile() && e.name === 'packages.lock.json') {
                result.hasLockfiles.nugetPackagesLock = true;
            } else if (e.isFile() && e.name.endsWith('.csproj')) {
                try {
                    const xml = fs.readFileSync(full, 'utf8');
                    const m = xml.match(/<TargetFramework[s]?>([^<]+)<\/TargetFramework[s]?>/i);
                    result.csprojTargets.push({
                        file: path.relative(workspaceRoot, full).replace(/\\/g, '/'),
                        targetFramework: m ? m[1].trim() : 'unknown'
                    });
                } catch {}
            }
        }
    };
    scanTargets(workspaceRoot, 0);
    return result;
}

function buildEnvironmentPrerequisites({ docker, podman, wsl, platform }) {
    const prereqs = [];
    if (platform === 'win32' && wsl && !wsl.installed) {
        prereqs.push('Install and enable WSL2 (`wsl --install`) for Linux container isolation on Windows.');
    }
    if (!docker.installed && !podman.installed) {
        prereqs.push('Install Docker Engine / Docker Desktop (Linux containers mode) or Podman v4+.');
    } else if (!docker.daemonReachable && !podman.daemonReachable) {
        prereqs.push('Start the Docker daemon (`docker info`) or Podman machine (`podman machine start`) before running governed builds/tests.');
    } else if (!docker.linuxContainerMode && !podman.linuxContainerMode) {
        prereqs.push('Switch container daemon to Linux containers mode (`ostype=linux`) so pinned Linux toolchain images can execute.');
    }
    prereqs.push('Pre-pull approved digest-pinned toolchain container images into the local/enterprise image cache or configure an approved internal mirror.');
    return prereqs;
}

/**
 * Discovers OS, container runtime, toolchains, scanners, and sandbox readiness
 * without assuming Docker/Podman/WSL2/CI exists and without auto-installing anything.
 */
function discoverEnvironment(workspaceRootOrOptions = {}, maybeOptions = {}) {
    const options = typeof workspaceRootOrOptions === 'string'
        ? { workspaceRoot: workspaceRootOrOptions, ...(maybeOptions || {}) }
        : (workspaceRootOrOptions || {});

    const workspaceRoot = options.workspaceRoot || null;
    const execProbe = options.execProbe || options.probeFn || safeExecProbe;
    const pathFinder = options.pathFinder || (options.probeFn
        ? (names) => {
            const probeCheck = options.probeFn(names[0], ['--probe-check']);
            return (!probeCheck || probeCheck.notFound) ? null : names[0];
        }
        : findExecutableOnPath);
    const platform = options.platform || process.platform;
    const arch = options.arch || process.arch;

    const docker = probeDocker(execProbe, pathFinder);
    const podman = probePodman(execProbe, pathFinder);
    const wsl = platform === 'win32' ? probeWsl(execProbe) : { applicable: false, installed: false, reason: 'Non-Windows host' };
    const dotnet = probeDotnet(execProbe, pathFinder, workspaceRoot);
    const javaMaven = probeJavaAndMaven(execProbe, pathFinder);
    const nodeGit = probeNodeAndGit(execProbe, pathFinder);
    const scanners = probeScannersAndSbom(execProbe, pathFinder, workspaceRoot);
    const workspace = inspectWorkspaceToolchainsAndConfigs(workspaceRoot);

    const dockerReady = docker.installed && docker.daemonReachable && docker.linuxContainerMode;
    const podmanReady = podman.installed && podman.daemonReachable && podman.linuxContainerMode;
    const sandboxAvailable = dockerReady || podmanReady;

    const selectedRuntime = dockerReady ? 'docker' : (podmanReady ? 'podman' : null);
    const sandboxStatus = sandboxAvailable ? SANDBOX_READINESS.SANDBOX_READY : SANDBOX_READINESS.SANDBOX_UNAVAILABLE;

    const prerequisites = sandboxAvailable
        ? []
        : buildEnvironmentPrerequisites({ docker, podman, wsl, platform });

    const boundaryDisclosure = sandboxAvailable
        ? {
            enforcedBoundaries: [
                'Non-root container UID/GID, dropped Linux capabilities, no-new-privileges',
                'Read-only base root filesystem with dedicated bounded temporary scratch mounts',
                'Network=none isolation during untrusted build/test operations',
                'CPU, memory, PID, and wall-clock timeout quotas',
                'No host home directory, credential store, or daemon socket mounts'
            ],
            limitations: [
                'Local containers share the host Linux kernel (or WSL2 utility VM kernel on Windows); stronger multi-tenant boundary requires dedicated ephemeral VM/CI runners.'
            ]
        }
        : {
            enforcedBoundaries: [],
            limitations: [
                'SANDBOX_UNAVAILABLE: No approved container runtime/daemon is available on this host. Governed builds/tests are blocked and will NOT fall back silently to host shell execution.'
            ]
        };

    return {
        discoveredAt: new Date().toISOString(),
        os: {
            platform,
            arch,
            type: os.type(),
            release: os.release()
        },
        sandboxStatus,
        sandboxAvailable,
        selectedRuntime,
        containers: {
            docker,
            podman,
            wsl
        },
        toolchains: {
            dotnet,
            java: {
                installed: javaMaven.javaInstalled,
                binaryPath: javaMaven.javaBinaryPath,
                version: javaMaven.javaVersion
            },
            maven: {
                installed: javaMaven.mavenInstalled,
                binaryPath: javaMaven.mavenBinaryPath,
                version: javaMaven.mavenVersion
            },
            node: {
                version: nodeGit.nodeVersion,
                npmInstalled: nodeGit.npmInstalled,
                npmVersion: nodeGit.npmVersion
            },
            git: {
                installed: nodeGit.gitInstalled,
                version: nodeGit.gitVersion
            }
        },
        scannersAndSbom: scanners,
        workspace,
        prerequisites,
        boundaryDisclosure
    };
}

module.exports = {
    SANDBOX_READINESS,
    safeExecProbe,
    findExecutableOnPath,
    discoverEnvironment
};

