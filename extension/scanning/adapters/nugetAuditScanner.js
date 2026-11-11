const path = require('path');
const fs = require('fs');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');
const { OUTCOME_STATUS } = require('../../outcomeContract');
const { SANDBOX_READINESS, discoverEnvironment } = require('../../sandbox/environmentDiscovery');
const { EXECUTION_POLICY_VERSION, OPERATION_TYPES, TrustedExecutionGateway } = require('../../sandbox/trustedExecutionGateway');
const { resolveProfileForRepository } = require('../../sandbox/toolchainProfiles');
const { resolveDotnetProjectFile, hasDotnetPackageDependencies } = require('../dotnetProjectLocator');

function extractAdvisoryId(advisoryUrl = '') {
    const m = String(advisoryUrl || '').match(/(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,7})/i);
    return m ? m[0].toUpperCase() : null;
}

/**
 * NuGet Dependency Auditing Scanner Adapter
 * Detects known vulnerabilities in direct and transitive NuGet package references.
 * Strictly respects offline boundaries, never fabricates CVEs/versions,
 * and reports AUDIT UNAVAILABLE when feeds are inaccessible.
 */
class NuGetAuditScanner extends ScannerAdapter {
    constructor() {
        super({
            id: 'nuget-audit',
            name: 'NuGet Dependency Auditor',
            version: '8.0.0',
            supportedLanguages: ['csharp', 'dotnet'],
            supportedCategories: ['CWE-1395 (Vulnerable 3PP Dependency)']
        });
    }

    async isAvailable(options = {}) {
        if (options && (options.sandboxBackend || options.executionGateway || options.envReport?.sandboxAvailable)) {
            return {
                available: true,
                version: options.envReport?.selectedRuntime || 'sandbox',
                mode: 'SANDBOX',
                reason: ''
            };
        }

        const envReport = discoverEnvironment(options?.workspaceRoot || process.cwd());
        if (envReport.sandboxAvailable) {
            return {
                available: true,
                version: envReport.selectedRuntime || 'sandbox',
                mode: 'SANDBOX',
                reason: ''
            };
        }

        const hostVer = envReport.toolchains?.dotnet?.activeVersion;
        return {
            available: false,
            version: hostVer || '',
            mode: 'SANDBOX_REQUIRED',
            reason: 'SANDBOX_UNAVAILABLE: NuGet vulnerability auditing requires an approved container runtime (Docker Linux mode or Podman); host-shell fallback is disabled.'
        };
    }

    /**
     * Parses output from `dotnet list package --vulnerable --include-transitive`
     * Handles text table format and checks for feed accessibility failures.
     */
    parseAuditOutput(stdout, stderr, targetFile, workspaceRoot, scanId, meta = {}) {
        const combined = (stdout || '') + '\n' + (stderr || '');

        // Detect inaccessible vulnerability audit sources
        const feedErrors = [
            'error NU1900',
            'error NU1901',
            'error NU1902',
            'error NU1903',
            'error NU1904',
            'Unable to load the service index for source',
            'Vulnerability intelligence source inaccessible',
            'The download of',
            'failed to retrieve information about vulnerabilities',
            'No vulnerability data'
        ];

        const hasFeedError = feedErrors.some(err => combined.includes(err));
        if (hasFeedError && !combined.includes('has the following vulnerable packages')) {
            return {
                inaccessible: true,
                findings: [],
                error: 'AUDIT UNAVAILABLE — Vulnerability intelligence source inaccessible'
            };
        }

        const findings = [];
        const lines = combined.split('\n');
        const effectiveRoot = meta.repositoryRoot || workspaceRoot;

        // Pattern: > PackageName   Requested   Resolved   Severity   Advisory URL
        const pkgLineRegex = />\s+([A-Za-z0-9_.-]+)\s+(\S+)\s+(\S+)\s+(Critical|High|Moderate|Low)\s+(https?:\/\/\S+)/i;

        for (const line of lines) {
            const match = line.trim().match(pkgLineRegex);
            if (!match) continue;

            const [, packageName, requestedVer, resolvedVer, severityStr, advisoryUrl] = match;
            if (!packageName || !resolvedVer || !advisoryUrl) continue;

            let relPath = targetFile || '';
            if (path.isAbsolute(relPath) && effectiveRoot) {
                relPath = path.relative(effectiveRoot, relPath);
            }
            relPath = relPath.replace(/\\/g, '/');
            if (!relPath) continue;

            const advisoryId = extractAdvisoryId(advisoryUrl);
            const finding = new NormalizedFinding({
                scanId,
                scannerId: this.id,
                scannerVersion: this.version,
                ruleId: advisoryId || 'NU1901',
                title: `Vulnerable Dependency: ${packageName} (${resolvedVer})`,
                description: `Package '${packageName}' resolved version ${resolvedVer} (requested ${requestedVer}) has a published NuGet security advisory: ${advisoryUrl}`,
                severity: severityStr.toUpperCase() === 'MODERATE' ? SEVERITY_LEVELS.MEDIUM : severityStr,
                cwe: 'CWE-1395',
                confidence: 'High',
                detectionMethod: 'NUGET_ADVISORY_DATA',
                filePath: relPath,
                line: 1,
                evidence: `Package: ${packageName}, Requested: ${requestedVer}, Resolved: ${resolvedVer}, Severity: ${severityStr}, Advisory: ${advisoryUrl}`,
                evidenceRef: `${relPath}:1`,
                remediationGuidance: `Upgrade package reference '${packageName}' in ${path.basename(relPath)} to a patched non-vulnerable version verified against ${advisoryUrl}.`,
                classificationType: 'CONFIRMED_RULE_VIOLATION',
                packageName,
                currentVersion: resolvedVer,
                fixedVersion: '', // Never invent unverified fixed versions
                advisoryUrl,
                repository: meta.repository || '',
                repositoryRoot: meta.repositoryRoot || '',
                canonicalRepositoryId: meta.canonicalRepositoryId || '',
                projectPath: meta.projectPath || relPath,
                applicationNumber: meta.applicationNumber || '',
                applicationName: meta.applicationName || '',
                applicationIdentitySource: meta.applicationIdentitySource || '',
                technology: 'dotnet'
            });

            findings.push(finding);
        }

        return {
            inaccessible: false,
            findings,
            error: null
        };
    }

    /**
     * Parses JSON format from `dotnet list package --vulnerable --format json` where supported
     */
    parseJsonAuditOutput(jsonContent, targetFile, workspaceRoot, scanId, meta = {}) {
        const findings = [];
        try {
            const parsed = typeof jsonContent === 'string' ? JSON.parse(jsonContent) : jsonContent;
            const projects = parsed.projects || [];
            const effectiveRoot = meta.repositoryRoot || workspaceRoot;

            for (const proj of projects) {
                const projPath = proj.path || targetFile;
                let relPath = projPath || '';
                if (path.isAbsolute(relPath) && effectiveRoot) {
                    relPath = path.relative(effectiveRoot, relPath);
                }
                relPath = relPath.replace(/\\/g, '/');
                if (!relPath) continue;

                const frameworks = proj.frameworks || [];
                for (const fw of frameworks) {
                    const topLevel = fw.topLevelPackages || [];
                    const transitive = fw.transitivePackages || [];
                    const allPkgs = [...topLevel, ...transitive];

                    for (const pkg of allPkgs) {
                        const vulns = pkg.vulnerabilities || [];
                        for (const vuln of vulns) {
                            const advUrl = vuln.advisoryUrl || vuln.advisoryurl;
                            if (!pkg.id || !pkg.resolvedVersion || !advUrl) continue;
                            const advisoryId = extractAdvisoryId(advUrl);
                            const finding = new NormalizedFinding({
                                scanId,
                                scannerId: this.id,
                                scannerVersion: this.version,
                                ruleId: advisoryId || 'NU1901',
                                title: `Vulnerable Dependency: ${pkg.id} (${pkg.resolvedVersion})`,
                                description: `Package '${pkg.id}' version ${pkg.resolvedVersion} contains security advisory: ${advUrl}`,
                                severity: vuln.severity || SEVERITY_LEVELS.HIGH,
                                cwe: 'CWE-1395',
                                confidence: 'High',
                                detectionMethod: 'NUGET_ADVISORY_DATA',
                                filePath: relPath,
                                line: 1,
                                evidence: `Package: ${pkg.id}, Resolved: ${pkg.resolvedVersion}, Severity: ${vuln.severity || 'High'}, Advisory: ${advUrl}`,
                                evidenceRef: `${relPath}:1`,
                                remediationGuidance: `Upgrade package '${pkg.id}' to a secure version verified against ${advUrl}.`,
                                packageName: pkg.id,
                                currentVersion: pkg.resolvedVersion,
                                fixedVersion: '',
                                advisoryUrl: advUrl,
                                repository: meta.repository || '',
                                repositoryRoot: meta.repositoryRoot || '',
                                canonicalRepositoryId: meta.canonicalRepositoryId || '',
                                projectPath: meta.projectPath || relPath,
                                applicationNumber: meta.applicationNumber || '',
                                applicationName: meta.applicationName || '',
                                applicationIdentitySource: meta.applicationIdentitySource || '',
                                technology: 'dotnet'
                            });
                            findings.push(finding);
                        }
                    }
                }
            }
        } catch (e) {}
        return findings;
    }

    async scan(workspaceRoot, targetPath, options = {}) {
        const scanId = options.scanId || `scan-${Date.now()}`;
        const startTime = Date.now();

        const projectDir = targetPath || workspaceRoot;
        if (!projectDir || !fs.existsSync(projectDir)) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                executionPolicy: 'SANDBOX_GATEWAY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [`Target path does not exist: '${projectDir}'.`],
                warnings: [],
                coverage: '0% (Target path missing)'
            };
        }

        const repoContext = options.repoContext || {};
        const boundaryRoot = repoContext.repositoryRoot || workspaceRoot;
        const projectFile = resolveDotnetProjectFile(boundaryRoot, projectDir);

        if (!projectFile) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.NO_SCANNABLE_INPUTS,
                noScannableInputs: true,
                executionPolicy: 'SANDBOX_GATEWAY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [],
                warnings: ['No .NET project or solution found for dependency auditing.'],
                coverage: '0% (No .NET project detected)'
            };
        }

        if (!hasDotnetPackageDependencies(projectFile)) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.NO_SCANNABLE_INPUTS,
                noScannableInputs: true,
                executionPolicy: 'SANDBOX_GATEWAY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [],
                warnings: ['Target .NET manifest declares zero NuGet PackageReference/packages.config entries.'],
                coverage: '0% (Empty dependency manifest — 0 packages declared)'
            };
        }

        const projectDirRoot = path.dirname(projectFile);
        const gateway = options.executionGateway || new TrustedExecutionGateway({
            workspaceRoot,
            backend: options.sandboxBackend || null,
            envReport: options.envReport || null,
            profilesPath: options.profilesPath
        });

        let profile;
        try {
            profile = resolveProfileForRepository(projectDirRoot, { Technology: 'dotnet' }, options.profilesPath);
        } catch (err) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                executionPolicy: 'SANDBOX_GATEWAY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [err.message],
                warnings: [],
                coverage: '0% (Toolchain profile blocked)'
            };
        }

        const effectiveAppId = repoContext.applicationNumber || options.applicationId || 'UNMAPPED-LOCAL';
        const req = {
            runId: options.runId || scanId,
            applicationId: effectiveAppId,
            vulnerabilityId: options.vulnerabilityId || 'VUL-NUGET',
            workspaceRef: projectDirRoot,
            operation: OPERATION_TYPES.NUGET_AUDIT,
            toolchainProfileId: profile.profileId,
            requestedExecutable: 'dotnet',
            inputs: [path.basename(projectFile)],
            expectedOutputPaths: profile.outputArtifactPaths || [],
            extraArgs: [],
            policyVersion: EXECUTION_POLICY_VERSION,
            networkPolicy: options.networkPolicy || profile.networkPolicy || 'NO_NETWORK',
            isControlledRestoreOperation: options.isControlledRestoreOperation === true,
            requestedFeeds: options.requestedFeeds || [],
            resourcePolicy: {
                ...profile.runtimeLimits,
                timeoutMs: options.timeoutMs || profile.runtimeLimits.timeoutMs
            }
        };

        const gwRes = await gateway.executeOperation(req, {
            ...options,
            originalWorkspaceRoot: boundaryRoot
        });

        if (!gwRes.executed || gwRes.timedOut || gwRes.cancelled ||
            gwRes.machineStatus === OUTCOME_STATUS.BLOCKED ||
            gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
            return {
                scannerId: this.id,
                status: gwRes.cancelled ? SCANNER_STATUS.CANCELLED : SCANNER_STATUS.FAILED,
                sandboxStatus: gwRes.sandboxStatus || SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                executionPolicy: 'SANDBOX_GATEWAY',
                networkPolicy: gwRes.networkPolicy || 'NO_NETWORK',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [gwRes.reason || gwRes.summary || 'AUDIT UNAVAILABLE — Sandbox required for NuGet dependency audit.'],
                warnings: gwRes.prerequisites || ['Vulnerability audit requires approved sandbox & offline/internal feed cache; host fallback blocked.'],
                coverage: '0% (Sandbox unavailable — NuGet audit blocked)'
            };
        }

        const effectiveRepoRoot = repoContext.repositoryRoot || projectDirRoot;
        const meta = {
            repository: repoContext.repository || effectiveRepoRoot,
            repositoryRoot: effectiveRepoRoot,
            canonicalRepositoryId: repoContext.canonicalRepositoryId || '',
            projectPath: path.relative(effectiveRepoRoot, projectFile).replace(/\\/g, '/'),
            applicationNumber: repoContext.applicationNumber || '',
            applicationName: repoContext.applicationName || '',
            applicationIdentitySource: repoContext.applicationIdentitySource || ''
        };

        const parsed = this.parseAuditOutput(gwRes.stdout || '', gwRes.stderr || '', projectFile, effectiveRepoRoot, scanId, meta);
        if (parsed.inaccessible) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                sandboxStatus: gwRes.sandboxStatus,
                executionPolicy: 'SANDBOX_GATEWAY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [parsed.error],
                warnings: ['Vulnerability audit feed inaccessible; cannot guarantee zero findings.'],
                coverage: '0% (Audit source inaccessible)'
            };
        }

        if ((gwRes.exitCode ?? 0) !== 0 && parsed.findings.length === 0) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                sandboxStatus: gwRes.sandboxStatus,
                executionPolicy: 'SANDBOX_GATEWAY',
                backendType: gwRes.backendType,
                networkPolicy: gwRes.networkPolicy,
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [`AUDIT UNAVAILABLE — NuGet audit command exited with code ${gwRes.exitCode}: ${(gwRes.stderr || gwRes.stdout || 'Unknown error').slice(0, 300)}`],
                warnings: ['NuGet dependency audit failed to complete cleanly; zero findings cannot be claimed.'],
                coverage: '0% (NuGet audit command failed)'
            };
        }

        return {
            scannerId: this.id,
            status: SCANNER_STATUS.COMPLETED,
            sandboxStatus: gwRes.sandboxStatus,
            executionPolicy: 'SANDBOX_GATEWAY',
            backendType: gwRes.backendType,
            networkPolicy: gwRes.networkPolicy,
            findings: parsed.findings,
            durationMs: Date.now() - startTime,
            errors: [],
            warnings: [],
            coverage: '100% (Sandboxed direct and transitive dependencies checked)'
        };
    }
}

module.exports = {
    NuGetAuditScanner,
    NugetAuditScanner: NuGetAuditScanner
};
