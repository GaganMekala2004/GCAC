const path = require('path');
const fs = require('fs');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');
const { OUTCOME_STATUS } = require('../../outcomeContract');
const { SANDBOX_READINESS, discoverEnvironment } = require('../../sandbox/environmentDiscovery');
const { EXECUTION_POLICY_VERSION, OPERATION_TYPES, TrustedExecutionGateway } = require('../../sandbox/trustedExecutionGateway');
const { ContainerSandboxBackend } = require('../../sandbox/containerSandboxBackend');
const { resolveProfileForRepository, assertProfileProvisioned } = require('../../sandbox/toolchainProfiles');
const { resolveDotnetProjectFile, hasDotnetPackageDependencies } = require('../dotnetProjectLocator');
const { snapshotPath, readSnapshot, refreshSnapshot } = require('../nugetAdvisories');
const { auditResolvedProjects } = require('../nugetOfflineAudit');

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
        try {
            readSnapshot(options.advisorySnapshotPath || snapshotPath(options.workspaceRoot || process.cwd()));
            return { available: true, version: this.version, mode: 'OFFLINE_ADVISORY_SNAPSHOT', reason: '' };
        } catch (_) { /* Approved sandbox remains available for unsupported graphs. */ }
        if (fs.existsSync(options.advisorySnapshotPath || snapshotPath(options.workspaceRoot || process.cwd()))) {
            return { available: true, version: this.version, mode: 'OFFLINE_ADVISORY_SNAPSHOT', reason: 'Advisory snapshot requires validation/refresh before use.' };
        }
        if (options && (options.sandboxBackend || options.executionGateway || options.envReport?.sandboxAvailable)) {
            return {
                available: true,
                version: options.envReport?.selectedRuntime || 'sandbox',
                mode: 'SANDBOX',
                reason: ''
            };
        }

        const envReport = options?.envReport || discoverEnvironment({
            workspaceRoot: options?.workspaceRoot || process.cwd(),
            useCache: true
        });
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
            'NU1900',
            'NU1905',
            'Unable to load the service index for source',
            'Vulnerability intelligence source inaccessible',
            'The download of',
            'failed to retrieve information about vulnerabilities',
            'No vulnerability data'
        ];

        const hasFeedError = feedErrors.some(err => combined.includes(err));

        const findings = [];
        const lines = combined.split('\n');
        const effectiveRoot = meta.repositoryRoot || workspaceRoot;

        // Pattern: > PackageName   Requested   Resolved   Severity   Advisory URL
        const pkgLineRegex = />\s+([A-Za-z0-9_.-]+)\s+(?:(\S+)\s+)?(\S+)\s+(Critical|High|Moderate|Low)\s+(https?:\/\/\S+)/i;

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
            inaccessible: hasFeedError,
            findings,
            error: hasFeedError ? 'AUDIT UNAVAILABLE — Vulnerability intelligence source inaccessible' : null
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
                                remediationGuidance: meta.offlineAudit && transitive.includes(pkg) && pkg.fixedVersion
                                    ? `Pin the resolved transitive package '${pkg.id}' in the project at verified version ${pkg.fixedVersion} and validate the restored graph.`
                                    : `Upgrade package '${pkg.id}' to a secure version verified against ${advUrl}.`,
                                packageName: pkg.id,
                                currentVersion: pkg.resolvedVersion,
                                fixedVersion: meta.offlineAudit === true ? pkg.fixedVersion || '' : '',
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
        let offlineDiagnostic = '';
        let snapshot;
        try {
            const snapshotFile = options.advisorySnapshotPath || snapshotPath(workspaceRoot);

            try { snapshot = readSnapshot(snapshotFile); }
            catch (error) {
                // Refresh official public data only; this never executes repository
                // code or sends package inventories outside the workspace.
                if (options.refreshAdvisories === false || options.abortSignal?.aborted ||
                    (!fs.existsSync(snapshotFile) && options.refreshAdvisories !== true)) throw error;
                snapshot = await refreshSnapshot(snapshotFile);
            }
            const audited = auditResolvedProjects(projectDir, snapshot, options.abortSignal);
            const effectiveRoot = repoContext.repositoryRoot || boundaryRoot;
            const findings = this.parseJsonAuditOutput(audited, projectFile, effectiveRoot, scanId, { ...repoContext, offlineAudit: true });
            return {
                scannerId: this.id, status: SCANNER_STATUS.COMPLETED,
                executionPolicy: 'READ_ONLY_ADVISORY_DATA', networkPolicy: 'NO_NETWORK',
                findings, errors: [], warnings: [], durationMs: Date.now() - startTime,
                coverage: `100% (${audited.packagesChecked} resolved direct/transitive packages across ${audited.projectsChecked} projects)`,
                diagnostics: { advisorySource: snapshot.source, advisoryFetchedAt: snapshot.fetchedAt,
                    projectsChecked: audited.projectsChecked, packagesChecked: audited.packagesChecked }
            };
        } catch (error) { offlineDiagnostic = error.message; }
        const repoLabel = repoContext.repository || (boundaryRoot && targetPath ? path.relative(boundaryRoot, targetPath).replace(/\\/g, '/') || path.basename(boundaryRoot) : path.basename(projectDirRoot));
        const envReport = options.envReport || (!options.executionGateway && !options.sandboxBackend
            ? discoverEnvironment({ workspaceRoot, useCache: true })
            : null);
        const gateway = options.executionGateway || new TrustedExecutionGateway({
            workspaceRoot,
            backend: options.sandboxBackend || null,
            envReport,
            profilesPath: options.profilesPath
        });

        let profile;
        try {
            profile = resolveProfileForRepository(projectFile || projectDirRoot, { Technology: 'dotnet' }, options.profilesPath, {
                repositoryLabel: repoLabel
            });
            const isRealContainer = !options.sandboxBackend ||
                (options.sandboxBackend instanceof ContainerSandboxBackend) ||
                (options.sandboxBackend && typeof options.sandboxBackend.execFileFn === 'function');
            if (isRealContainer && options.allowTemplateDigests !== true) {
                assertProfileProvisioned(profile, { repositoryLabel: repoLabel });
            }
        } catch (err) {
            const targetFramework = err.targetFramework || profile?.targetFramework || 'unknown';
            const profileId = err.profileId || profile?.profileId || 'unresolved';
            const imageDigest = err.imageDigest || profile?.imageDigest || 'none';
            const digestStatus = err.digestStatus || profile?.digestStatus || 'UNRESOLVED';
            const diagMsg = `Target repository '${repoLabel}' (${targetFramework} -> ${profileId}): ${err.message}`;
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                sandboxStatus: SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                executionPolicy: 'SANDBOX_GATEWAY',
                toolchainProfileId: profileId,
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [diagMsg],
                warnings: [
                    `Toolchain resolution failed for '${repoLabel}'.`,
                    err.code === 'UNPROVISIONED_TOOLCHAIN_PROFILE'
                        ? `Profile '${profileId}' uses template placeholder digest '${imageDigest}'. Configure a verified SDK digest for this profile.`
                        : err.message
                ],
                coverage: err.code === 'UNPROVISIONED_TOOLCHAIN_PROFILE'
                    ? '0% (Unprovisioned toolchain profile)'
                    : '0% (Toolchain profile blocked)',
                diagnostics: {
                    repository: repoLabel,
                    targetFramework,
                    toolchainProfileId: profileId,
                    imageDigest,
                    digestStatus
                }
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

        if (options.isRescan && snapshot && projectDir.endsWith('.csproj')) {
            try {
                const restored = await gateway.executeOperation({ ...req, operation: OPERATION_TYPES.NUGET_RESTORE_GRAPH,
                    workspaceRef: boundaryRoot, inputs: [path.relative(boundaryRoot, projectFile).split(path.sep).join('/')],
                    networkPolicy: 'NO_NETWORK' }, { ...options, originalWorkspaceRoot: boundaryRoot });
                if (!restored.executed || restored.exitCode !== 0 || restored.machineStatus !== OUTCOME_STATUS.PASSED)
                    throw Error(restored.reason || 'Offline package restore failed.');
                const graph = JSON.parse(restored.outputArtifacts?.['project.assets.json']?.content || 'null');
                if (!graph || graph.project?.restore?.projectPath !== path.posix.join('/sandbox-work', path.relative(boundaryRoot, projectFile).split(path.sep).join('/')))
                    throw Error('Offline restore did not produce the target project graph.');
                const audit = auditResolvedProjects(projectFile, snapshot, options.abortSignal, undefined, graph);
                return { scannerId: this.id, status: SCANNER_STATUS.COMPLETED, executionPolicy: 'SANDBOX_GATEWAY',
                    networkPolicy: 'NO_NETWORK', sandboxStatus: restored.sandboxStatus, errors: [], warnings: [],
                    coverage: `100% (${audit.packagesChecked} restored packages checked)`,
                    findings: this.parseJsonAuditOutput(audit, projectFile, boundaryRoot, scanId, { ...repoContext, offlineAudit: true }) };
            } catch (error) {
                return { scannerId: this.id, status: SCANNER_STATUS.FAILED, findings: [], warnings: [],
                    errors: ['Post-fix NuGet verification: ' + error.message], coverage: '0% (restore or audit incomplete)' };
            }
        }
        const gwRes = await gateway.executeOperation(req, {
            ...options,
            originalWorkspaceRoot: boundaryRoot
        });

        if (!gwRes.executed || gwRes.timedOut || gwRes.cancelled ||
            gwRes.machineStatus === OUTCOME_STATUS.BLOCKED ||
            gwRes.machineStatus === OUTCOME_STATUS.COULD_NOT_RUN) {
            const diagMsg = `Target repository '${repoLabel}' (${profile.targetFramework || 'dotnet'} -> ${profile.profileId}): ${gwRes.reason || gwRes.summary || 'AUDIT UNAVAILABLE — Sandbox required for NuGet dependency audit.'}`;
            return {
                scannerId: this.id,
                status: gwRes.cancelled ? SCANNER_STATUS.CANCELLED : SCANNER_STATUS.FAILED,
                sandboxStatus: gwRes.sandboxStatus || SANDBOX_READINESS.SANDBOX_UNAVAILABLE,
                executionPolicy: 'SANDBOX_GATEWAY',
                toolchainProfileId: profile.profileId,
                networkPolicy: gwRes.networkPolicy || 'NO_NETWORK',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [diagMsg],
                warnings: gwRes.prerequisites || ['Vulnerability audit requires approved sandbox & offline/internal feed cache; host fallback blocked.'],
                coverage: '0% (Sandbox unavailable — NuGet audit blocked)',
                diagnostics: {
                    repository: repoLabel,
                    targetFramework: profile.targetFramework || 'unknown',
                    toolchainProfileId: profile.profileId,
                    imageDigest: profile.imageDigest,
                    digestStatus: profile.digestStatus || 'VERIFIED_IMAGE_DIGEST'
                }
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
                findings: parsed.findings,
                durationMs: Date.now() - startTime,
                errors: [parsed.error],
                warnings: [`Offline audit unavailable: ${offlineDiagnostic}`, 'Refresh official advisory data with: node scripts/refresh-nuget-advisories.js. A package cache alone contains no vulnerability intelligence.'],
                coverage: '0% (Audit source inaccessible)'
            };
        }

        if (gwRes.exitCode !== 0) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                sandboxStatus: gwRes.sandboxStatus,
                executionPolicy: 'SANDBOX_GATEWAY',
                backendType: gwRes.backendType,
                networkPolicy: gwRes.networkPolicy,
                findings: parsed.findings,
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
            coverage: '100% (Sandboxed direct and transitive dependencies checked)',
            diagnostics: {
                repository: repoLabel,
                targetFramework: profile.targetFramework || 'net10.0',
                toolchainProfileId: profile.profileId,
                imageDigest: profile.imageDigest,
                digestStatus: profile.digestStatus || 'VERIFIED_IMAGE_DIGEST'
            }
        };
    }
}

module.exports = {
    NuGetAuditScanner,
    NugetAuditScanner: NuGetAuditScanner
};
