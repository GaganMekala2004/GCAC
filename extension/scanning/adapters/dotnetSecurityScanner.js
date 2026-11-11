const path = require('path');
const fs = require('fs');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');
const { OUTCOME_STATUS } = require('../../outcomeContract');
const { SANDBOX_READINESS, discoverEnvironment } = require('../../sandbox/environmentDiscovery');
const { EXECUTION_POLICY_VERSION, OPERATION_TYPES, TrustedExecutionGateway } = require('../../sandbox/trustedExecutionGateway');
const { resolveProfileForRepository } = require('../../sandbox/toolchainProfiles');
const { resolveDotnetProjectFile } = require('../dotnetProjectLocator');

/**
 * Known Roslyn Security Diagnostic Rules mapping to CWE and Severity
 */
const ROSLYN_SECURITY_RULES = {
    'CA5350': {
        cwe: 'CWE-327',
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Do Not Use Weak Cryptographic Algorithm (DES/RC2)',
        description: 'The use of weak cryptographic algorithms such as DES or RC2 is vulnerable to decryption and brute force attacks.'
    },
    'CA5351': {
        cwe: 'CWE-327',
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Do Not Use Broken Cryptographic Algorithm (MD5)',
        description: 'MD5 is cryptographically broken and subject to collision attacks. Use SHA-256 or SHA-512 instead.'
    },
    'CA5358': {
        cwe: 'CWE-326',
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Do Not Use Unsafe Cipher Modes',
        description: 'ECB cipher mode is deterministic and leaks pattern information. Use CBC or GCM mode.'
    },
    'CA2100': {
        cwe: 'CWE-89',
        severity: SEVERITY_LEVELS.CRITICAL,
        title: 'Review SQL queries for security vulnerabilities',
        description: 'A SQL command string appears to be constructed from untrusted input without parameterization.'
    },
    'CA3001': {
        cwe: 'CWE-89',
        severity: SEVERITY_LEVELS.CRITICAL,
        title: 'Review code for SQL injection vulnerabilities',
        description: 'Potential SQL injection vulnerability in database command.'
    },
    'CA3002': {
        cwe: 'CWE-79',
        severity: SEVERITY_LEVELS.MEDIUM,
        title: 'Review code for XSS vulnerabilities',
        description: 'Potential Cross-Site Scripting (XSS) vulnerability detected in web output.'
    },
    'CA3003': {
        cwe: 'CWE-22',
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Review code for file path injection vulnerabilities',
        description: 'Untrusted input is passed to file path APIs without validation.'
    },
    'CA3006': {
        cwe: 'CWE-78',
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Review code for process command injection vulnerabilities',
        description: 'Untrusted input is used in process command construction.'
    }
};

class DotnetSecurityScanner extends ScannerAdapter {
    constructor() {
        super({
            id: 'dotnet-security',
            name: '.NET Security Analyzer',
            version: '8.0.0',
            supportedLanguages: ['csharp', 'dotnet'],
            supportedCategories: [
                'CWE-327 (Broken Crypto)',
                'CWE-89 (SQL Injection)',
                'CWE-79 (Cross-Site Scripting)',
                'CWE-22 (Path Traversal)',
                'CWE-78 (Command Injection)'
            ]
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
            reason: 'SANDBOX_UNAVAILABLE: Build-backed .NET security scanning requires an approved container runtime (Docker Linux mode or Podman); host-shell fallback is disabled.'
        };
    }

    /**
     * Parses standard Roslyn compiler diagnostic output lines into NormalizedFinding records
     * Format: File.cs(line,col): warning CA5350: Message [Project.csproj]
     */
    parseRoslynDiagnostics(output, workspaceRoot, scanId, meta = {}) {
        const findings = [];
        if (!output || typeof output !== 'string') return findings;

        const lines = output.split('\n');
        const diagRegex = /^(.*?)\((\d+),(\d+)\):\s*(warning|error)\s+([A-Z0-9]+):\s*(.*?)(?:\s+\[.*?\])?$/;
        const effectiveRoot = meta.repositoryRoot || workspaceRoot;

        for (const line of lines) {
            const match = line.trim().match(diagRegex);
            if (!match) continue;

            const [, rawFilePath, lineStr, colStr, severityType, ruleId, message] = match;
            if (!rawFilePath || !rawFilePath.trim()) continue;

            const knownRule = ROSLYN_SECURITY_RULES[ruleId];
            if (!knownRule && !ruleId.startsWith('CA5') && !ruleId.startsWith('CA3')) {
                continue;
            }

            const lineNum = parseInt(lineStr, 10);
            const colNum = parseInt(colStr, 10);

            let relPath = rawFilePath.trim();
            if (path.isAbsolute(relPath) && effectiveRoot) {
                relPath = path.relative(effectiveRoot, relPath);
            }
            relPath = relPath.replace(/\\/g, '/');
            if (!relPath) continue;

            const finding = new NormalizedFinding({
                scanId,
                scannerId: this.id,
                scannerVersion: this.version,
                ruleId: ruleId,
                title: knownRule ? knownRule.title : `Security Diagnostic ${ruleId}`,
                description: message || (knownRule ? knownRule.description : `Roslyn security diagnostic ${ruleId}`),
                severity: knownRule ? knownRule.severity : (severityType === 'error' ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM),
                cwe: knownRule ? knownRule.cwe : null,
                confidence: 'High',
                detectionMethod: 'ROSLYN_ANALYZER',
                filePath: relPath,
                line: lineNum,
                column: colNum,
                evidence: line.trim(),
                evidenceRef: `${relPath}:${lineNum}`,
                remediationGuidance: knownRule ? `Follow remediation guidance for ${knownRule.cwe} and rule ${ruleId}.` : 'Address security diagnostic.',
                repository: meta.repository || '',
                repositoryRoot: meta.repositoryRoot || '',
                canonicalRepositoryId: meta.canonicalRepositoryId || '',
                projectPath: meta.projectPath || '',
                applicationNumber: meta.applicationNumber || '',
                applicationName: meta.applicationName || '',
                applicationIdentitySource: meta.applicationIdentitySource || '',
                technology: 'dotnet'
            });

            findings.push(finding);
        }

        return findings;
    }

    /**
     * Parses SARIF 2.1.0 JSON output if generated by dotnet build /p:ErrorLog=...
     */
    parseSarif(sarifContent, workspaceRoot, scanId, meta = {}) {
        const findings = [];
        try {
            const sarif = typeof sarifContent === 'string' ? JSON.parse(sarifContent) : sarifContent;
            const runs = sarif.runs || [];
            const effectiveRoot = meta.repositoryRoot || workspaceRoot;

            for (const run of runs) {
                const results = run.results || [];
                for (const res of results) {
                    const ruleId = res.ruleId || 'SECURITY-RULE';
                    const known = ROSLYN_SECURITY_RULES[ruleId];
                    if (!known && !ruleId.startsWith('CA5') && !ruleId.startsWith('CA3')) continue;

                    const loc = (res.locations && res.locations[0]?.physicalLocation) || {};
                    let uri = loc.artifactLocation?.uri || '';
                    if (!uri) continue;
                    if (path.isAbsolute(uri) && effectiveRoot) {
                        uri = path.relative(effectiveRoot, uri);
                    }
                    const relPath = uri.replace(/\\/g, '/');
                    const region = loc.region || {};

                    const finding = new NormalizedFinding({
                        scanId,
                        scannerId: this.id,
                        scannerVersion: this.version,
                        ruleId,
                        title: known ? known.title : ruleId,
                        description: res.message?.text || (known ? known.description : ''),
                        severity: known ? known.severity : (res.level === 'error' ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM),
                        cwe: known ? known.cwe : null,
                        confidence: 'High',
                        detectionMethod: 'ROSLYN_ANALYZER',
                        filePath: relPath,
                        line: region.startLine || 1,
                        column: region.startColumn || 1,
                        evidence: res.message?.text || '',
                        evidenceRef: `${relPath}:${region.startLine || 1}`,
                        remediationGuidance: known ? `Follow remediation guidance for ${known.cwe}.` : '',
                        repository: meta.repository || '',
                        repositoryRoot: meta.repositoryRoot || '',
                        canonicalRepositoryId: meta.canonicalRepositoryId || '',
                        projectPath: meta.projectPath || '',
                        applicationNumber: meta.applicationNumber || '',
                        applicationName: meta.applicationName || '',
                        applicationIdentitySource: meta.applicationIdentitySource || '',
                        technology: 'dotnet'
                    });
                    findings.push(finding);
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
                warnings: ['No .NET solution (.sln) or project (.csproj) found in target path.'],
                coverage: '0% (No .NET project detected)'
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

        const operation = options.isRescan ? OPERATION_TYPES.TARGETED_RESCAN : OPERATION_TYPES.SECURITY_SCAN;
        const effectiveAppId = repoContext.applicationNumber || options.applicationId || 'UNMAPPED-LOCAL';
        const req = {
            runId: options.runId || scanId,
            applicationId: effectiveAppId,
            vulnerabilityId: options.vulnerabilityId || 'VUL-SCAN',
            workspaceRef: projectDirRoot,
            operation,
            toolchainProfileId: profile.profileId,
            requestedExecutable: 'dotnet',
            inputs: [path.basename(projectFile)],
            expectedOutputPaths: profile.outputArtifactPaths || [],
            extraArgs: [],
            policyVersion: EXECUTION_POLICY_VERSION,
            networkPolicy: profile.networkPolicy || 'NO_NETWORK',
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
                toolchainProfileId: profile.profileId,
                networkPolicy: gwRes.networkPolicy || 'NO_NETWORK',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [gwRes.reason || gwRes.summary || 'SANDBOX_UNAVAILABLE'],
                warnings: gwRes.prerequisites || [],
                coverage: '0% (Build-backed security scan blocked or failed)'
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

        const findings = this.parseRoslynDiagnostics((gwRes.stdout || '') + '\n' + (gwRes.stderr || ''), effectiveRepoRoot, scanId, meta);
        return {
            scannerId: this.id,
            status: SCANNER_STATUS.COMPLETED,
            sandboxStatus: gwRes.sandboxStatus,
            executionPolicy: 'SANDBOX_GATEWAY',
            backendType: gwRes.backendType,
            toolchainProfileId: profile.profileId,
            networkPolicy: gwRes.networkPolicy,
            findings,
            durationMs: Date.now() - startTime,
            errors: [],
            warnings: gwRes.exitCode !== 0 ? [`Build completed with compilation diagnostics (exit code ${gwRes.exitCode})`] : [],
            coverage: gwRes.exitCode === 0 ? '100% (Sandboxed Roslyn analyzers active)' : 'Coverage active (Sandboxed diagnostics encountered)'
        };
    }
}

module.exports = {
    DotnetSecurityScanner,
    ROSLYN_SECURITY_RULES
};
