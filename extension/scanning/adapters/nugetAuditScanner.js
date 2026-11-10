const { spawn, execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');
const { isExecutableAvailable } = require('../../testRunner');

/**
 * NuGet Dependency Auditing Scanner Adapter
 * Detects known vulnerabilities in direct and transitive NuGet package references.
 * Strictly respects offline boundaries and reports AUDIT UNAVAILABLE when feeds are inaccessible.
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

    async isAvailable() {
        if (!isExecutableAvailable('dotnet')) {
            return {
                available: false,
                version: '',
                reason: "Required runtime unavailable: 'dotnet' not found in PATH."
            };
        }

        try {
            const ver = execFileSync('dotnet', ['--version'], {
                timeout: 4000,
                encoding: 'utf-8',
                shell: false
            }).trim();
            return {
                available: true,
                version: ver
            };
        } catch (e) {
            return {
                available: false,
                version: '',
                reason: `Failed to query dotnet version: ${e.message}`
            };
        }
    }

    /**
     * Parses output from `dotnet list package --vulnerable --include-transitive`
     * Handles text table format and checks for feed accessibility failures.
     */
    parseAuditOutput(stdout, stderr, targetFile, workspaceRoot, scanId) {
        const combined = stdout + '\n' + stderr;
        
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

        // Pattern: > PackageName   Requested   Resolved   Severity   Advisory URL
        const pkgLineRegex = />\s+([A-Za-z0-9_.-]+)\s+(\S+)\s+(\S+)\s+(Critical|High|Moderate|Low)\s+(\S+)/i;

        for (const line of lines) {
            const match = line.trim().match(pkgLineRegex);
            if (match) {
                const [, packageName, requestedVer, resolvedVer, severityStr, advisoryUrl] = match;
                
                let relPath = targetFile;
                if (path.isAbsolute(targetFile)) {
                    relPath = path.relative(workspaceRoot, targetFile);
                }

                const finding = new NormalizedFinding({
                    scanId,
                    scannerId: this.id,
                    scannerVersion: this.version,
                    ruleId: 'NU1901',
                    title: `Vulnerable Dependency: ${packageName} (${resolvedVer})`,
                    description: `Package '${packageName}' version ${resolvedVer} contains known security vulnerabilities according to NuGet audit data. Advisory: ${advisoryUrl}`,
                    severity: severityStr.toUpperCase() === 'MODERATE' ? SEVERITY_LEVELS.MEDIUM : severityStr,
                    cwe: 'CWE-1395',
                    confidence: 'High',
                    filePath: relPath.replace(/\\/g, '/'),
                    line: 1,
                    evidence: `Package: ${packageName}, Version: ${resolvedVer}, Severity: ${severityStr}, Advisory: ${advisoryUrl}`,
                    remediationGuidance: `Upgrade package reference '${packageName}' in ${path.basename(targetFile)} to a patched non-vulnerable version.`,
                    classificationType: 'CONFIRMED_RULE_VIOLATION'
                });

                findings.push(finding);
            }
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
    parseJsonAuditOutput(jsonContent, targetFile, workspaceRoot, scanId) {
        const findings = [];
        try {
            const parsed = typeof jsonContent === 'string' ? JSON.parse(jsonContent) : jsonContent;
            const projects = parsed.projects || [];
            for (const proj of projects) {
                const projPath = proj.path || targetFile;
                let relPath = projPath;
                if (path.isAbsolute(projPath)) {
                    relPath = path.relative(workspaceRoot, projPath);
                }

                const frameworks = proj.frameworks || [];
                for (const fw of frameworks) {
                    const topLevel = fw.topLevelPackages || [];
                    const transitive = fw.transitivePackages || [];
                    const allPkgs = [...topLevel, ...transitive];

                    for (const pkg of allPkgs) {
                        const vulns = pkg.vulnerabilities || [];
                        for (const vuln of vulns) {
                            const finding = new NormalizedFinding({
                                scanId,
                                scannerId: this.id,
                                scannerVersion: this.version,
                                ruleId: 'NU1901',
                                title: `Vulnerable Dependency: ${pkg.id} (${pkg.resolvedVersion})`,
                                description: `Package '${pkg.id}' contains security advisory: ${vuln.advisoryUrl || 'Known vulnerability'}`,
                                severity: vuln.severity || SEVERITY_LEVELS.HIGH,
                                cwe: 'CWE-1395',
                                confidence: 'High',
                                filePath: relPath.replace(/\\/g, '/'),
                                line: 1,
                                evidence: `Package: ${pkg.id}, Resolved: ${pkg.resolvedVersion}, Severity: ${vuln.severity}, Advisory: ${vuln.advisoryUrl}`,
                                remediationGuidance: `Upgrade package '${pkg.id}' to a secure version.`
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

        const avail = await this.isAvailable();
        if (!avail.available) {
            this.status = SCANNER_STATUS.NOT_INSTALLED;
            this.statusReason = avail.reason;
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.NOT_INSTALLED,
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [avail.reason],
                warnings: [],
                coverage: '0% (Runtime not installed)'
            };
        }

        const projectDir = targetPath || workspaceRoot;
        let projectFile = null;
        if (fs.existsSync(projectDir)) {
            if (fs.statSync(projectDir).isFile() && (projectDir.endsWith('.csproj') || projectDir.endsWith('.sln'))) {
                projectFile = projectDir;
            } else {
                try {
                    const files = fs.readdirSync(projectDir);
                    const sln = files.find(f => f.endsWith('.sln'));
                    const csproj = files.find(f => f.endsWith('.csproj'));
                    projectFile = sln ? path.join(projectDir, sln) : (csproj ? path.join(projectDir, csproj) : null);
                } catch (e) {}
            }
        }

        if (!projectFile) {
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.COMPLETED,
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [],
                warnings: ['No .NET project or solution found for dependency auditing.'],
                coverage: '0% (No project detected)'
            };
        }

        return new Promise((resolve) => {
            const cwd = path.dirname(projectFile);
            // Execute non-mutating vulnerable package list with transitive auditing
            const args = ['list', path.basename(projectFile), 'package', '--vulnerable', '--include-transitive'];
            let stdout = '';
            let stderr = '';

            try {
                const child = spawn('dotnet', args, {
                    cwd,
                    shell: false,
                    env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1' }
                });
                this.activeProcess = child;

                const timer = setTimeout(() => {
                    if (!child.killed) {
                        child.kill('SIGTERM');
                        resolve({
                            scannerId: this.id,
                            status: SCANNER_STATUS.FAILED,
                            findings: [],
                            durationMs: Date.now() - startTime,
                            errors: ['NuGet dependency audit timed out after 60000ms'],
                            warnings: [],
                            coverage: '0% (Timed out)'
                        });
                    }
                }, options.timeoutMs || 60000);

                child.stdout.on('data', d => stdout += d.toString());
                child.stderr.on('data', d => stderr += d.toString());

                child.on('close', (code) => {
                    clearTimeout(timer);
                    this.activeProcess = null;
                    const parsed = this.parseAuditOutput(stdout, stderr, projectFile, workspaceRoot, scanId);

                    if (parsed.inaccessible) {
                        resolve({
                            scannerId: this.id,
                            status: SCANNER_STATUS.FAILED,
                            findings: [],
                            durationMs: Date.now() - startTime,
                            errors: [parsed.error],
                            warnings: ['Vulnerability audit feed inaccessible; cannot guarantee zero findings.'],
                            coverage: '0% (Audit source inaccessible)'
                        });
                        return;
                    }

                    resolve({
                        scannerId: this.id,
                        status: SCANNER_STATUS.COMPLETED,
                        findings: parsed.findings,
                        durationMs: Date.now() - startTime,
                        errors: [],
                        warnings: [],
                        coverage: '100% (Direct and transitive dependencies checked)'
                    });
                });

                child.on('error', (err) => {
                    clearTimeout(timer);
                    this.activeProcess = null;
                    resolve({
                        scannerId: this.id,
                        status: SCANNER_STATUS.FAILED,
                        findings: [],
                        durationMs: Date.now() - startTime,
                        errors: [err.message],
                        warnings: [],
                        coverage: '0% (Spawn error)'
                    });
                });
            } catch (err) {
                resolve({
                    scannerId: this.id,
                    status: SCANNER_STATUS.FAILED,
                    findings: [],
                    durationMs: Date.now() - startTime,
                    errors: [err.message],
                    warnings: [],
                    coverage: '0% (Exception)'
                });
            }
        });
    }
}

module.exports = {
    NuGetAuditScanner,
    NugetAuditScanner: NuGetAuditScanner
};
