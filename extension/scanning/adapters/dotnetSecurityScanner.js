const { spawn, execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');
const { isExecutableAvailable } = require('../../testRunner');

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
     * Parses standard Roslyn compiler diagnostic output lines into NormalizedFinding records
     * Format: File.cs(line,col): warning CA5350: Message [Project.csproj]
     */
    parseRoslynDiagnostics(output, workspaceRoot, scanId) {
        const findings = [];
        const lines = output.split('\n');
        const diagRegex = /^(.*?)\((\d+),(\d+)\):\s*(warning|error)\s+([A-Z0-9]+):\s*(.*?)(?:\s+\[.*?\])?$/;

        for (const line of lines) {
            const match = line.trim().match(diagRegex);
            if (!match) continue;

            const [, rawFilePath, lineStr, colStr, severityType, ruleId, message] = match;
            
            // Only process genuine security rules
            const knownRule = ROSLYN_SECURITY_RULES[ruleId];
            if (!knownRule && !ruleId.startsWith('CA5') && !ruleId.startsWith('CA3')) {
                continue; // Do not claim general compiler warnings are security vulnerabilities
            }

            const lineNum = parseInt(lineStr, 10);
            const colNum = parseInt(colStr, 10);
            
            let relPath = rawFilePath;
            if (path.isAbsolute(rawFilePath)) {
                relPath = path.relative(workspaceRoot, rawFilePath);
            }

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
                filePath: relPath.replace(/\\/g, '/'),
                line: lineNum,
                column: colNum,
                evidence: line.trim(),
                remediationGuidance: knownRule ? `Follow remediation guidance for ${knownRule.cwe} and rule ${ruleId}.` : 'Address security diagnostic.'
            });

            findings.push(finding);
        }

        return findings;
    }

    /**
     * Parses SARIF 2.1.0 JSON output if generated by dotnet build /p:ErrorLog=...
     */
    parseSarif(sarifContent, workspaceRoot, scanId) {
        const findings = [];
        try {
            const sarif = typeof sarifContent === 'string' ? JSON.parse(sarifContent) : sarifContent;
            const runs = sarif.runs || [];
            for (const run of runs) {
                const results = run.results || [];
                for (const res of results) {
                    const ruleId = res.ruleId || 'SECURITY-RULE';
                    const known = ROSLYN_SECURITY_RULES[ruleId];
                    if (!known && !ruleId.startsWith('CA5') && !ruleId.startsWith('CA3')) continue;

                    const loc = (res.locations && res.locations[0]?.physicalLocation) || {};
                    const uri = loc.artifactLocation?.uri || '';
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
                        filePath: uri.replace(/\\/g, '/'),
                        line: region.startLine || 1,
                        column: region.startColumn || 1,
                        evidence: res.message?.text || '',
                        remediationGuidance: known ? `Follow remediation guidance for ${known.cwe}.` : ''
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
        // Locate .sln or .csproj
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
                warnings: ['No .NET solution (.sln) or project (.csproj) found in target path.'],
                coverage: '0% (No project detected)'
            };
        }

        return new Promise((resolve) => {
            const cwd = path.dirname(projectFile);
            const args = ['build', path.basename(projectFile), '--nologo', '/p:EnableNETAnalyzers=true', '/p:AnalysisLevel=latest'];
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
                            errors: ['Execution timed out after 60000ms'],
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
                    const findings = this.parseRoslynDiagnostics(stdout + '\n' + stderr, workspaceRoot, scanId);

                    resolve({
                        scannerId: this.id,
                        status: SCANNER_STATUS.COMPLETED,
                        findings,
                        durationMs: Date.now() - startTime,
                        errors: [],
                        warnings: code !== 0 ? [`Build completed with compilation diagnostics (exit code ${code})`] : [],
                        coverage: code === 0 ? '100% (Analyzers active)' : 'Coverage active (Diagnostics encountered)'
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
                        coverage: '0% (Process spawn error)'
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
    DotnetSecurityScanner,
    ROSLYN_SECURITY_RULES
};
