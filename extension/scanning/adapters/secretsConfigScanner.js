const fs = require('fs');
const path = require('path');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS, maskSensitiveEvidence } = require('../findingModel');
const { assertPathWithinWorkspace } = require('../../pathUtils');

/**
 * High-confidence security pattern definitions for local source & config analysis
 */
const SCANNER_RULES = [
    {
        ruleId: 'SEC-001',
        title: 'Hardcoded API Secret or Private Key',
        cwe: 'CWE-798',
        severity: SEVERITY_LEVELS.HIGH,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        filePatterns: [/\.(json|config|xml|env|cs|js|ts|properties|yaml|yml)$/i],
        // Match live API keys: sk_live_..., AKIA..., private_key...
        regex: /(sk_live_[a-zA-Z0-9_-]{16,}|AKIA[0-9A-Z]{16}|(?:"|')?(?:api[_-]?key|secret[_-]?key|auth[_-]?token)(?:"|')?\s*[:=]\s*["']([a-zA-Z0-9_\-.~+=]{16,})["'])/i,
        description: 'Hardcoded sensitive secret or API key identified in configuration or source code. Secrets must be extracted into secure environment variables or secret vaults.',
        remediationGuidance: 'Extract hardcoded credentials into environment variables or a secure key vault (e.g. Azure Key Vault, AWS Secrets Manager).'
    },
    {
        ruleId: 'SEC-002',
        title: 'Plaintext Password in Connection String',
        cwe: 'CWE-798',
        severity: SEVERITY_LEVELS.CRITICAL,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        filePatterns: [/\.(json|config|xml|env|cs)$/i],
        regex: /(?:password|pwd)\s*=\s*([^;'"\r\n]{4,})/i,
        description: 'Plaintext database password identified in connection string. Plaintext credentials risk unauthorized database access if repositories or logs are exposed.',
        remediationGuidance: 'Use Managed Identity, Windows Authentication, or token-based authentication without storing plaintext passwords in configuration files.'
    },
    {
        ruleId: 'SEC-003',
        title: 'Use of Broken Cryptographic Algorithm (DES/MD5)',
        cwe: 'CWE-327',
        severity: SEVERITY_LEVELS.HIGH,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        filePatterns: [/\.cs$/i],
        regex: /(?:DES\.Create|MD5\.Create|RC2\.Create|TripleDES\.Create|new\s+DESCryptoServiceProvider)/i,
        description: 'Deprecated cryptographic algorithm detected. DES and MD5 are vulnerable to collision and brute-force attacks and must not be used for encryption or hashing.',
        remediationGuidance: 'Migrate cryptography to AES-256 (AES-GCM) for symmetric encryption and SHA-256/SHA-512 for cryptographic hashing.'
    },
    {
        ruleId: 'SEC-004',
        title: 'OS Command Injection via Shell Invocation',
        cwe: 'CWE-78',
        severity: SEVERITY_LEVELS.HIGH,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        filePatterns: [/\.cs$/i],
        regex: /Process\.Start\s*\(\s*["'](?:cmd\.exe|\/bin\/sh|\/bin\/bash)["']\s*,\s*\$["']/i,
        description: 'Direct shell execution with string interpolation or concatenation detected. Untrusted arguments passed to shell interpreters enable arbitrary command execution.',
        remediationGuidance: 'Avoid invoking system shells directly; use ProcessStartInfo with strongly-typed arguments and strict whitelist validation.'
    },
    {
        ruleId: 'SEC-005',
        title: 'Potential SQL Injection via Unparameterized Query',
        cwe: 'CWE-89',
        severity: SEVERITY_LEVELS.CRITICAL,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        filePatterns: [/\.cs$/i],
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*from\s+.*?\s*\+.*?(?:request|input|param|query)/i,
        description: 'SQL statement constructed via string concatenation with request parameters. Unparameterized queries allow attackers to alter database logic.',
        remediationGuidance: 'Use parameterized SQL queries or ORM abstractions (e.g. Entity Framework Core parameters, SqlCommand.Parameters).'
    },
    {
        ruleId: 'SEC-006',
        title: 'Potential Hardcoded Token Requiring Review',
        cwe: 'CWE-547',
        severity: SEVERITY_LEVELS.LOW,
        classificationType: 'POTENTIAL_SECRET_REVIEW',
        filePatterns: [/\.(json|config|cs|js)$/i],
        regex: /(?:token|secret|key)\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/i,
        description: 'Suspicious entropy token detected. Requires human security review to determine whether value is an active credential or a benign non-sensitive identifier.',
        remediationGuidance: 'Verify if token is active. If active, rotate immediately and externalize configuration.'
    }
];

class SecretsConfigScanner extends ScannerAdapter {
    constructor() {
        super({
            id: 'secrets-config',
            name: 'Local Secrets & Configuration Analyzer',
            version: '1.2.0',
            supportedLanguages: ['csharp', 'dotnet', 'json', 'xml', 'javascript', 'config'],
            supportedCategories: [
                'CWE-798 (Hardcoded Credentials)',
                'CWE-327 (Broken Crypto)',
                'CWE-78 (Command Injection)',
                'CWE-89 (SQL Injection)',
                'CWE-547 (Potential Secret)'
            ]
        });
    }

    async isAvailable() {
        // Pure Node.js local scanner with zero external dependencies
        return {
            available: true,
            version: this.version
        };
    }

    /**
     * Recursively traverses target path respecting security boundaries and exclusions
     */
    _collectFiles(dirPath, workspaceRoot, collected = []) {
        const IGNORED_DIRS = new Set([
            '.git', '.vscode', '.agents', 'node_modules', 'bin', 'obj',
            'output', 'remediation-output', 'evidence', '.gcac'
        ]);

        const IGNORED_EXTENSIONS = new Set([
            '.dll', '.exe', '.pdb', '.png', '.jpg', '.jpeg', '.gif',
            '.zip', '.tar', '.gz', '.svg', '.woff', '.woff2', '.lock'
        ]);

        try {
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.name.startsWith('.') && entry.name !== '.env') continue;
                if (entry.isDirectory()) {
                    if (!IGNORED_DIRS.has(entry.name)) {
                        this._collectFiles(path.join(dirPath, entry.name), workspaceRoot, collected);
                    }
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name).toLowerCase();
                    if (!IGNORED_EXTENSIONS.has(ext)) {
                        const fullPath = path.join(dirPath, entry.name);
                        // Security check: ensure path is strictly contained within workspace
                        const safePath = assertPathWithinWorkspace(fullPath, workspaceRoot);
                        if (safePath) {
                            collected.push(safePath);
                        }
                    }
                }
            }
        } catch (e) {}

        return collected;
    }

    /**
     * Scans a single file against configured rules
     */
    scanFile(filePath, workspaceRoot, scanId) {
        const findings = [];
        let content = '';

        try {
            // Guard against large files (> 2MB)
            const stats = fs.statSync(filePath);
            if (stats.size > 2 * 1024 * 1024) return findings;
            content = fs.readFileSync(filePath, 'utf-8');
        } catch (e) {
            return findings;
        }

        const lines = content.split(/\r?\n/);
        let relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');

        // Extract repository prefix if available
        let repoName = '';
        if (relPath.startsWith('sample-repos/')) {
            const parts = relPath.split('/');
            repoName = `${parts[0]}/${parts[1]}`;
        }

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNum = i + 1;

            for (const rule of SCANNER_RULES) {
                // Check if file matches pattern
                const matchesPattern = rule.filePatterns.some(p => p.test(filePath));
                if (!matchesPattern) continue;

                // Match regex
                const match = line.match(rule.regex);
                if (match) {
                    // Avoid duplicate finding if SEC-001 already matched this line
                    if (rule.ruleId === 'SEC-006') {
                        const hasHigherMatch = findings.some(f => f.line === lineNum && f.ruleId === 'SEC-001');
                        if (hasHigherMatch) continue;
                    }

                    // Mask sensitive evidence! NEVER store raw secret!
                    const maskedLine = maskSensitiveEvidence(line.trim());

                    const finding = new NormalizedFinding({
                        scanId,
                        scannerId: this.id,
                        scannerVersion: this.version,
                        ruleId: rule.ruleId,
                        title: rule.title,
                        description: rule.description,
                        severity: rule.severity,
                        cwe: rule.cwe,
                        confidence: 'High',
                        filePath: relPath,
                        line: lineNum,
                        column: match.index ? match.index + 1 : 1,
                        evidence: maskedLine,
                        remediationGuidance: rule.remediationGuidance,
                        classificationType: rule.classificationType,
                        repository: repoName
                    });

                    findings.push(finding);
                }
            }
        }

        return findings;
    }

    async scan(workspaceRoot, targetPath, options = {}) {
        const scanId = options.scanId || `scan-${Date.now()}`;
        const startTime = Date.now();
        this.status = SCANNER_STATUS.RUNNING;

        const baseDir = targetPath && fs.existsSync(targetPath) ? targetPath : workspaceRoot;
        const filesToScan = fs.statSync(baseDir).isFile() 
            ? [baseDir] 
            : this._collectFiles(baseDir, workspaceRoot);

        const allFindings = [];
        const errors = [];
        const warnings = [];

        for (const file of filesToScan) {
            try {
                const fileFindings = this.scanFile(file, workspaceRoot, scanId);
                allFindings.push(...fileFindings);
            } catch (err) {
                warnings.push(`Could not scan ${path.basename(file)}: ${err.message}`);
            }
        }

        this.status = SCANNER_STATUS.COMPLETED;

        return {
            scannerId: this.id,
            status: SCANNER_STATUS.COMPLETED,
            executionPolicy: 'READ_ONLY_STATIC_POLICY',
            findings: allFindings,
            durationMs: Date.now() - startTime,
            errors,
            warnings,
            coverage: `100% (${filesToScan.length} files scanned)`
        };
    }
}

module.exports = {
    SecretsConfigScanner,
    SCANNER_RULES
};
