const fs = require('fs');
const path = require('path');
const { ScannerAdapter } = require('../scannerAdapter');
const {
    NormalizedFinding,
    SCANNER_STATUS,
    SEVERITY_LEVELS,
    maskSensitiveEvidence,
    inferTechnologyFromFilePath
} = require('../findingModel');
const { assertPathWithinAuthorizedRoots, canonicalizePath } = require('../../repositoryContext');

const PLACEHOLDER_VALUE_REGEX = /(?:^|["'])(?:\$\{[^}]+\}|@Microsoft\.KeyVault|Environment\.GetEnvironmentVariable|process\.env\.|<[^>]+>|REDACTED|PLACEHOLDER|EXAMPLE|YOUR[_-]|CHANGE[_-]?ME|DUMMY|SAMPLE)/i;

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
        detectionMethod: 'DETERMINISTIC_REGEX',
        confidence: 'High',
        filePatterns: [/\.(json|config|xml|env|cs|js|ts|properties|yaml|yml)$/i],
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
        detectionMethod: 'DETERMINISTIC_REGEX',
        confidence: 'High',
        filePatterns: [/\.(json|config|xml|env|cs)$/i],
        regex: /(?:Server|Data Source|Host|Initial Catalog|Database|User Id|Uid)[^;\r\n]*;(?:[^;\r\n]*;)*\s*(?:password|pwd)\s*=\s*([^;'"\r\n$\s]{4,})/i,
        description: 'Plaintext database password identified in connection string. Plaintext credentials risk unauthorized database access if repositories or logs are exposed.',
        remediationGuidance: 'Use Managed Identity, Windows Authentication, or token-based authentication without storing plaintext passwords in configuration files.'
    },
    {
        ruleId: 'SEC-003',
        title: 'Use of Broken Cryptographic Algorithm (DES/MD5)',
        cwe: 'CWE-327',
        severity: SEVERITY_LEVELS.HIGH,
        classificationType: 'CONFIRMED_RULE_VIOLATION',
        detectionMethod: 'DETERMINISTIC_REGEX',
        confidence: 'High',
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
        detectionMethod: 'DETERMINISTIC_REGEX',
        confidence: 'High',
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
        detectionMethod: 'DETERMINISTIC_REGEX',
        confidence: 'High',
        filePatterns: [/\.cs$/i],
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*from\s+.*?\s*\+.*?(?:request|input|param|query)/i,
        description: 'SQL statement constructed via string concatenation with request parameters. Unparameterized queries allow attackers to alter database logic.',
        remediationGuidance: 'Use parameterized SQL queries or ORM abstractions (e.g. Entity Framework Core parameters, SqlCommand.Parameters).'
    },
    {
        ruleId: 'SEC-006',
        title: 'Potential Hardcoded Token Requiring Review (Heuristic)',
        cwe: 'CWE-547',
        severity: SEVERITY_LEVELS.LOW,
        classificationType: 'POTENTIAL_SECRET_REVIEW',
        detectionMethod: 'HEURISTIC_PATTERN',
        confidence: 'Low',
        filePatterns: [/\.(json|config|cs|js)$/i],
        regex: /(?:token|secret|key)\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/i,
        description: 'Heuristic detection: high-length token literal matched pattern. Exploitability and credential status are unconfirmed; human security review is required.',
        remediationGuidance: 'Verify if token is active. If active, rotate immediately and externalize configuration.'
    }
];

function isCommentLine(trimmedLine) {
    return trimmedLine.startsWith('//') ||
        trimmedLine.startsWith('#') ||
        trimmedLine.startsWith('/*') ||
        trimmedLine.startsWith('*');
}

class SecretsConfigScanner extends ScannerAdapter {
    constructor() {
        super({
            id: 'secrets-config',
            name: 'Local Secrets & Configuration Analyzer',
            version: '1.3.0',
            supportedLanguages: ['csharp', 'dotnet', 'java', 'json', 'xml', 'javascript', 'config'],
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
        return {
            available: true,
            version: this.version
        };
    }

    /**
     * Recursively traverses target path respecting security boundaries and exclusions
     */
    _collectFiles(dirPath, allowedRoots, collected = []) {
        const IGNORED_DIRS = new Set([
            '.git', '.vscode', '.agents', '.github', 'node_modules', 'bin', 'obj',
            'output', 'remediation-output', 'evidence', '.gcac', 'workspaces', 'TestResults', 'target'
        ]);

        const IGNORED_EXTENSIONS = new Set([
            '.dll', '.exe', '.pdb', '.png', '.jpg', '.jpeg', '.gif',
            '.zip', '.tar', '.gz', '.svg', '.woff', '.woff2', '.lock',
            '.md', '.txt', '.db', '.db-wal', '.db-shm', '.xlsx', '.xls', '.csv', '.pfx', '.pem', '.key', '.p12'
        ]);

        try {
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.isSymbolicLink()) continue;
                if (entry.name.startsWith('.') && entry.name !== '.env') continue;
                if (entry.isDirectory()) {
                    if (!IGNORED_DIRS.has(entry.name)) {
                        this._collectFiles(path.join(dirPath, entry.name), allowedRoots, collected);
                    }
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name).toLowerCase();
                    if (!IGNORED_EXTENSIONS.has(ext) && entry.name !== 'packages.lock.json' && entry.name !== 'package-lock.json') {
                        const fullPath = path.join(dirPath, entry.name);
                        const safeMatch = assertPathWithinAuthorizedRoots(fullPath, allowedRoots);
                        if (safeMatch) {
                            collected.push(safeMatch.canonicalPath);
                        }
                    }
                }
            }
        } catch (e) {}

        return collected;
    }

    /**
     * Scans a single file against configured rules.
     * Skips empty/whitespace-only files cleanly without producing findings.
     */
    scanFile(filePath, workspaceRoot, scanId, meta = {}) {
        const result = this._scanFileDetailed(filePath, workspaceRoot, scanId, meta);
        return result.findings;
    }

    _scanFileDetailed(filePath, workspaceRoot, scanId, meta = {}) {
        const findings = [];
        let content = '';

        try {
            const stats = fs.statSync(filePath);
            if (!stats.isFile() || stats.size === 0) {
                return { findings, skippedEmpty: true };
            }
            if (stats.size > 2 * 1024 * 1024) {
                return { findings, skippedEmpty: false };
            }
            content = fs.readFileSync(filePath, 'utf-8');
        } catch (e) {
            return { findings, skippedEmpty: false };
        }

        if (!content || !content.trim()) {
            return { findings, skippedEmpty: true };
        }

        const effectiveRoot = meta.repositoryRoot || workspaceRoot;
        const lines = content.split(/\r?\n/);
        let relPath = effectiveRoot
            ? path.relative(effectiveRoot, filePath).replace(/\\/g, '/')
            : path.basename(filePath);
        if (relPath.startsWith('..') && workspaceRoot) {
            relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');
        }

        // Extract repository provenance (never drop external repo metadata!)
        let repoName = meta.repository || '';
        if (!repoName) {
            const wsRel = workspaceRoot ? path.relative(workspaceRoot, filePath).replace(/\\/g, '/') : '';
            if (wsRel.startsWith('sample-repos/')) {
                const parts = wsRel.split('/');
                repoName = `${parts[0]}/${parts[1]}`;
            } else if (effectiveRoot) {
                repoName = canonicalizePath(effectiveRoot);
            }
        }

        const tech = inferTechnologyFromFilePath(filePath, meta.technology || '');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();
            if (!trimmed || isCommentLine(trimmed)) continue;
            const lineNum = i + 1;

            for (const rule of SCANNER_RULES) {
                const matchesPattern = rule.filePatterns.some(p => p.test(filePath));
                if (!matchesPattern) continue;

                const match = line.match(rule.regex);
                if (!match) continue;

                const capturedSecret = match[1] || '';
                if (capturedSecret && PLACEHOLDER_VALUE_REGEX.test(capturedSecret)) {
                    continue;
                }
                if (rule.ruleId === 'SEC-006' && PLACEHOLDER_VALUE_REGEX.test(trimmed)) {
                    continue;
                }

                // Avoid duplicate heuristic SEC-006 if higher-confidence SEC-001 already matched this line
                if (rule.ruleId === 'SEC-006') {
                    const hasHigherMatch = findings.some(f => f.line === lineNum && f.ruleId === 'SEC-001');
                    if (hasHigherMatch) continue;
                }

                const maskedLine = maskSensitiveEvidence(trimmed);

                const finding = new NormalizedFinding({
                    scanId,
                    scannerId: this.id,
                    scannerVersion: this.version,
                    ruleId: rule.ruleId,
                    title: rule.title,
                    description: rule.description,
                    severity: rule.severity,
                    cwe: rule.cwe,
                    confidence: rule.confidence || 'High',
                    detectionMethod: rule.detectionMethod || 'DETERMINISTIC_REGEX',
                    filePath: relPath,
                    line: lineNum,
                    column: match.index ? match.index + 1 : 1,
                    evidence: maskedLine,
                    evidenceRef: `${relPath}:${lineNum}`,
                    remediationGuidance: rule.remediationGuidance,
                    classificationType: rule.classificationType,
                    repository: repoName,
                    repositoryRoot: meta.repositoryRoot || '',
                    canonicalRepositoryId: meta.canonicalRepositoryId || '',
                    applicationNumber: meta.applicationNumber || '',
                    applicationName: meta.applicationName || '',
                    applicationIdentitySource: meta.applicationIdentitySource || '',
                    technology: tech
                });

                findings.push(finding);
            }
        }

        return { findings, skippedEmpty: false };
    }

    async scan(workspaceRoot, targetPath, options = {}) {
        const scanId = options.scanId || `scan-${Date.now()}`;
        const startTime = Date.now();
        this.status = SCANNER_STATUS.RUNNING;

        const baseDir = targetPath || workspaceRoot;
        if (!baseDir || !fs.existsSync(baseDir)) {
            this.status = SCANNER_STATUS.FAILED;
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.FAILED,
                executionPolicy: 'READ_ONLY_STATIC_POLICY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors: [`Target path does not exist: '${baseDir}'.`],
                warnings: [],
                coverage: '0% (Target path missing)'
            };
        }

        const repoContext = options.repoContext || {};
        const allowedRoots = Array.from(new Set([
            canonicalizePath(workspaceRoot),
            canonicalizePath(repoContext.repositoryRoot),
            canonicalizePath(baseDir),
            ...(Array.isArray(options.authorizedRoots) ? options.authorizedRoots.map(r => canonicalizePath(r)) : [])
        ].filter(Boolean)));

        const stat = fs.statSync(baseDir);
        const filesToScan = stat.isFile()
            ? [canonicalizePath(baseDir)]
            : this._collectFiles(canonicalizePath(baseDir), allowedRoots);

        const allFindings = [];
        const errors = [];
        const warnings = [];
        let nonEmptyScanned = 0;
        let emptySkipped = 0;

        const meta = {
            repository: repoContext.repository || '',
            repositoryRoot: repoContext.repositoryRoot || (stat.isDirectory() ? canonicalizePath(baseDir) : ''),
            canonicalRepositoryId: repoContext.canonicalRepositoryId || '',
            applicationNumber: repoContext.applicationNumber || options.applicationId || '',
            applicationName: repoContext.applicationName || '',
            applicationIdentitySource: repoContext.applicationIdentitySource || '',
            technology: repoContext.detectedTechnology || ''
        };

        for (const file of filesToScan) {
            try {
                const { findings: fileFindings, skippedEmpty } = this._scanFileDetailed(file, workspaceRoot, scanId, meta);
                if (skippedEmpty) {
                    emptySkipped++;
                } else {
                    nonEmptyScanned++;
                    allFindings.push(...fileFindings);
                }
            } catch (err) {
                warnings.push(`Could not scan ${path.basename(file)}: ${err.message}`);
            }
        }

        if (nonEmptyScanned === 0) {
            this.status = SCANNER_STATUS.COMPLETED;
            return {
                scannerId: this.id,
                status: SCANNER_STATUS.NO_SCANNABLE_INPUTS,
                noScannableInputs: true,
                executionPolicy: 'READ_ONLY_STATIC_POLICY',
                findings: [],
                durationMs: Date.now() - startTime,
                errors,
                warnings: [
                    emptySkipped > 0
                        ? `All ${emptySkipped} candidate file(s) were empty or whitespace-only.`
                        : 'No scannable non-empty source or configuration files found in target.'
                ],
                coverage: '0% (No non-empty scannable inputs)'
            };
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
            coverage: `100% (${nonEmptyScanned} non-empty file(s) scanned${emptySkipped > 0 ? `, ${emptySkipped} empty skipped` : ''})`
        };
    }
}

module.exports = {
    SecretsConfigScanner,
    SCANNER_RULES
};
