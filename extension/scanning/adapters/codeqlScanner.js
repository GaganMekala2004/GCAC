'use strict';

const { spawn, execFileSync } = require('child_process');
const path = require('path');
const fs   = require('fs');
const os   = require('os');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS } = require('../findingModel');

/**
 * GitHub CodeQL CLI Scanner Adapter
 * ─────────────────────────────────────────────────────────────────────────────
 * Integrates the official GitHub CodeQL CLI for semantic static analysis.
 *
 * Binary discovery order (first match wins):
 *   1. CODEQL_PATH environment variable
 *   2. <workspace>/tools/codeql/codeql[.exe]  (local install via setup-codeql.js)
 *   3. System PATH  (where/which codeql)
 *
 * When CodeQL is NOT installed this adapter:
 *   - Returns NOT_INSTALLED status (non-blocking; other scanners continue)
 *   - Reports its availability status with actionable install guidance
 *   - Does NOT generate any synthetic/fake findings
 *
 * When CodeQL IS installed this adapter:
 *   1. Detects target source language (C#, Java, JS/TS, Python)
 *   2. Creates a temporary CodeQL database  (codeql database create)
 *   3. Runs the language-specific code scanning query suite
 *   4. Outputs SARIF 2.1.0  (codeql database analyze)
 *   5. Parses SARIF → NormalizedFinding[] and feeds results to FindingsStore
 *   6. NormalizedFindings link directly into the 7-stage remediation pipeline
 *
 * All database and SARIF artifacts are created in OS temp and cleaned up after
 * each scan session.  No data is uploaded externally.
 */
class CodeQLScanner extends ScannerAdapter {
    constructor(options = {}) {
        super({
            id: 'codeql',
            name: 'GitHub CodeQL (Semantic SAST)',
            version: '2.20.0',
            description: 'Semantic static analysis via the official GitHub CodeQL CLI. Detects SQL Injection, XSS, Path Traversal, Command Injection, and hardcoded credentials using data-flow queries.',
            supportedLanguages: ['csharp', 'java', 'javascript', 'typescript', 'python', 'cpp', 'go'],
            supportedCategories: [
                'CWE-89 (SQL Injection)',
                'CWE-79 (Cross-Site Scripting)',
                'CWE-22 (Path Traversal)',
                'CWE-78 (Command Injection)',
                'CWE-798 (Hardcoded Credentials)',
                'CWE-327 (Broken Crypto)',
                'CWE-611 (XXE Injection)',
                'CWE-918 (Server-Side Request Forgery)'
            ],
            rulesCount: 200
        });

        // Workspace root – set by ScanController on scan(); may also be injected
        this._workspaceRoot = options.workspaceRoot || null;
        this._resolvedBinary = null;  // cached after first isAvailable()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Binary Discovery
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Resolves the CodeQL CLI binary path using a multi-location search:
     *   1. CODEQL_PATH env var
     *   2. Local tools/codeql/ directory (managed by setup-codeql.js)
     *   3. System PATH
     *
     * @returns {string|null} Absolute path to codeql binary, or null if not found
     */
    _findCodeqlBinary(workspaceRoot) {
        const exeName = process.platform === 'win32' ? 'codeql.exe' : 'codeql';

        // 1. Environment variable override
        const envPath = process.env.CODEQL_PATH;
        if (envPath && fs.existsSync(envPath)) {
            return envPath;
        }

        // 2. Local workspace tools directory (setup-codeql.js target)
        const root = workspaceRoot || this._workspaceRoot;
        if (root) {
            const localBin = path.join(root, 'tools', 'codeql', exeName);
            if (fs.existsSync(localBin)) {
                return localBin;
            }
            // Also try tools/codeql/codeql/codeql.exe (nested extraction)
            const nestedBin = path.join(root, 'tools', 'codeql', 'codeql', exeName);
            if (fs.existsSync(nestedBin)) {
                return nestedBin;
            }
        }

        // 3. Common OS-level install locations
        const candidates = process.platform === 'win32'
            ? [
                path.join(process.env.LOCALAPPDATA || '', 'Programs', 'CodeQL', exeName),
                'C:\\tools\\codeql\\codeql.exe',
                'C:\\Program Files\\CodeQL\\codeql.exe'
              ]
            : [
                '/usr/local/bin/codeql',
                '/usr/bin/codeql',
                path.join(os.homedir(), '.local', 'bin', 'codeql')
              ];

        for (const c of candidates) {
            if (fs.existsSync(c)) return c;
        }

        // 4. System PATH
        try {
            const lookupTool = process.platform === 'win32' ? 'where' : 'which';
            const found = execFileSync(lookupTool, [exeName], {
                stdio: 'pipe',
                timeout: 3000,
                encoding: 'utf-8',
                shell: false
            }).trim().split(/\r?\n/)[0].trim();
            if (found && fs.existsSync(found)) return found;
        } catch { /* not on PATH */ }

        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Availability Check  (called by ScanController.getAvailableScanners)
    // ─────────────────────────────────────────────────────────────────────────

    async isAvailable(workspaceRoot) {
        const root = workspaceRoot || this._workspaceRoot;
        const bin = this._findCodeqlBinary(root);

        if (!bin) {
            this.status = SCANNER_STATUS.NOT_INSTALLED;
            return {
                available: false,
                version: '',
                binaryPath: null,
                reason: [
                    'CodeQL CLI not found. Install it via one of the following methods:',
                    '  • Run: node scripts/setup-codeql.js  (auto-installs to tools/codeql/)',
                    '  • Download manually from https://github.com/github/codeql-action/releases',
                    '    and extract to <workspace>/tools/codeql/',
                    '  • Set the CODEQL_PATH environment variable to the codeql executable',
                    'CodeQL scanning is optional and does not block other scanner adapters.'
                ].join('\n')
            };
        }

        try {
            if (typeof bin !== 'string' || bin.includes('\0')) {
                throw new Error('Invalid CodeQL executable path');
            }
            const ver = execFileSync(bin, ['version', '--format=json'], {
                timeout: 8000,
                encoding: 'utf-8',
                stdio: ['ignore', 'pipe', 'ignore'],
                shell: false
            }).trim();
            const parsed = JSON.parse(ver);
            this.status = SCANNER_STATUS.READY;
            this._resolvedBinary = bin;
            return {
                available: true,
                version: parsed.version || 'unknown',
                binaryPath: bin,
                reason: ''
            };
        } catch (e) {
            this.status = SCANNER_STATUS.NOT_INSTALLED;
            return {
                available: false,
                version: '',
                binaryPath: bin,
                reason: `CodeQL binary found at ${bin} but failed to execute: ${e.message}`
            };
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Language Detection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Scans target directory for language indicators and returns CodeQL
     * language + query suite + build flags for that language.
     *
     * @param {string} targetDir
     * @returns {{ language: string, suite: string, buildMode: string }}
     */
    _detectLanguage(targetDir) {
        let hasCs = false, hasCsproj = false, hasJava = false, hasJs = false, hasPy = false, hasCpp = false, hasGo = false;
        try {
            // BFS-style check (avoid deep recursion on large repos)
            const scanDir = (dir, depth = 0) => {
                if (depth > 4) return;
                let entries;
                try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
                for (const e of entries) {
                    if (e.name.startsWith('.') || e.name === 'node_modules' || e.name === 'bin' || e.name === 'obj') continue;
                    const f = e.name.toLowerCase();
                    if (e.isDirectory()) { scanDir(path.join(dir, e.name), depth + 1); continue; }
                    if (f.endsWith('.cs'))       hasCs     = true;
                    if (f.endsWith('.csproj') || f.endsWith('.sln')) hasCsproj = true;
                    if (f.endsWith('.java') || f.endsWith('pom.xml')) hasJava   = true;
                    if (f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.jsx') || f.endsWith('.tsx')) hasJs = true;
                    if (f.endsWith('.py'))       hasPy     = true;
                    if (f.endsWith('.cpp') || f.endsWith('.c') || f.endsWith('.h')) hasCpp = true;
                    if (f === 'go.mod')          hasGo     = true;
                }
            };
            scanDir(targetDir);
        } catch {}

        // Priority order: C# > Java > JS/TS > Python > C++ > Go
        if (hasCs || hasCsproj) return {
            language:  'csharp',
            suite:     'codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasJava) return {
            language:  'java',
            suite:     'codeql/java-queries:codeql-suites/java-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasJs) return {
            language:  'javascript',
            suite:     'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
            buildMode: ''
        };
        if (hasPy) return {
            language:  'python',
            suite:     'codeql/python-queries:codeql-suites/python-code-scanning.qls',
            buildMode: ''
        };
        if (hasCpp) return {
            language:  'cpp',
            suite:     'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasGo) return {
            language:  'go',
            suite:     'codeql/go-queries:codeql-suites/go-code-scanning.qls',
            buildMode: ''
        };

        // Default to C# (most common in this project)
        return {
            language:  'csharp',
            suite:     'codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SARIF 2.1.0 Parser
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Parses a CodeQL SARIF 2.1.0 report and converts each result into a
     * NormalizedFinding that flows into the remediation pipeline.
     *
     * @param {object|string} sarifContent  - Raw SARIF JSON or parsed object
     * @param {string} workspaceRoot        - Workspace root for relative path calculation
     * @param {string} scanId               - Parent scan session ID
     * @returns {NormalizedFinding[]}
     */
    parseSarif(sarifContent, workspaceRoot, scanId) {
        const findings = [];
        try {
            const sarif = typeof sarifContent === 'string' ? JSON.parse(sarifContent) : sarifContent;

            for (const run of (sarif.runs || [])) {
                const driver = run.tool?.driver || {};
                const driverVersion = driver.semanticVersion || driver.version || this.version;

                // Build rule-ID → rule definition index
                const rulesMap = {};
                for (const r of (driver.rules || [])) {
                    rulesMap[r.id] = r;
                }

                for (const res of (run.results || [])) {
                    const ruleId  = res.ruleId || res.rule?.id || 'CODEQL-UNKNOWN';
                    const ruleDef = rulesMap[ruleId] || {};
                    const loc     = res.locations && res.locations[0]?.physicalLocation;
                    const uri     = loc?.artifactLocation?.uri || '';
                    const region  = loc?.region || {};

                    // ── CWE extraction ──────────────────────────────────────
                    let cwe = null;
                    const tags = ruleDef.properties?.tags || res.properties?.tags || [];
                    for (const tag of tags) {
                        const m = String(tag).match(/external\/cwe\/(cwe-\d+)/i);
                        if (m) { cwe = m[1].toUpperCase(); break; }
                    }

                    // ── Severity mapping ────────────────────────────────────
                    // CodeQL levels: error → High, warning → Medium, note → Low
                    // 'error' for critical security findings often maps to HIGH;
                    // we bump to CRITICAL when CWE is explicitly critical category
                    const CRITICAL_CWES = new Set(['CWE-89', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-798']);
                    let sev = SEVERITY_LEVELS.MEDIUM;
                    if (res.level === 'error') {
                        sev = (cwe && CRITICAL_CWES.has(cwe)) ? SEVERITY_LEVELS.CRITICAL : SEVERITY_LEVELS.HIGH;
                    } else if (res.level === 'warning') {
                        sev = SEVERITY_LEVELS.MEDIUM;
                    } else if (res.level === 'note' || res.level === 'open') {
                        sev = SEVERITY_LEVELS.LOW;
                    }

                    // ── File path normalization ─────────────────────────────
                    let normalizedPath = uri.replace(/\\/g, '/');
                    if (normalizedPath.startsWith('file:///')) {
                        normalizedPath = normalizedPath.substring(8);          // strip file:///
                    } else if (normalizedPath.startsWith('file://')) {
                        normalizedPath = normalizedPath.substring(7);          // strip file://
                    }
                    // Windows path fix: file:///C:/... → C:/...
                    if (/^[a-zA-Z]:\//.test(normalizedPath) && workspaceRoot) {
                        try {
                            normalizedPath = path.relative(workspaceRoot, normalizedPath).replace(/\\/g, '/');
                        } catch {}
                    } else if (path.isAbsolute(normalizedPath) && workspaceRoot) {
                        normalizedPath = path.relative(workspaceRoot, normalizedPath).replace(/\\/g, '/');
                    }

                    // ── Remediation guidance ────────────────────────────────
                    const remGuidance = ruleDef.help?.text
                        || ruleDef.help?.markdown
                        || `Fix ${ruleId}: ${ruleDef.shortDescription?.text || 'Address the identified vulnerability'}. See ${ruleDef.helpUri || 'https://codeql.github.com/codeql-query-help/'} for detailed remediation guidance.`;

                    // ── Related locations (data-flow paths) ─────────────────
                    let evidence = res.message?.text || '';
                    if (res.relatedLocations && res.relatedLocations.length > 0) {
                        const steps = res.relatedLocations
                            .slice(0, 3)
                            .map(rl => rl.message?.text || '')
                            .filter(Boolean);
                        if (steps.length) evidence += ` [Flow: ${steps.join(' → ')}]`;
                    }

                    const finding = new NormalizedFinding({
                        scanId,
                        scannerId:        this.id,
                        scannerVersion:   driverVersion,
                        ruleId,
                        title:            ruleDef.shortDescription?.text || ruleId,
                        description:      res.message?.text || ruleDef.fullDescription?.text || '',
                        severity:         sev,
                        cwe,
                        confidence:       res.level === 'error' ? 'High' : 'Medium',
                        filePath:         normalizedPath,
                        line:             region.startLine  || 1,
                        column:           region.startColumn || 1,
                        evidence,
                        remediationGuidance: remGuidance,
                        sourceClassification: 'LocalScanner',
                        classificationType:   'CONFIRMED_RULE_VIOLATION'
                    });

                    findings.push(finding);
                }
            }
        } catch (e) {
            // Parsing failure is non-fatal — return whatever was collected
        }

        return findings;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Main Scan Entry Point
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Executes a full CodeQL scan against the target path:
     *   1. Checks binary availability
     *   2. Detects source language
     *   3. Creates a CodeQL database (codeql database create)
     *   4. Runs query analysis  (codeql database analyze)
     *   5. Parses SARIF output → NormalizedFinding[]
     *   6. Cleans up temp artefacts
     *
     * @param {string} workspaceRoot  - Workspace boundary (for path containment)
     * @param {string} targetPath     - Directory to scan
     * @param {object} options
     * @param {string} [options.scanId]
     * @param {number} [options.timeoutMs=300000]  - Per-command timeout (default 5 min)
     * @returns {Promise<{scannerId, status, findings, durationMs, errors, warnings, coverage}>}
     */
    async scan(workspaceRoot, targetPath, options = {}) {
        const scanId    = options.scanId || `codeql-${Date.now()}`;
        const startTime = Date.now();
        this._workspaceRoot = workspaceRoot;

        // ── 1. Binary availability ──────────────────────────────────────────
        const avail = await this.isAvailable(workspaceRoot);
        if (!avail.available) {
            this.status = SCANNER_STATUS.NOT_INSTALLED;
            this.statusReason = avail.reason;
            return {
                scannerId:  this.id,
                status:     SCANNER_STATUS.NOT_INSTALLED,
                executionPolicy: 'READ_ONLY_STATIC_POLICY',
                findings:   [],
                durationMs: Date.now() - startTime,
                errors:     [],
                warnings:   [
                    'GitHub CodeQL CLI is not installed. CodeQL semantic analysis is skipped.',
                    'To enable: run  node scripts/setup-codeql.js  or set the CODEQL_PATH environment variable.',
                    avail.reason
                ],
                coverage:   '0% (CodeQL CLI not installed — optional scanner)',
                binaryPath: null
            };
        }

        const codeqlBin  = avail.binaryPath || this._resolvedBinary;
        const scanTarget = targetPath || workspaceRoot;
        const timeoutMs  = options.timeoutMs || 300000;   // 5 minutes

        // ── 2. Language detection ───────────────────────────────────────────
        const { language, suite, buildMode } = this._detectLanguage(scanTarget);

        // ── 3. Temp paths ───────────────────────────────────────────────────
        const stamp       = Date.now();
        const tempDbDir   = path.join(os.tmpdir(), `gcac-codeql-db-${stamp}`);
        const sarifOutput = path.join(os.tmpdir(), `gcac-codeql-${stamp}.sarif`);

        this.status = SCANNER_STATUS.RUNNING;

        try {
            // ── 4. Create CodeQL database ───────────────────────────────────
            const createArgs = [
                'database', 'create',
                tempDbDir,
                `--language=${language}`,
                `--source-root=${scanTarget}`,
                '--overwrite',
                '--no-run-unnecessary-builds'
            ];
            if (buildMode) createArgs.push(buildMode);

            this._execCodeql(codeqlBin, createArgs, { timeout: timeoutMs });

            // ── 5. Analyze database ─────────────────────────────────────────
            const analyzeArgs = [
                'database', 'analyze',
                tempDbDir,
                suite,
                '--format=sarif-latest',
                `--output=${sarifOutput}`,
                '--no-print-metrics-summary'
            ];

            this._execCodeql(codeqlBin, analyzeArgs, { timeout: timeoutMs });

            // ── 6. Parse SARIF ──────────────────────────────────────────────
            if (!fs.existsSync(sarifOutput)) {
                return this._buildResult(SCANNER_STATUS.COMPLETED, [], startTime, [], ['CodeQL analysis completed but produced no SARIF output.'], `0% (${language} — no findings output)`);
            }

            const sarifRaw = fs.readFileSync(sarifOutput, 'utf-8');
            const findings = this.parseSarif(sarifRaw, workspaceRoot, scanId);

            this.status = SCANNER_STATUS.COMPLETED;
            return this._buildResult(
                SCANNER_STATUS.COMPLETED,
                findings,
                startTime,
                [],
                [],
                `100% (CodeQL ${language} semantic analysis — ${findings.length} finding(s))`
            );

        } catch (err) {
            this.status = SCANNER_STATUS.FAILED;
            // Distinguish timeout vs other errors
            const isTimeout = err.message && (err.message.includes('ETIMEDOUT') || err.message.includes('timed out') || err.message.includes('timeout'));
            const errorMsg  = isTimeout
                ? `CodeQL analysis timed out after ${Math.round(timeoutMs / 1000)}s. Consider increasing timeoutMs or scanning a smaller target.`
                : `CodeQL execution error: ${err.message}`;

            return this._buildResult(SCANNER_STATUS.FAILED, [], startTime, [errorMsg], [], '0% (Execution failure)');

        } finally {
            // ── 7. Cleanup temp artifacts ───────────────────────────────────
            try { if (fs.existsSync(tempDbDir))   fs.rmSync(tempDbDir,   { recursive: true, force: true }); } catch {}
            try { if (fs.existsSync(sarifOutput)) fs.unlinkSync(sarifOutput); } catch {}
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Executes the CodeQL CLI with given arguments synchronously.
     * Throws on non-zero exit code or timeout.
     */
    _execCodeql(bin, args, opts = {}) {
        if (typeof bin !== 'string' || !bin.trim() || bin.includes('\0')) {
            throw new Error('Invalid CodeQL executable path.');
        }
        const safeArgs = (Array.isArray(args) ? args : []).map((arg) => {
            const str = String(arg ?? '');
            if (str.includes('\0')) {
                throw new Error('CodeQL argument contains invalid null byte.');
            }
            return str;
        });
        execFileSync(bin, safeArgs, {
            timeout: opts.timeout || 180000,
            stdio: 'ignore',
            windowsHide: true,
            shell: false
        });
    }

    _buildResult(status, findings, startTime, errors, warnings, coverage) {
        return {
            scannerId:  this.id,
            status,
            executionPolicy: 'READ_ONLY_STATIC_POLICY',
            findings,
            durationMs: Date.now() - startTime,
            errors,
            warnings,
            coverage
        };
    }
}

module.exports = { CodeQLScanner };
