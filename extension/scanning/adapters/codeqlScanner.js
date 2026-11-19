'use strict';

const { execFileSync, spawn } = require('child_process');
const { isSeparateRepositoryDirectory } = require('../../repositoryContext');
const path = require('path');
const fs   = require('fs');
const os   = require('os');
const { randomUUID } = require('crypto');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS, SEVERITY_LEVELS, inferTechnologyFromFilePath } = require('../findingModel');
const { findExecutableOnPath } = require('../../sandbox/environmentDiscovery');

const _codeqlVersionCache = new Map();

const excludedDirectories = new Set(['.git', '.gcac', 'node_modules', 'bin', 'obj', 'output', 'remediation-output', 'workspaces', 'evidence']);
function skipDirectory(dir) {
    return excludedDirectories.has(path.basename(dir)) || isSeparateRepositoryDirectory(dir);
}

class CodeQLScanner extends ScannerAdapter {
    constructor(options = {}) {
        super({
            id: 'codeql',
            name: 'GitHub CodeQL (Semantic SAST)',
            version: '2.20.1',
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

        this._workspaceRoot = options.workspaceRoot || null;
        this._extensionRoot = options.extensionRoot || null;
        this._resolvedBinary = null;
    }

    _findCodeqlBinary(workspaceRoot, extensionRoot = null) {
        const exeName = process.platform === 'win32' ? 'codeql.exe' : 'codeql';

        const envPath = process.env.CODEQL_PATH;
        if (envPath && fs.existsSync(envPath)) {
            return envPath;
        }

        const roots = [workspaceRoot, this._workspaceRoot, extensionRoot, this._extensionRoot].filter(Boolean);
        for (const root of roots) {
            const localBin = path.join(root, 'tools', 'codeql', exeName);
            if (fs.existsSync(localBin)) return localBin;
            const nestedBin = path.join(root, 'tools', 'codeql', 'codeql', exeName);
            if (fs.existsSync(nestedBin)) return nestedBin;
        }

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
            if (c && fs.existsSync(c)) return c;
        }

        return findExecutableOnPath([exeName]);
    }

    async isAvailable(optionsOrWorkspaceRoot, maybeExtensionRoot = null) {
        const isObj = optionsOrWorkspaceRoot && typeof optionsOrWorkspaceRoot === 'object';
        const root = isObj
            ? (optionsOrWorkspaceRoot.workspaceRoot || this._workspaceRoot)
            : (optionsOrWorkspaceRoot || this._workspaceRoot);
        const extRoot = isObj
            ? (optionsOrWorkspaceRoot.extensionRoot || maybeExtensionRoot || this._extensionRoot)
            : (maybeExtensionRoot || this._extensionRoot);
        const bin = this._findCodeqlBinary(root, extRoot);

        if (!bin) {
            this.status = SCANNER_STATUS.NOT_INSTALLED;
            return {
                available: false,
                version: '',
                binaryPath: null,
                reason: [
                    'CodeQL CLI not found. Install it via one of the following methods:',
                    '  - Run: node scripts/setup-codeql.js (auto-installs to tools/codeql/)',
                    '  - Download manually from https://github.com/github/codeql-action/releases and extract to <workspace>/tools/codeql/',
                    '  - Set the CODEQL_PATH environment variable to the codeql executable',
                    'CodeQL scanning is optional and does not block other scanner adapters.'
                ].join('\n')
            };
        }

        const useCache = !isObj || optionsOrWorkspaceRoot.useCache !== false;
        if (useCache && _codeqlVersionCache.has(bin)) {
            const cached = _codeqlVersionCache.get(bin);
            if ((Date.now() - cached.checkedAt) < 60000) {
                this.status = SCANNER_STATUS.READY;
                this._resolvedBinary = bin;
                return { ...cached.info };
            }
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
            const info = {
                available: true,
                version: parsed.version || 'unknown',
                binaryPath: bin,
                reason: ''
            };
            _codeqlVersionCache.set(bin, { checkedAt: Date.now(), info });
            return info;
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

    /**
     * Scans target directory/file for non-empty supported language files.
     * Uses bounded 512-byte reads rather than ingesting entire source trees.
     * Returns null when no supported non-empty source files exist (never guesses csharp!).
     */
    _detectLanguage(targetPath) {
        if (!targetPath || !fs.existsSync(targetPath)) return null;
        let hasCs = false, hasCsproj = false, hasJava = false, hasJs = false, hasPy = false, hasCpp = false, hasGo = false;

        const isNonEmptyFile = (filePath) => {
            try {
                const st = fs.statSync(filePath);
                if (!st.isFile() || st.size === 0) return false;
                const readLen = Math.min(st.size, 512);
                const fd = fs.openSync(filePath, 'r');
                try {
                    const buf = Buffer.allocUnsafe(readLen);
                    const bytesRead = fs.readSync(fd, buf, 0, readLen, 0);
                    const sample = buf.subarray(0, bytesRead).toString('utf8');
                    return sample.trim().length > 0 || st.size > readLen;
                } finally {
                    fs.closeSync(fd);
                }
            } catch {
                return false;
            }
        };

        const checkFile = (fullPath, name) => {
            const f = name.toLowerCase();
            if (!isNonEmptyFile(fullPath)) return;
            if (f.endsWith('.cs')) hasCs = true;
            else if (f.endsWith('.csproj') || f.endsWith('.sln')) hasCsproj = true;
            else if (f.endsWith('.java') || f === 'pom.xml') hasJava = true;
            else if (f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.jsx') || f.endsWith('.tsx')) hasJs = true;
            else if (f.endsWith('.py')) hasPy = true;
            else if (f.endsWith('.cpp') || f.endsWith('.c') || f.endsWith('.h')) hasCpp = true;
            else if (f === 'go.mod' || f.endsWith('.go')) hasGo = true;
        };

        try {
            const st = fs.statSync(targetPath);
            if (st.isFile()) {
                checkFile(targetPath, path.basename(targetPath));
            } else {
                const scanDir = (dir, depth = 0) => {
                    if (depth > 4) return;
                    let entries;
                    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
                    for (const e of entries) {
                        if (e.isSymbolicLink()) continue;
                        if (e.name.startsWith('.') || e.name === 'node_modules' || e.name === 'bin' || e.name === 'obj') continue;
                        const full = path.join(dir, e.name);
                        if (e.isDirectory()) {
                            if (!skipDirectory(full)) scanDir(full, depth + 1);
                            continue;
                        }
                        if (e.isFile()) checkFile(full, e.name);
                    }
                };
                scanDir(targetPath);
            }
        } catch {}

        if (hasCs || hasCsproj) return {
            language: 'csharp',
            suite: 'codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasJava) return {
            language: 'java',
            suite: 'codeql/java-queries:codeql-suites/java-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasJs) return {
            language: 'javascript',
            suite: 'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
            buildMode: ''
        };
        if (hasPy) return {
            language: 'python',
            suite: 'codeql/python-queries:codeql-suites/python-code-scanning.qls',
            buildMode: ''
        };
        if (hasCpp) return {
            language: 'cpp',
            suite: 'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
            buildMode: '--build-mode=none'
        };
        if (hasGo) return {
            language: 'go',
            suite: 'codeql/go-queries:codeql-suites/go-code-scanning.qls',
            buildMode: ''
        };

        return null;
    }

    parseSarif(sarifContent, workspaceRoot, scanId, meta = {}) {
        const findings = [];
        try {
            const sarif = typeof sarifContent === 'string' ? JSON.parse(sarifContent) : sarifContent;
            const effectiveRoot = meta.sourceRoot || meta.repositoryRoot || workspaceRoot;

            for (const run of (sarif.runs || [])) {
                const driver = run.tool?.driver || {};
                const driverVersion = driver.semanticVersion || driver.version || this.version;

                const rulesMap = {};
                for (const r of (driver.rules || [])) {
                    rulesMap[r.id] = r;
                }

                for (const res of (run.results || [])) {
                    const ruleId  = res.ruleId || res.rule?.id || 'CODEQL-UNKNOWN';
                    const ruleDef = rulesMap[ruleId] || {};
                    const loc     = res.locations && res.locations[0]?.physicalLocation;
                    const uri     = loc?.artifactLocation?.uri || '';
                    if (!uri) continue;
                    const region  = loc?.region || {};

                    let cwe = null;
                    const tags = ruleDef.properties?.tags || res.properties?.tags || [];
                    for (const tag of tags) {
                        const m = String(tag).match(/external\/cwe\/(cwe-\d+)/i);
                        if (m) { cwe = m[1].toUpperCase(); break; }
                    }

                    const CRITICAL_CWES = new Set(['CWE-89', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-798']);
                    let sev = SEVERITY_LEVELS.MEDIUM;
                    if (res.level === 'error') {
                        sev = (cwe && CRITICAL_CWES.has(cwe)) ? SEVERITY_LEVELS.CRITICAL : SEVERITY_LEVELS.HIGH;
                    } else if (res.level === 'warning') {
                        sev = SEVERITY_LEVELS.MEDIUM;
                    } else if (res.level === 'note' || res.level === 'open') {
                        sev = SEVERITY_LEVELS.LOW;
                    }

                    let normalizedPath = uri.replace(/\\/g, '/');
                    if (normalizedPath.startsWith('file:///')) {
                        normalizedPath = normalizedPath.substring(8);
                    } else if (normalizedPath.startsWith('file://')) {
                        normalizedPath = normalizedPath.substring(7);
                    }
                    if (/^[a-zA-Z]:\//.test(normalizedPath) && effectiveRoot) {
                        try {
                            normalizedPath = path.relative(effectiveRoot, normalizedPath).replace(/\\/g, '/');
                        } catch {}
                    } else if (path.isAbsolute(normalizedPath) && effectiveRoot) {
                        normalizedPath = path.relative(effectiveRoot, normalizedPath).replace(/\\/g, '/');
                    }

                    if (meta.sourcePathPrefix) normalizedPath = path.posix.join(meta.sourcePathPrefix, normalizedPath);

                    const remGuidance = ruleDef.help?.text
                        || ruleDef.help?.markdown
                        || `Fix ${ruleId}: ${ruleDef.shortDescription?.text || 'Address the identified vulnerability'}. See ${ruleDef.helpUri || 'https://codeql.github.com/codeql-query-help/'} for detailed remediation guidance.`;

                    let evidence = res.message?.text || '';
                    if (res.relatedLocations && res.relatedLocations.length > 0) {
                        const steps = res.relatedLocations
                            .slice(0, 3)
                            .map(rl => rl.message?.text || '')
                            .filter(Boolean);
                        if (steps.length) evidence += ` [Flow: ${steps.join(' → ')}]`;
                    }

                    const tech = inferTechnologyFromFilePath(normalizedPath, meta.technology || '');
                    const lineNum = region.startLine || 1;

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
                        detectionMethod:  'CODEQL_SEMANTIC_SAST',
                        filePath:         normalizedPath,
                        line:             lineNum,
                        column:           region.startColumn || 1,
                        evidence,
                        evidenceRef:      `${normalizedPath}:${lineNum}`,
                        remediationGuidance: remGuidance,
                        sourceClassification: 'LocalScanner',
                        classificationType:   'CONFIRMED_RULE_VIOLATION',
                        repository:       meta.repository || '',
                        repositoryRoot:   meta.repositoryRoot || '',
                        canonicalRepositoryId: meta.canonicalRepositoryId || '',
                        applicationNumber: meta.applicationNumber || '',
                        applicationName:  meta.applicationName || '',
                        applicationIdentitySource: meta.applicationIdentitySource || '',
                        technology:       tech
                    });

                    findings.push(finding);
                }
            }
        } catch (e) {}

        return findings;
    }

    async scan(workspaceRoot, targetPath, options = {}) {
        const scanId    = options.scanId || `codeql-${Date.now()}`;
        const startTime = Date.now();
        const tTotal = process.hrtime.bigint();
        this._workspaceRoot = workspaceRoot;
        this._cancelled = false;
        const onProgress = typeof options.onProgress === 'function' ? options.onProgress : () => {};
        const abortSignal = options.abortSignal || null;

        const scanTarget = targetPath || workspaceRoot;
        if (!scanTarget || !fs.existsSync(scanTarget)) {
            return this._buildResult(
                SCANNER_STATUS.FAILED,
                [],
                startTime,
                [`Target path does not exist: '${scanTarget}'.`],
                [],
                '0% (Target path missing)'
            );
        }

        const tDetect0 = process.hrtime.bigint();
        const langInfo = this._detectLanguage(scanTarget);
        const discoveryMs = Number(process.hrtime.bigint() - tDetect0) / 1e6;
        if (!langInfo) {
            return {
                ...this._buildResult(
                    SCANNER_STATUS.NO_SCANNABLE_INPUTS,
                    [],
                    startTime,
                    [],
                    ['No CodeQL-supported non-empty source files found in target.'],
                    '0% (No CodeQL-supported non-empty source files)',
                    { metrics: { discoveryMs: Number(discoveryMs.toFixed(2)), externalProcessMs: 0, parsingMs: 0, totalMs: Number((Number(process.hrtime.bigint() - tTotal) / 1e6).toFixed(2)) } }
                ),
                noScannableInputs: true
            };
        }

        const avail = await this.isAvailable({ workspaceRoot, extensionRoot: options.extensionRoot || this._extensionRoot });
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
                binaryPath: null,
                metrics: {
                    discoveryMs: Number(discoveryMs.toFixed(2)),
                    externalProcessMs: 0,
                    parsingMs: 0,
                    totalMs: Number((Number(process.hrtime.bigint() - tTotal) / 1e6).toFixed(2))
                }
            };
        }

        if (this._cancelled || (abortSignal && abortSignal.aborted)) {
            this.status = SCANNER_STATUS.CANCELLED || 'Cancelled';
            return this._buildResult(SCANNER_STATUS.CANCELLED || 'Cancelled', [], startTime, ['CodeQL scan cancelled before execution.'], [], '0% (Cancelled)', { cancelled: true });
        }

        const codeqlBin  = avail.binaryPath || this._resolvedBinary;
        const timeoutMs  = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 300000;
        const { language, suite, buildMode } = langInfo;

        const stamp       = randomUUID();
        const tempDbDir   = path.join(os.tmpdir(), `gcac-codeql-db-${stamp}`);
        const sarifOutput = path.join(os.tmpdir(), `gcac-codeql-${stamp}.sarif`);

        const stagedSourceRoot = path.join(os.tmpdir(), `gcac-codeql-source-${stamp}`);
        this.status = SCANNER_STATUS.RUNNING;
        let externalProcessNs = 0n;
        let parsingNs = 0n;

        try {
            // Buildless extraction may restore packages and write obj files.
            // A disposable copy prevents interference with concurrent adapters.
            fs.mkdirSync(stagedSourceRoot);
            fs.cpSync(scanTarget, fs.statSync(scanTarget).isDirectory() ? stagedSourceRoot : path.join(stagedSourceRoot, path.basename(scanTarget)), {
                recursive: true,
                filter: source => {
                    const stat = fs.lstatSync(source);
                    return !stat.isSymbolicLink() && (source === scanTarget ||
                        (path.basename(source) !== '.git' && (!stat.isDirectory() || !skipDirectory(source))));
                }
            });
            const createArgs = [
                'database', 'create',
                tempDbDir,
                `--language=${language}`,
                `--source-root=${stagedSourceRoot}`,
                '--overwrite',
                '--no-run-unnecessary-builds'
            ];
            if (buildMode) createArgs.push(buildMode);

            onProgress({
                type: 'SCANNER_FILE_PROGRESS',
                scanId,
                scannerId: this.id,
                currentOperation: `Creating CodeQL ${language} database`,
                indeterminate: true,
                elapsedMs: Date.now() - startTime
            });

            const tProc1 = process.hrtime.bigint();
            await this._execCodeqlAsync(codeqlBin, createArgs, { timeout: timeoutMs, abortSignal });
            externalProcessNs += (process.hrtime.bigint() - tProc1);

            if (this._cancelled || (abortSignal && abortSignal.aborted)) {
                throw new Error('SCAN_CANCELLED');
            }

            const analyzeArgs = [
                'database', 'analyze',
                tempDbDir,
                suite,
                '--format=sarif-latest',
                `--output=${sarifOutput}`,
                '--no-print-metrics-summary'
            ];

            onProgress({
                type: 'SCANNER_FILE_PROGRESS',
                scanId,
                scannerId: this.id,
                currentOperation: `Running CodeQL ${language} security queries`,
                indeterminate: true,
                elapsedMs: Date.now() - startTime
            });

            const tProc2 = process.hrtime.bigint();
            await this._execCodeqlAsync(codeqlBin, analyzeArgs, { timeout: timeoutMs, abortSignal });
            externalProcessNs += (process.hrtime.bigint() - tProc2);

            if (!fs.existsSync(sarifOutput)) {
                return this._buildResult(SCANNER_STATUS.FAILED, [], startTime, ['CodeQL analysis completed without SARIF output; cannot claim zero vulnerabilities.'], [], `0% (${language} — SARIF output missing)`);
            }

            const tParse = process.hrtime.bigint();
            const repoContext = options.repoContext || {};
            const effectiveRepoRoot = repoContext.repositoryRoot || (fs.statSync(scanTarget).isDirectory() ? scanTarget : path.dirname(scanTarget));
            const sarifRaw = await fs.promises.readFile(sarifOutput, 'utf-8');
            const sarif = JSON.parse(sarifRaw);
            if (!Array.isArray(sarif.runs) || sarif.runs.length === 0 || sarif.runs.some(run =>
                !Array.isArray(run.results) || run.invocations?.some(invocation => invocation.executionSuccessful === false))) {
                throw new Error('CodeQL SARIF is incomplete or records unsuccessful execution; coverage cannot be verified.');
            }
            const findings = this.parseSarif(sarifRaw, effectiveRepoRoot, scanId, {
                repository: repoContext.repository || effectiveRepoRoot,
                repositoryRoot: effectiveRepoRoot,
                sourceRoot: stagedSourceRoot,
                sourcePathPrefix: path.relative(effectiveRepoRoot, fs.statSync(scanTarget).isDirectory() ? scanTarget : path.dirname(scanTarget)).replace(/\\/g, '/'),
                canonicalRepositoryId: repoContext.canonicalRepositoryId || '',
                applicationNumber: repoContext.applicationNumber || '',
                applicationName: repoContext.applicationName || '',
                applicationIdentitySource: repoContext.applicationIdentitySource || ''
            });
            parsingNs = process.hrtime.bigint() - tParse;

            this.status = SCANNER_STATUS.COMPLETED;
            return this._buildResult(
                SCANNER_STATUS.COMPLETED,
                findings,
                startTime,
                [],
                [],
                `100% (CodeQL ${language} semantic analysis — ${findings.length} finding(s))`,
                {
                    metrics: {
                        discoveryMs: Number(discoveryMs.toFixed(2)),
                        externalProcessMs: Number((Number(externalProcessNs) / 1e6).toFixed(2)),
                        parsingMs: Number((Number(parsingNs) / 1e6).toFixed(2)),
                        totalMs: Number((Number(process.hrtime.bigint() - tTotal) / 1e6).toFixed(2))
                    }
                }
            );

        } catch (err) {
            const isCancelled = this._cancelled || (abortSignal && abortSignal.aborted) || (err.message && err.message.includes('SCAN_CANCELLED'));
            if (isCancelled) {
                this.status = SCANNER_STATUS.CANCELLED || 'Cancelled';
                return this._buildResult(SCANNER_STATUS.CANCELLED || 'Cancelled', [], startTime, ['CodeQL analysis cancelled; incomplete execution.'], [], '0% (Cancelled)', {
                    cancelled: true,
                    metrics: {
                        discoveryMs: Number(discoveryMs.toFixed(2)),
                        externalProcessMs: Number((Number(externalProcessNs) / 1e6).toFixed(2)),
                        parsingMs: 0,
                        totalMs: Number((Number(process.hrtime.bigint() - tTotal) / 1e6).toFixed(2))
                    }
                });
            }
            this.status = SCANNER_STATUS.FAILED;
            const isTimeout = err.message && (err.message.includes('ETIMEDOUT') || err.message.includes('timed out') || err.message.includes('timeout'));
            const errorMsg  = isTimeout
                ? `CodeQL analysis timed out after ${Math.round(timeoutMs / 1000)}s (incomplete execution).`
                : `CodeQL execution error: ${err.message}`;

            return this._buildResult(SCANNER_STATUS.FAILED, [], startTime, [errorMsg], [], isTimeout ? '0% (Timed out — incomplete execution)' : '0% (Execution failure)', {
                timedOut: isTimeout,
                timeoutReason: isTimeout ? errorMsg : undefined,
                metrics: {
                    discoveryMs: Number(discoveryMs.toFixed(2)),
                    externalProcessMs: Number((Number(externalProcessNs) / 1e6).toFixed(2)),
                    parsingMs: 0,
                    totalMs: Number((Number(process.hrtime.bigint() - tTotal) / 1e6).toFixed(2))
                }
            });

        } finally {
            this.activeProcess = null;
            try { if (fs.existsSync(tempDbDir))   fs.rmSync(tempDbDir,   { recursive: true, force: true }); } catch {}
            try { if (fs.existsSync(sarifOutput)) fs.unlinkSync(sarifOutput); } catch {}
            try { if (fs.existsSync(stagedSourceRoot)) fs.rmSync(stagedSourceRoot, { recursive: true, force: true }); } catch {}
        }
    }

    _validateExecArgs(bin, args) {
        if (typeof bin !== 'string' || !bin.trim() || bin.includes('\0')) {
            throw new Error('Invalid CodeQL executable path.');
        }
        return (Array.isArray(args) ? args : []).map((arg) => {
            const str = String(arg ?? '');
            if (str.includes('\0')) {
                throw new Error('CodeQL argument contains invalid null byte.');
            }
            return str;
        });
    }

    _execCodeql(bin, args, opts = {}) {
        const safeArgs = this._validateExecArgs(bin, args);
        execFileSync(bin, safeArgs, {
            timeout: opts.timeout || 180000,
            stdio: 'ignore',
            windowsHide: true,
            shell: false
        });
    }

    _execCodeqlAsync(bin, args, opts = {}) {
        const safeArgs = this._validateExecArgs(bin, args);
        const timeoutMs = opts.timeout || 180000;
        const abortSignal = opts.abortSignal || null;

        return new Promise((resolve, reject) => {
            if (this._cancelled || (abortSignal && abortSignal.aborted)) {
                return reject(new Error('SCAN_CANCELLED'));
            }

            let finished = false;
            let timedOut = false;
            let cancelled = false;
            let forceKillTimer = null;
            let timeoutTimer = null;

            const child = spawn(bin, safeArgs, {
                stdio: ['ignore', 'ignore', 'pipe'],
                windowsHide: true,
                shell: false,
                // Extractors launch dotnet/java descendants. Terminating only
                // the CLI leaves those processes holding stderr open forever.
                detached: process.platform !== 'win32'
            });
            this.activeProcess = child;

            let stderrBuf = '';
            if (child.stderr) {
                child.stderr.on('data', (chunk) => {
                    if (stderrBuf.length < 4096) stderrBuf += String(chunk);
                });
            }

            const killChild = (reason) => {
                if (finished) return;
                if (reason === 'timeout') timedOut = true;
                if (reason === 'cancel') cancelled = true;
                const killTree = signal => {
                    try {
                        if (process.platform === 'win32') {
                            execFileSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { shell: false, windowsHide: true, stdio: 'ignore', timeout: 5000 });
                        } else process.kill(-child.pid, signal);
                    } catch { try { child.kill(signal); } catch {} }
                };
                killTree('SIGTERM');
                forceKillTimer = setTimeout(() => {
                    killTree('SIGKILL');
                }, 400);
                if (forceKillTimer.unref) forceKillTimer.unref();
            };

            const onAbort = () => killChild('cancel');
            if (abortSignal) {
                abortSignal.addEventListener('abort', onAbort, { once: true });
            }

            timeoutTimer = setTimeout(() => killChild('timeout'), timeoutMs);
            if (timeoutTimer.unref) timeoutTimer.unref();

            const cleanup = () => {
                if (timeoutTimer) clearTimeout(timeoutTimer);
                if (forceKillTimer) clearTimeout(forceKillTimer);
                if (abortSignal) abortSignal.removeEventListener('abort', onAbort);
                if (this.activeProcess === child) this.activeProcess = null;
            };

            child.on('error', (err) => {
                if (finished) return;
                finished = true;
                cleanup();
                reject(err);
            });

            child.on('close', (code, signal) => {
                if (finished) return;
                finished = true;
                cleanup();
                if (cancelled || this._cancelled) {
                    return reject(new Error('SCAN_CANCELLED'));
                }
                if (timedOut) {
                    return reject(new Error(`ETIMEDOUT: CodeQL process timed out after ${timeoutMs}ms`));
                }
                if (code === 0) {
                    return resolve();
                }
                const detail = stderrBuf.trim() ? `: ${stderrBuf.trim().slice(0, 400)}` : '';
                return reject(new Error(`CodeQL exited with code ${code}${signal ? ` (signal ${signal})` : ''}${detail}`));
            });
        });
    }

    _buildResult(status, findings, startTime, errors, warnings, coverage, extra = {}) {
        return {
            scannerId:  this.id,
            status,
            executionPolicy: 'READ_ONLY_STATIC_POLICY',
            findings,
            durationMs: Date.now() - startTime,
            errors,
            warnings,
            coverage,
            ...extra
        };
    }
}

module.exports = { CodeQLScanner };
