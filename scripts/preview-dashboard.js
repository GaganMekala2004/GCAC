const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadVulnerabilities } = require('../extension/csvParser');
const { loadVulnerabilityDetails, loadAllReports } = require('../extension/reportParser');
const { RemediationEngine } = require('../extension/remediationEngine');
const { ScanController } = require('../extension/scanning/scanController');
const { FindingsStore } = require('../extension/scanning/findingsStore');
const { ReScanVerifier } = require('../extension/scanning/reScanVerifier');
const { assertPathWithinWorkspace } = require('../extension/pathUtils');

let PORT = 3000;
const workspaceRoot = path.resolve(__dirname, '..');
const csvPath = path.join(workspaceRoot, 'vulnerability', 'vulnerabilities.csv');
const mediaDir = path.join(workspaceRoot, 'extension', 'media');

const findingsStore = new FindingsStore(workspaceRoot);
const scanController = new ScanController(workspaceRoot, { findingsStore });

const reScanVerifier = new ReScanVerifier(workspaceRoot, scanController);
const engine = new RemediationEngine(workspaceRoot, null, { findingsStore, reScanVerifier });

let hasUserInitiatedScan = false;
let activeScanTarget = '';
let activeCsv = null;

function isLoopbackHostHeader(hostHeader) {
    if (!hostHeader || typeof hostHeader !== 'string') return true;
    const hostname = hostHeader.split(':')[0].trim().toLowerCase();
    return hostname === 'localhost' || hostname === '127.0.0.1';
}

function isAllowedOriginAndHost(req) {
    if (!isLoopbackHostHeader(req.headers.host)) return false;
    const origin = req.headers.origin;
    if (!origin) return true;
    try {
        const parsed = new URL(origin);
        const host = parsed.hostname.toLowerCase();
        return host === 'localhost' || host === '127.0.0.1';
    } catch {
        return false;
    }
}

function sendBlockedPreviewAction(res) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        success: false,
        error: 'POLICY_BLOCKED (Phase 1 P0-F): Browser preview server is read-only and cannot authorize remediation gates or mutate vulnerability records.'
    }));
}

/**
 * Helper to locate source files strictly within workspaceRoot boundary
 */
function resolveSourceFilePath(repository, targetPath) {
    if (!targetPath || typeof targetPath !== 'string' || targetPath.includes('\0')) return null;

    // 1. Direct path
    const directRel = repository ? path.join(repository, targetPath) : targetPath;
    const directCandidate = path.isAbsolute(directRel) ? directRel : path.join(workspaceRoot, directRel);
    const safeDirect = assertPathWithinWorkspace(directCandidate, workspaceRoot);
    if (safeDirect && fs.existsSync(safeDirect) && fs.statSync(safeDirect).isFile()) {
        return safeDirect;
    }

    // 2. Relative to workspace
    const safeWs = assertPathWithinWorkspace(path.join(workspaceRoot, targetPath), workspaceRoot);
    if (safeWs && fs.existsSync(safeWs) && fs.statSync(safeWs).isFile()) {
        return safeWs;
    }

    // 3. Search within repository folder for the base filename
    const repoBaseCandidate = repository ? path.join(workspaceRoot, repository) : workspaceRoot;
    const safeRepoBase = assertPathWithinWorkspace(repoBaseCandidate, workspaceRoot);
    if (safeRepoBase && fs.existsSync(safeRepoBase) && fs.statSync(safeRepoBase).isDirectory()) {
        const targetFilename = path.basename(targetPath).toLowerCase();
        const findRecursive = (dir) => {
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    if (entry.name === 'bin' || entry.name === 'obj' || entry.name === 'node_modules' || entry.name === '.git') continue;
                    const full = path.join(dir, entry.name);
                    if (entry.isFile() && entry.name.toLowerCase() === targetFilename) {
                        return assertPathWithinWorkspace(full, workspaceRoot);
                    }
                    if (entry.isDirectory()) {
                        const res = findRecursive(full);
                        if (res) return res;
                    }
                }
            } catch (e) { }
            return null;
        };
        const found = findRecursive(safeRepoBase);
        if (found) return found;
    }

    return null;
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

    if (!isAllowedOriginAndHost(req)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Forbidden: cross-origin or non-loopback requests are blocked.' }));
        return;
    }

    if (req.method === 'OPTIONS') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Cross-origin preflight disabled in preview server.' }));
        return;
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
        let html = fs.readFileSync(path.join(mediaDir, 'dashboard.html'), 'utf-8');
        const previewCsp = "default-src 'none'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self';";
        html = html.replace('{{CSP_POLICY}}', previewCsp);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    if (url.pathname === '/dashboard.css') {
        const css = fs.readFileSync(path.join(mediaDir, 'dashboard.css'), 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
        res.end(css);
        return;
    }

    if (url.pathname === '/dashboard.js') {
        let js = fs.readFileSync(path.join(mediaDir, 'dashboard.js'), 'utf-8');
        // Inject rich browser shim for acquireVsCodeApi with live SSE stream and IPC bridge
        const browserShim = `
            window.acquireVsCodeApi = function() {
                return {
                    postMessage: function(msg) {
                        if (msg.command === 'getConfig') {
                            fetch('/api/config')
                                .then(r => r.json())
                                .then(cfg => {
                                    window.postMessage({
                                        type: 'CONFIG_UPDATED',
                                        activeRepo: cfg.activeRepo,
                                        activeCsv: cfg.activeCsv,
                                        availableCsvs: cfg.availableCsvs
                                    }, '*');
                                });
                        } else if (msg.command === 'getSandboxStatus') {
                            fetch('/api/sandbox-status')
                                .then(r => r.json())
                                .then(sbx => {
                                    window.postMessage({ type: 'SANDBOX_STATUS_UPDATED', ...sbx }, '*');
                                });
                        } else if (msg.command === 'requestData' || msg.command === 'refresh') {
                            fetch('/api/vulnerabilities')
                                .then(r => r.json())
                                .then(data => {
                                    window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data }, '*');
                                    window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Vulnerability repository synchronized', status: 'info' }, '*');
                                });
                        } else if (msg.command === 'loadDetails') {
                            fetch('/api/details?id=' + encodeURIComponent(msg.vulnerabilityId))
                                .then(r => r.json())
                                .then(details => {
                                    window.postMessage({ type: 'DETAILS_LOADED', details: details }, '*');
                                });
                        } else if (msg.command === 'getSourceCode' || msg.command === 'openLocation') {
                            fetch('/api/source-code?repo=' + encodeURIComponent(msg.repository || '') + '&path=' + encodeURIComponent(msg.path || '') + '&line=' + (msg.line || 1))
                                .then(r => r.json())
                                .then(data => {
                                    if (data.success) {
                                        window.postMessage({
                                            type: 'SOURCE_CODE_LOADED',
                                            filePath: data.filePath,
                                            relativePath: data.relativePath,
                                            code: data.code,
                                            targetLine: data.targetLine
                                        }, '*');
                                        window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Loaded ' + data.relativePath + ' (Line ' + data.targetLine + ')', status: 'success' }, '*');
                                    } else {
                                        window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Source file could not be found: ' + (msg.path || ''), status: 'warning' }, '*');
                                    }
                                });
                        } else if (msg.command === 'runRemediation') {
                            // Connect to live SSE stream for real-time tracking
                            const es = new EventSource('/api/remediate-stream?id=' + encodeURIComponent(msg.vulnerabilityId));
                            es.onmessage = function(e) {
                                try {
                                    const event = JSON.parse(e.data);
                                    window.postMessage({ type: 'REMEDIATION_PROGRESS', event: event }, '*');
                                    if (event.type === 'GATE_REQUIRED' || event.type === 'FINAL_GATE_REQUIRED' || event.type === 'WORKFLOW_COMPLETE') {
                                        es.close();
                                    }
                                } catch (err) {}
                            };
                            es.onerror = function() {
                                es.close();
                            };
                        } else if (msg.command === 'approveRemediation' || msg.command === 'rejectRemediation' || msg.command === 'approveFinalGate' || msg.command === 'rejectFinalGate') {
                            const endpointMap = {
                                approveRemediation: '/api/approve',
                                rejectRemediation: '/api/reject',
                                approveFinalGate: '/api/approve-final',
                                rejectFinalGate: '/api/reject-final'
                            };
                            fetch(endpointMap[msg.command], {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({
                                    type: 'ACTION_FEEDBACK',
                                    text: res.error || 'Gate operations require VS Code Extension Host authorization.',
                                    status: res.success ? 'info' : 'error'
                                }, '*');
                            });
                        } else if (msg.command === 'loadReports') {
                            fetch('/api/reports')
                                .then(r => r.json())
                                .then(reports => {
                                    window.postMessage({ type: 'REPORTS_LOADED', reports: reports }, '*');
                                });
                        } else if (msg.command === 'loadReportContent') {
                            fetch('/api/report-content?path=' + encodeURIComponent(msg.filePath || ''))
                                .then(r => r.json())
                                .then(data => {
                                    if (data.success) {
                                        window.postMessage({
                                            type: 'REPORT_CONTENT_LOADED',
                                            filePath: data.filePath,
                                            fileName: data.fileName,
                                            content: data.content
                                        }, '*');
                                    }
                                });
                        } else if (msg.command === 'launchCopilot') {
                            window.postMessage({
                                type: 'COPILOT_LAUNCHED',
                                prompt: '@vulnerability-orchestrator /remediate-vulnerability ' + msg.vulnerabilityId,
                                vulnerabilityId: msg.vulnerabilityId,
                                title: msg.title
                            }, '*');
                            window.postMessage({
                                type: 'ACTION_FEEDBACK',
                                text: 'Copilot command prepared: @vulnerability-orchestrator /remediate-vulnerability ' + msg.vulnerabilityId,
                                status: 'info'
                            }, '*');
                        } else if (msg.command === 'getScanners') {
                            fetch('/api/scanners')
                                .then(r => r.json())
                                .then(scanners => {
                                    window.postMessage({ type: 'SCANNERS_LOADED', scanners: scanners }, '*');
                                });
                        } else if (msg.command === 'getScanHistory') {
                            fetch('/api/scan-history')
                                .then(r => r.json())
                                .then(history => {
                                    window.postMessage({ type: 'SCAN_HISTORY_LOADED', history: history }, '*');
                                });
                        } else if (msg.command === 'selectRepo' || msg.command === 'selectFile') {
                            fetch('/api/workspace-targets')
                                .then(r => r.json())
                                .then(targets => {
                                    window.postMessage({
                                        type: 'SHOW_TARGET_PICKER',
                                        targets: targets,
                                        mode: msg.command === 'selectFile' ? 'file' : 'folder'
                                    }, '*');
                                });
                        } else if (msg.command === 'selectScanTarget') {
                            fetch('/api/scan/target', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ targetPath: msg.targetPath })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({
                                    type: 'TARGET_SELECTED',
                                    targetPath: res.targetPath,
                                    isFolder: res.isFolder,
                                    displayName: res.displayName
                                }, '*');
                            });
                        } else if (msg.command === 'clearScanResults') {
                            fetch('/api/scan/clear', { method: 'POST' })
                                .then(r => r.json())
                                .then(() => {
                                    window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: [] }, '*');
                                    window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Scan results cleared. Dashboard reset to 0.', status: 'info' }, '*');
                                });
                        } else if (msg.command === 'scanRepository') {
                            fetch('/api/scan', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ scannerIds: msg.scannerIds, targetRepo: msg.targetRepo })
                            }).then(r => r.json()).then(summary => {
                                window.postMessage({
                                    type: 'SCAN_COMPLETED',
                                    scanId: summary.scanId,
                                    findingsCount: summary.findingsSummary ? summary.findingsSummary.total : (summary.findingsCount || 0),
                                    summary: summary
                                }, '*');
                            }).catch(err => {
                                window.postMessage({ type: 'SCAN_ERROR', error: err.message }, '*');
                            });
                        } else if (msg.command === 'cancelScan') {
                            fetch('/api/scan/cancel', { method: 'POST' });
                        }
                    }
                };
            };
        `;
        js = browserShim + '\n' + js;
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
        res.end(js);
        return;
    }

    if (url.pathname === '/api/sandbox-status') {
        const { discoverEnvironment } = require('../extension/sandbox/environmentDiscovery');
        const { loadAndVerifyToolchainRegistry, isTemplateDigestProfile } = require('../extension/sandbox/toolchainProfiles');
        const env = discoverEnvironment(workspaceRoot);
        let approvedProfiles = [];
        let hasTemplateDigests = false;
        try {
            const reg = loadAndVerifyToolchainRegistry();
            hasTemplateDigests = Boolean(reg.hasTemplateDigests);
            approvedProfiles = reg.profiles.map(p => ({
                profileId: p.profileId,
                supportedStack: p.supportedStack,
                toolchainVersion: p.toolchainVersion,
                networkPolicy: p.networkPolicy,
                digestStatus: p.digestStatus || (isTemplateDigestProfile(p) ? 'TEMPLATE_PLACEHOLDER' : 'VERIFIED_IMAGE_DIGEST')
            }));
        } catch {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            sandboxAvailable: Boolean(env.sandboxAvailable),
            sandboxStatus: env.sandboxAvailable ? 'SANDBOX READY' : 'SANDBOX UNAVAILABLE',
            backendType: env.sandboxAvailable ? 'CONTAINER_SANDBOX' : 'NONE',
            selectedRuntime: env.selectedRuntime || 'None',
            osPlatform: `${env.os.platform} (${env.os.arch})`,
            approvedProfiles,
            hasTemplateDigests,
            prerequisites: env.prerequisites || [],
            limitations: env.limitations || []
        }));
        return;
    }

    if (url.pathname === '/api/config') {
        const available = [
            { fsPath: csvPath, relPath: path.relative(workspaceRoot, csvPath), name: path.basename(csvPath) }
        ];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            activeRepo: activeScanTarget || workspaceRoot,
            activeCsv: activeCsv || '',
            availableCsvs: available,
            hasScanned: hasUserInitiatedScan,
            simulationMode: true,
            securityNotice: 'Browser preview runs in read-only local mode; remediation approvals and CSV mutations are disabled.'
        }));
        return;
    }

    if (url.pathname === '/api/workspace-targets') {
        const targets = [
            { path: '.', name: 'Entire Workspace', isFolder: true },
            { path: 'sample-repos/payments-api', name: 'payments-api (Payments API)', isFolder: true },
            { path: 'sample-repos/customer-service', name: 'customer-service (Customer Service)', isFolder: true },
            { path: 'sample-repos/inventory-manager', name: 'inventory-manager (Inventory Manager)', isFolder: true },
            { path: 'sample-repos/identity-provider', name: 'identity-provider (Identity Provider)', isFolder: true },
            { path: 'sample-repos/storefront-api', name: 'storefront-api (Storefront API)', isFolder: true },
            { path: 'sample-repos/gcas-agentic-e2e-test-repo', name: 'gcas-agentic-e2e-test-repo (Agentic E2E Test API)', isFolder: true },
            { path: 'sample-repos/payments-api/src/PaymentsAPI/Controllers/PaymentController.cs', name: 'PaymentController.cs (SQL Injection)', isFolder: false },
            { path: 'sample-repos/payments-api/src/PaymentsAPI/Controllers/ReceiptController.cs', name: 'ReceiptController.cs (Command Injection)', isFolder: false },
            { path: 'sample-repos/payments-api/src/PaymentsAPI/LegacyCrypto.cs', name: 'LegacyCrypto.cs (DES Crypto)', isFolder: false },
            { path: 'sample-repos/payments-api/src/PaymentsAPI/appsettings.json', name: 'appsettings.json (Hardcoded API Key)', isFolder: false },
            { path: 'sample-repos/customer-service/src/main/java/com/example/customer/config/SecurityConfig.java', name: 'SecurityConfig.java (Auth Bypass)', isFolder: false },
            { path: 'sample-repos/customer-service/src/main/java/com/example/customer/controller/DocumentDownloadController.java', name: 'DocumentDownloadController.java (Path Traversal)', isFolder: false },
            { path: 'sample-repos/gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/SecretService.cs', name: 'SecretService.cs (Hardcoded Secret)', isFolder: false }
        ];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(targets));
        return;
    }

    if (url.pathname === '/api/scanners') {
        const scanners = await scanController.getAvailableScanners();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(scanners));
        return;
    }

    if (url.pathname === '/api/scan-history') {
        const history = scanController.getScanHistory();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(history));
        return;
    }

    if (url.pathname === '/api/scan' && req.method === 'POST') {
        let bodyStr = '';
        req.on('data', chunk => { bodyStr += chunk; });
        req.on('end', async () => {
            try {
                const body = JSON.parse(bodyStr || '{}');
                const rawTarget = body.targetRepo || body.targetPath || activeScanTarget || workspaceRoot;
                const candidate = path.isAbsolute(rawTarget) ? rawTarget : path.resolve(workspaceRoot, rawTarget);
                const safeTarget = assertPathWithinWorkspace(candidate, workspaceRoot);
                if (!safeTarget) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Access denied: scan target outside workspace boundary.' }));
                    return;
                }
                const summary = await scanController.startScan({
                    scannerIds: body.scannerIds,
                    targetRepo: safeTarget
                });
                hasUserInitiatedScan = true;
                activeScanTarget = safeTarget;
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(summary));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    if (url.pathname === '/api/scan/clear' && req.method === 'POST') {
        hasUserInitiatedScan = false;
        activeScanTarget = '';
        activeCsv = null;
        findingsStore.clearFindings();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
        return;
    }

    if (url.pathname === '/api/scan/target' && req.method === 'POST') {
        let bodyStr = '';
        req.on('data', chunk => { bodyStr += chunk; });
        req.on('end', () => {
            try {
                const body = JSON.parse(bodyStr || '{}');
                const rel = body.targetPath || '.';
                const candidate = path.isAbsolute(rel) ? rel : path.resolve(workspaceRoot, rel);
                const fullPath = assertPathWithinWorkspace(candidate, workspaceRoot);
                if (!fullPath) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Access denied: scan target outside workspace boundary.' }));
                    return;
                }
                const normalizedRel = path.relative(workspaceRoot, fullPath).replace(/\\/g, '/') || '.';
                activeScanTarget = normalizedRel;
                const isFolder = fs.existsSync(fullPath) ? fs.statSync(fullPath).isDirectory() : true;
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    targetPath: normalizedRel,
                    isFolder: isFolder,
                    displayName: path.basename(fullPath) || 'Workspace'
                }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    if (url.pathname === '/api/scan/cancel' && req.method === 'POST') {
        scanController.cancelScan();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ cancelled: true }));
        return;
    }

    if (url.pathname === '/api/vulnerabilities') {
        if (!hasUserInitiatedScan && !activeCsv) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify([]));
            return;
        }
        const csvData = (activeCsv && fs.existsSync(activeCsv)) ? loadVulnerabilities(activeCsv) : [];
        const scanned = findingsStore.getFindings();
        const adapted = scanned.map(f => f.toCsvCompatibleRecord ? f.toCsvCompatibleRecord() : f);
        const combined = [...csvData, ...adapted];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(combined));
        return;
    }

    if (url.pathname === '/api/details') {
        const id = url.searchParams.get('id');
        const details = loadVulnerabilityDetails(workspaceRoot, id);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(details));
        return;
    }

    if (url.pathname === '/api/reports') {
        const reports = loadAllReports(workspaceRoot);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reports));
        return;
    }

    if (url.pathname === '/api/report-content') {
        const targetPath = url.searchParams.get('path');
        const safePath = targetPath ? assertPathWithinWorkspace(targetPath) : null;
        if (safePath && fs.existsSync(safePath)) {
            const content = fs.readFileSync(safePath, 'utf-8');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                filePath: safePath,
                fileName: path.basename(safePath),
                content: content
            }));
        } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Report not found or path outside workspace' }));
        }
        return;
    }

    // Server-Sent Events endpoint for read-only local analysis preview
    if (url.pathname === '/api/remediate-stream') {
        const id = url.searchParams.get('id');
        const isApproved = url.searchParams.get('approved') === 'true';
        const isFinalApproved = url.searchParams.get('finalApproved') === 'true';

        if (isApproved || isFinalApproved) {
            sendBlockedPreviewAction(res);
            return;
        }

        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });

        try {
            await engine.executePipeline(id, {
                isHumanApproved: false,
                isFinalApproved: false,
                onProgress: (evt) => {
                    res.write(`data: ${JSON.stringify(evt)}\n\n`);
                }
            });
        } catch (err) {
            res.write(`data: ${JSON.stringify({ type: 'LOG', tag: 'ERROR', message: err.message })}\n\n`);
            res.write(`data: ${JSON.stringify({ type: 'REMEDIATION_ERROR', error: err.message })}\n\n`);
        }

        res.end();
        return;
    }

    if (url.pathname === '/api/source-code') {
        const repo = url.searchParams.get('repo') || '';
        const targetPath = url.searchParams.get('path') || '';
        const line = parseInt(url.searchParams.get('line'), 10) || 1;

        const rawDirect = repo ? path.join(repo, targetPath) : targetPath;
        const candidateCheck = rawDirect
            ? (path.isAbsolute(rawDirect) ? rawDirect : path.resolve(workspaceRoot, rawDirect))
            : null;
        const relTargetCheck = targetPath
            ? (path.isAbsolute(targetPath) ? targetPath : path.resolve(workspaceRoot, targetPath))
            : null;
        if (
            !targetPath ||
            (candidateCheck && !assertPathWithinWorkspace(candidateCheck, workspaceRoot)) ||
            (relTargetCheck && !assertPathWithinWorkspace(relTargetCheck, workspaceRoot))
        ) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: false,
                error: 'Access denied: source path outside active workspace boundary.'
            }));
            return;
        }

        const fullPath = resolveSourceFilePath(repo, targetPath);
        if (fullPath && fs.existsSync(fullPath)) {
            const code = fs.readFileSync(fullPath, 'utf-8');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                filePath: fullPath,
                relativePath: path.relative(workspaceRoot, fullPath),
                code: code,
                targetLine: line
            }));
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: false,
                error: `File not found within workspace: ${targetPath}`
            }));
        }
        return;
    }

    if (
        (url.pathname === '/api/approve' ||
            url.pathname === '/api/reject' ||
            url.pathname === '/api/approve-final' ||
            url.pathname === '/api/reject-final') &&
        req.method === 'POST'
    ) {
        sendBlockedPreviewAction(res);
        return;
    }

    res.writeHead(404);
    res.end('Not Found');
});

function startServer(port = PORT) {
    server.listen(port, '127.0.0.1', () => {
        console.log(`GCAC WebView Dashboard preview running at: http://127.0.0.1:${port}`);
    });
}

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const nextPort = server.address()?.port ? server.address().port + 1 : (PORT + 1);
        console.log(`Port ${PORT} is in use. Attempting next available port: http://127.0.0.1:${nextPort}...`);
        PORT = nextPort;
        setTimeout(() => startServer(PORT), 200);
    } else {
        console.error('Server error:', err);
    }
});

if (require.main === module) {
    startServer(PORT);
}

module.exports = {
    server,
    assertPathWithinWorkspace,
    resolveSourceFilePath,
    isAllowedOriginAndHost,
    startServer
};

