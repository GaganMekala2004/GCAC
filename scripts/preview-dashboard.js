const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadVulnerabilities, updateVulnerabilityRow } = require('../extension/csvParser');
const { loadVulnerabilityDetails, loadAllReports } = require('../extension/reportParser');
const { RemediationEngine } = require('../extension/remediationEngine');

let PORT = 3000;
const workspaceRoot = path.resolve(__dirname, '..');
const csvPath = path.join(workspaceRoot, 'vulnerability', 'vulnerabilities.csv');
const mediaDir = path.join(workspaceRoot, 'extension', 'media');
const engine = new RemediationEngine(workspaceRoot);

/**
 * Helper to locate source files in workspace
 */
function resolveSourceFilePath(repository, targetPath) {
    if (!targetPath) return null;

    // 1. Direct path
    const directRel = repository ? path.join(repository, targetPath) : targetPath;
    const directAbs = path.isAbsolute(directRel) ? directRel : path.join(workspaceRoot, directRel);
    if (fs.existsSync(directAbs) && fs.statSync(directAbs).isFile()) {
        return directAbs;
    }

    // 2. Relative to workspace
    const wsRel = path.join(workspaceRoot, targetPath);
    if (fs.existsSync(wsRel) && fs.statSync(wsRel).isFile()) {
        return wsRel;
    }

    // 3. Search within repository folder for the base filename
    const repoBase = repository ? path.join(workspaceRoot, repository) : workspaceRoot;
    if (fs.existsSync(repoBase) && fs.statSync(repoBase).isDirectory()) {
        const targetFilename = path.basename(targetPath).toLowerCase();
        const findRecursive = (dir) => {
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    if (entry.name === 'bin' || entry.name === 'obj' || entry.name === 'node_modules' || entry.name === '.git') continue;
                    const full = path.join(dir, entry.name);
                    if (entry.isFile() && entry.name.toLowerCase() === targetFilename) {
                        return full;
                    }
                    if (entry.isDirectory()) {
                        const res = findRecursive(full);
                        if (res) return res;
                    }
                }
            } catch (e) {}
            return null;
        };
        const found = findRecursive(repoBase);
        if (found) return found;
    }

    return null;
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    // Enable CORS for local testing
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
        const html = fs.readFileSync(path.join(mediaDir, 'dashboard.html'), 'utf-8');
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
                        } else if (msg.command === 'approveRemediation') {
                            fetch('/api/approve', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Stage 4 Gate Approved. Continuing Bench Tests...', status: 'success' }, '*');
                                // Connect to live SSE stream to resume pipeline through Stage 5 & 6
                                const es = new EventSource('/api/remediate-stream?id=' + encodeURIComponent(msg.vulnerabilityId) + '&approved=true');
                                es.onmessage = function(e) {
                                    try {
                                        const event = JSON.parse(e.data);
                                        window.postMessage({ type: 'REMEDIATION_PROGRESS', event: event }, '*');
                                        if (event.type === 'FINAL_GATE_REQUIRED' || event.type === 'WORKFLOW_COMPLETE') {
                                            es.close();
                                        }
                                    } catch (err) {}
                                };
                            });
                        } else if (msg.command === 'rejectRemediation') {
                            fetch('/api/reject', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: res.vulnerabilities }, '*');
                                if (res.details) {
                                    window.postMessage({ type: 'DETAILS_LOADED', details: res.details }, '*');
                                }
                                window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Remediation Fix Rejected for ' + msg.vulnerabilityId, status: 'warning' }, '*');
                            });
                        } else if (msg.command === 'approveFinalGate') {
                            fetch('/api/approve-final', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Stage 6 Final Gate Signed Off. Handing off...', status: 'success' }, '*');
                                const es = new EventSource('/api/remediate-stream?id=' + encodeURIComponent(msg.vulnerabilityId) + '&approved=true&finalApproved=true');
                                es.onmessage = function(e) {
                                    try {
                                        const event = JSON.parse(e.data);
                                        window.postMessage({ type: 'REMEDIATION_PROGRESS', event: event }, '*');
                                        if (event.type === 'WORKFLOW_COMPLETE') {
                                            es.close();
                                        }
                                    } catch (err) {}
                                };
                            });
                        } else if (msg.command === 'rejectFinalGate') {
                            fetch('/api/reject-final', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: res.vulnerabilities }, '*');
                                if (res.details) {
                                    window.postMessage({ type: 'DETAILS_LOADED', details: res.details }, '*');
                                }
                                window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Final sign-off rejected. Rework requested.', status: 'warning' }, '*');
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

    if (url.pathname === '/api/config') {
        const available = [
            { fsPath: csvPath, relPath: path.relative(workspaceRoot, csvPath), name: path.basename(csvPath) }
        ];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            activeRepo: workspaceRoot,
            activeCsv: csvPath,
            availableCsvs: available
        }));
        return;
    }

    if (url.pathname === '/api/vulnerabilities') {
        const data = loadVulnerabilities(csvPath);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
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
        if (targetPath && fs.existsSync(targetPath)) {
            const content = fs.readFileSync(targetPath, 'utf-8');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                filePath: targetPath,
                fileName: path.basename(targetPath),
                content: content
            }));
        } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Report not found' }));
        }
        return;
    }

    // Server-Sent Events endpoint for live real-time remediation tracking
    if (url.pathname === '/api/remediate-stream') {
        const id = url.searchParams.get('id');
        const isApproved = url.searchParams.get('approved') === 'true';
        const isFinalApproved = url.searchParams.get('finalApproved') === 'true';

        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        });

        try {
            await engine.executePipeline(id, {
                isHumanApproved: isApproved,
                isFinalApproved: isFinalApproved,
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
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: false,
                error: `File not found on disk: ${targetPath}`
            }));
        }
        return;
    }

    if (url.pathname === '/api/approve' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const payload = JSON.parse(body || '{}');
            if (payload.id) {
                updateVulnerabilityRow(csvPath, payload.id, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Approved'
                });
            }
            const data = loadVulnerabilities(csvPath);
            const details = loadVulnerabilityDetails(workspaceRoot, payload.id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, vulnerabilities: data, details }));
        });
        return;
    }

    if (url.pathname === '/api/reject' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const payload = JSON.parse(body || '{}');
            if (payload.id) {
                updateVulnerabilityRow(csvPath, payload.id, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Rejected'
                });
            }
            const data = loadVulnerabilities(csvPath);
            const details = loadVulnerabilityDetails(workspaceRoot, payload.id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, vulnerabilities: data, details }));
        });
        return;
    }

    if (url.pathname === '/api/approve-final' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const payload = JSON.parse(body || '{}');
            if (payload.id) {
                updateVulnerabilityRow(csvPath, payload.id, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Remediated',
                    Final_Validation_Status: 'PASS'
                });
            }
            const data = loadVulnerabilities(csvPath);
            const details = loadVulnerabilityDetails(workspaceRoot, payload.id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, vulnerabilities: data, details }));
        });
        return;
    }

    if (url.pathname === '/api/reject-final' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const payload = JSON.parse(body || '{}');
            if (payload.id) {
                updateVulnerabilityRow(csvPath, payload.id, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Validation Failed'
                });
            }
            const data = loadVulnerabilities(csvPath);
            const details = loadVulnerabilityDetails(workspaceRoot, payload.id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, vulnerabilities: data, details }));
        });
        return;
    }

    res.writeHead(404);
    res.end('Not Found');
});

function startServer(port = PORT) {
    server.listen(port, () => {
        console.log(`GCAC WebView Dashboard preview running at: http://localhost:${port}`);
    });
}

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const nextPort = server.address()?.port ? server.address().port + 1 : (PORT + 1);
        console.log(`Port ${PORT} is in use. Attempting next available port: http://localhost:${nextPort}...`);
        PORT = nextPort;
        setTimeout(() => startServer(PORT), 200);
    } else {
        console.error('Server error:', err);
    }
});

startServer(PORT);

