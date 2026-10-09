const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadVulnerabilities, updateVulnerabilityRow } = require('../extension/csvParser');
const { loadVulnerabilityDetails } = require('../extension/reportParser');

const PORT = 3000;
const workspaceRoot = path.resolve(__dirname, '..');
const csvPath = path.join(workspaceRoot, 'vulnerability', 'vulnerabilities.csv');
const mediaDir = path.join(workspaceRoot, 'extension', 'media');

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

const server = http.createServer((req, res) => {
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
        // Inject rich browser shim for acquireVsCodeApi if running in web browser
        const browserShim = `
            window.acquireVsCodeApi = function() {
                return {
                    postMessage: function(msg) {
                        if (msg.command === 'requestData' || msg.command === 'refresh') {
                            fetch('/api/vulnerabilities')
                                .then(r => r.json())
                                .then(data => {
                                    window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data }, '*');
                                    window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Vulnerability data synchronized', status: 'info' }, '*');
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
                        } else if (msg.command === 'approveRemediation') {
                            fetch('/api/approve', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ id: msg.vulnerabilityId })
                            }).then(r => r.json()).then(res => {
                                window.postMessage({ type: 'DATA_UPDATED', vulnerabilities: res.vulnerabilities }, '*');
                                if (res.details) {
                                    window.postMessage({ type: 'DETAILS_LOADED', details: res.details }, '*');
                                }
                                window.postMessage({ type: 'ACTION_FEEDBACK', text: 'Human Approval Gate Authorized for ' + msg.vulnerabilityId, status: 'success' }, '*');
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

    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, () => {
    console.log(`GCAC WebView Dashboard preview running at: http://localhost:${PORT}`);
});
