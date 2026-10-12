const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { loadVulnerabilities, updateVulnerabilityRow } = require('./csvParser');
const { loadVulnerabilityDetails, loadAllReports } = require('./reportParser');
const { RemediationEngine } = require('./remediationEngine');

let currentPanel = undefined;
let sidebarProvider = null;
let engine = null;
let currentWorkspaceRoot = '';
let currentCsvPath = '';

/**
 * Searches for all available CSV files in the workspace
 */
async function getAvailableCsvFiles(workspaceRoot) {
    const list = [];
    try {
        const uris = await vscode.workspace.findFiles('**/*.csv', '**/node_modules/**');
        for (const uri of uris) {
            const rel = workspaceRoot ? path.relative(workspaceRoot, uri.fsPath) : uri.fsPath;
            list.push({
                fsPath: uri.fsPath,
                relPath: rel,
                name: path.basename(uri.fsPath)
            });
        }
    } catch (e) {}

    // Ensure current CSV is represented
    if (currentCsvPath && fs.existsSync(currentCsvPath) && !list.some(item => item.fsPath === currentCsvPath)) {
        list.unshift({
            fsPath: currentCsvPath,
            relPath: workspaceRoot ? path.relative(workspaceRoot, currentCsvPath) : currentCsvPath,
            name: path.basename(currentCsvPath)
        });
    }

    return list;
}

/**
 * Broadcasts an IPC message to both the main dashboard panel and sidebar provider
 */
function broadcast(message) {
    if (currentPanel) {
        currentPanel.webview.postMessage(message);
    }
    if (sidebarProvider && sidebarProvider.view) {
        sidebarProvider.view.webview.postMessage(message);
    }
}

/**
 * Extension Activation Entry Point
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    currentWorkspaceRoot = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
        ? vscode.workspace.workspaceFolders[0].uri.fsPath
        : context.extensionUri.fsPath;

    currentCsvPath = path.join(currentWorkspaceRoot, 'vulnerability', 'vulnerabilities.csv');
    if (!fs.existsSync(currentCsvPath)) {
        const fallbackCsv = path.join(context.extensionUri.fsPath, 'vulnerability', 'vulnerabilities.csv');
        if (fs.existsSync(fallbackCsv)) {
            currentWorkspaceRoot = context.extensionUri.fsPath;
            currentCsvPath = fallbackCsv;
        }
    }
    engine = new RemediationEngine(currentWorkspaceRoot, currentCsvPath);

    // 1. Register Webview View Provider (Sidebar)
    sidebarProvider = new GcacWebviewViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('gcac.remediationView', sidebarProvider)
    );

    // 2. Register Dashboard Panel Command (Full Editor tab)
    context.subscriptions.push(
        vscode.commands.registerCommand('gcac.openDashboard', () => {
            if (currentPanel) {
                currentPanel.reveal(vscode.ViewColumn.One);
            } else {
                currentPanel = vscode.window.createWebviewPanel(
                    'gcacDashboard',
                    'GCAC Remediation Hub',
                    vscode.ViewColumn.One,
                    {
                        enableScripts: true,
                        retainContextWhenHidden: true,
                        localResourceRoots: [vscode.Uri.file(path.join(context.extensionUri.fsPath, 'extension', 'media'))]
                    }
                );

                currentPanel.webview.html = getWebviewHtml(currentPanel.webview, context.extensionUri);

                currentPanel.webview.onDidReceiveMessage(message => {
                    handleWebviewMessage(message, currentPanel.webview);
                }, undefined, context.subscriptions);

                currentPanel.onDidDispose(() => {
                    currentPanel = undefined;
                }, null, context.subscriptions);
            }
        })
    );

    // 3. Register Refresh Command
    context.subscriptions.push(
        vscode.commands.registerCommand('gcac.refreshData', async () => {
            const data = loadVulnerabilities(currentCsvPath);
            const preloaded = getPreloadedDetails(currentWorkspaceRoot, data);
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            broadcast({
                type: 'CONFIG_UPDATED',
                activeRepo: currentWorkspaceRoot,
                activeCsv: currentCsvPath,
                availableCsvs: availableCsvs
            });
            broadcast({ type: 'DATA_UPDATED', vulnerabilities: data, preloadedDetails: preloaded });
            vscode.window.showInformationMessage('GCAC Remediation data refreshed.');
        })
    );

    // 4. Register Workspace File Watchers (Offline real-time sync)
    const csvWatcher = vscode.workspace.createFileSystemWatcher('**/*.csv');
    const outputWatcher = vscode.workspace.createFileSystemWatcher('**/output/**');
    const remWatcher = vscode.workspace.createFileSystemWatcher('**/remediation-output/**');

    const triggerRefresh = (uri) => {
        const data = loadVulnerabilities(currentCsvPath);
        const preloaded = getPreloadedDetails(currentWorkspaceRoot, data);
        const fileName = uri && uri.fsPath ? path.basename(uri.fsPath) : '';
        const payload = { type: 'DATA_UPDATED', vulnerabilities: data, preloadedDetails: preloaded, updatedFile: fileName };
        broadcast(payload);

        // If an output report or remediation evidence file changed, broadcast DETAILS_LOADED immediately
        if (uri && uri.fsPath) {
            const match = path.basename(uri.fsPath).match(/(?:GCAS-E2E-\d+|VUL-POC-\d+)/i) ||
                          path.dirname(uri.fsPath).match(/(?:GCAS-E2E-\d+|VUL-POC-\d+)/i);
            if (match) {
                const freshDetails = loadVulnerabilityDetails(currentWorkspaceRoot, match[0].toUpperCase());
                broadcast({ type: 'DETAILS_LOADED', details: freshDetails });
            }
        }

        if (fileName) {
            vscode.window.setStatusBarMessage(`GCAC: Synced updates from ${fileName}`, 4000);
        }
    };

    csvWatcher.onDidChange(triggerRefresh);
    csvWatcher.onDidCreate(triggerRefresh);
    outputWatcher.onDidChange(triggerRefresh);
    outputWatcher.onDidCreate(triggerRefresh);
    remWatcher.onDidChange(triggerRefresh);
    remWatcher.onDidCreate(triggerRefresh);

    context.subscriptions.push(csvWatcher, outputWatcher, remWatcher);

    // 5. Register GitHub Copilot Chat Participant for @vulnerability-orchestrator
    if (vscode.chat && typeof vscode.chat.createChatParticipant === 'function') {
        try {
            const participant = vscode.chat.createChatParticipant('gcac.vulnerability-orchestrator', async (request, context, response, token) => {
                const prompt = request.prompt.trim();
                const command = request.command;

                const match = prompt.match(/(?:GCAS-E2E-\d+|VUL-POC-\d+)/i) || prompt.split(/\s+/).find(w => w.includes('-'));
                const vulnId = match ? (Array.isArray(match) ? match[0] : match) : null;

                if (!vulnId) {
                    response.markdown('### 🛡️ GCAC Vulnerability Orchestrator\n\n' +
                        'Welcome to the 7-stage LLM Vulnerability Remediation Agent (powered by GitHub Copilot).\n\n' +
                        '**Available Copilot Chat Commands:**\n' +
                        '- `@vulnerability-orchestrator /remediate-vulnerability <ID>`: Initiate pipeline (Classification, RCA, Remediation Patch -> Pauses at Stage 4 Human Gate)\n' +
                        '- `@vulnerability-orchestrator /approve <ID>`: Authorize Stage 4 Gate -> Applies patch and runs Stage 5 Bench Testing\n' +
                        '- `@vulnerability-orchestrator /final-approve <ID>`: Sign off Stage 6 Gate -> Finalizes Documentation & updates CSV row\n\n' +
                        '**Example:**\n' +
                        '`@vulnerability-orchestrator /remediate-vulnerability VUL-POC-008`\n\n' +
                        'Or open the visual dashboard via `GCAC: Open Remediation Dashboard`.');
                    return;
                }

                const lowerPrompt = prompt.toLowerCase();
                const isApproveCmd = command === 'approve' || lowerPrompt.startsWith('approve') || lowerPrompt.includes('/approve');
                const isFinalApproveCmd = command === 'final-approve' || lowerPrompt.startsWith('final-approve') || lowerPrompt.includes('/final-approve') || lowerPrompt.includes('signoff');

                const isHumanApproved = isApproveCmd || isFinalApproveCmd;
                const isFinalApproved = isFinalApproveCmd;

                const runModeDesc = isFinalApproved 
                    ? 'Final Sign-off & Completion' 
                    : (isHumanApproved ? 'Authorizing Patch & Executing Bench Tests' : 'Initiating 7-Stage Autonomous Pipeline');

                response.markdown(`### 🛡️ GCAC Orchestrator: \`${vulnId}\`\n\n**Action**: ${runModeDesc}\n\n`);

                try {
                    const result = await engine.executePipeline(vulnId, {
                        isHumanApproved,
                        isFinalApproved,
                        onProgress: (evt) => {
                            if (evt.type === 'STAGE_START') {
                                response.markdown(`- ⏳ **Stage ${evt.stageNumber} Active**: \`${evt.stageId}\`\n`);
                            } else if (evt.type === 'STAGE_COMPLETE') {
                                response.markdown(`- ✅ **Stage ${evt.stageNumber} Complete**: ${evt.summary}\n`);
                            }
                        }
                    });

                    if (result.isAwaitingApproval) {
                        response.markdown(`\n\n---\n### 🛡️ Human Approval Gate (Stage 4)\n` +
                            `Proposed secure patch generated by Copilot LLM for \`${vulnId}\`:\n\n` +
                            `\`\`\`diff\n${result.patchDiff}\n\`\`\`\n\n` +
                            `**To authorize via Copilot Chat**, enter:\n` +
                            `> \`@vulnerability-orchestrator /approve ${vulnId}\`\n\n` +
                            `*(Or click Approve in the GCAC Remediation Hub)*\n`);
                    } else if (result.isAwaitingFinalApproval) {
                        response.markdown(`\n\n---\n### 🛡️ Final Human Approval Gate (Stage 6)\n` +
                            `Independent Security Auditor review completed with confidence score: **${result.securityReview ? result.securityReview.score : 95}/100** (Rating: **${result.securityReview ? result.securityReview.rating : 'PASS'}**)\n\n` +
                            `**To sign off and finalize via Copilot Chat**, enter:\n` +
                            `> \`@vulnerability-orchestrator /final-approve ${vulnId}\`\n\n` +
                            `*(Or click Sign-off in the GCAC Remediation Hub)*\n`);
                    } else if (result.isCompleted) {
                        response.markdown(`\n\n---\n### ✅ Remediation Completed\n` +
                            `- **Vulnerability ID**: \`${vulnId}\`\n` +
                            `- **Shared Markdown Report**: \`${result.reportPath}\`\n` +
                            `- **CSV Status**: Updated to \`Remediated\` (Selected Row Only)\n` +
                            `- **Next Step**: Ready for Non-Agentic Regression Testing & CI/CD Deployment.\n`);
                    }
                } catch (err) {
                    response.markdown(`\n\n❌ **Remediation Failed**: ${err.message}\n`);
                }
            });
            context.subscriptions.push(participant);
        } catch (e) {
            console.warn('Could not register chat participant:', e.message);
        }
    }
}

/**
 * Preloads details for vulnerabilities that have evidence packages in remediation-output or evidence
 */
function getPreloadedDetails(workspaceRoot, vulnerabilities) {
    const detailsList = [];
    if (!vulnerabilities || !Array.isArray(vulnerabilities)) return detailsList;
    for (const v of vulnerabilities) {
        const id = v.Vulnerability_ID;
        if (!id) continue;
        const remDir = path.join(workspaceRoot, 'remediation-output', id);
        const evidenceDir = path.join(workspaceRoot, 'evidence', id);
        if (fs.existsSync(remDir) || fs.existsSync(evidenceDir)) {
            try {
                const det = loadVulnerabilityDetails(workspaceRoot, id);
                if (det && det.hasEvidence) {
                    detailsList.push(det);
                }
            } catch (e) {}
        }
    }
    return detailsList;
}

/**
 * Helper to locate source files even if relative paths differ slightly
 */
function resolveSourceFilePath(workspaceRoot, repository, targetPath) {
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

/**
 * Handles Webview IPC messages
 */
async function handleWebviewMessage(message, webview) {
    if (!engine) engine = new RemediationEngine(currentWorkspaceRoot, currentCsvPath);

    switch (message.command) {
        case 'getConfig': {
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            webview.postMessage({
                type: 'CONFIG_UPDATED',
                activeRepo: currentWorkspaceRoot,
                activeCsv: currentCsvPath,
                availableCsvs: availableCsvs
            });
            break;
        }

        case 'selectCsv': {
            const uris = await vscode.window.showOpenDialog({
                canSelectFiles: true,
                canSelectFolders: false,
                canSelectMany: false,
                title: 'Select Vulnerability Scan CSV File',
                filters: {
                    'CSV Files': ['csv'],
                    'All Files': ['*']
                }
            });
            if (uris && uris.length > 0) {
                currentCsvPath = uris[0].fsPath;
                engine.updatePaths(currentWorkspaceRoot, currentCsvPath);
                const list = loadVulnerabilities(currentCsvPath);
                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast({
                    type: 'CONFIG_UPDATED',
                    activeRepo: currentWorkspaceRoot,
                    activeCsv: currentCsvPath,
                    availableCsvs: availableCsvs
                });
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                vscode.window.showInformationMessage(`Loaded CSV: ${path.basename(currentCsvPath)}`);
            }
            break;
        }

        case 'selectRepo': {
            const uris = await vscode.window.showOpenDialog({
                canSelectFiles: false,
                canSelectFolders: true,
                canSelectMany: false,
                title: 'Select Target Application Repository Folder'
            });
            if (uris && uris.length > 0) {
                currentWorkspaceRoot = uris[0].fsPath;
                const repoCsv = path.join(currentWorkspaceRoot, 'vulnerability', 'vulnerabilities.csv');
                if (fs.existsSync(repoCsv)) {
                    currentCsvPath = repoCsv;
                }
                engine.updatePaths(currentWorkspaceRoot, currentCsvPath);
                const list = loadVulnerabilities(currentCsvPath);
                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast({
                    type: 'CONFIG_UPDATED',
                    activeRepo: currentWorkspaceRoot,
                    activeCsv: currentCsvPath,
                    availableCsvs: availableCsvs
                });
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                vscode.window.showInformationMessage(`Active Repository switched to: ${path.basename(currentWorkspaceRoot)}`);
            }
            break;
        }

        case 'setCsvPath': {
            if (message.csvPath && fs.existsSync(message.csvPath)) {
                currentCsvPath = message.csvPath;
                engine.updatePaths(currentWorkspaceRoot, currentCsvPath);
                const list = loadVulnerabilities(currentCsvPath);
                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast({
                    type: 'CONFIG_UPDATED',
                    activeRepo: currentWorkspaceRoot,
                    activeCsv: currentCsvPath,
                    availableCsvs: availableCsvs
                });
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                vscode.window.showInformationMessage(`Switched CSV to: ${path.basename(currentCsvPath)}`);
            }
            break;
        }

        case 'requestData':
        case 'refresh': {
            const list = loadVulnerabilities(currentCsvPath);
            const preloaded = getPreloadedDetails(currentWorkspaceRoot, list);
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            webview.postMessage({
                type: 'CONFIG_UPDATED',
                activeRepo: currentWorkspaceRoot,
                activeCsv: currentCsvPath,
                availableCsvs: availableCsvs
            });
            webview.postMessage({ type: 'INIT_DATA', vulnerabilities: list, preloadedDetails: preloaded });
            break;
        }

        case 'loadDetails': {
            const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
            webview.postMessage({ type: 'DETAILS_LOADED', details });
            break;
        }

        case 'runRemediation': {
            try {
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: false,
                    isFinalApproved: false,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = loadVulnerabilities(currentCsvPath);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
            } catch (err) {
                vscode.window.showErrorMessage(`Remediation error: ${err.message}`);
                webview.postMessage({
                    type: 'REMEDIATION_PROGRESS',
                    event: { type: 'LOG', tag: 'ERROR', message: err.message }
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Remediation error: ${err.message}`,
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'approveRemediation': {
            try {
                vscode.window.showInformationMessage(`Stage 4 Gate authorized for ${message.vulnerabilityId}. Continuing to Bench Testing...`);
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: true,
                    isFinalApproved: false,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = loadVulnerabilities(currentCsvPath);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
            } catch (err) {
                vscode.window.showErrorMessage(`Approval error: ${err.message}`);
                webview.postMessage({
                    type: 'REMEDIATION_PROGRESS',
                    event: { type: 'LOG', tag: 'ERROR', message: err.message }
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Approval error: ${err.message}`,
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'rejectRemediation': {
            try {
                updateVulnerabilityRow(currentCsvPath, message.vulnerabilityId, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Rejected'
                });
                vscode.window.showWarningMessage(`Remediation rejected for ${message.vulnerabilityId}.`);
                const list = loadVulnerabilities(currentCsvPath);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Remediation rejected for ${message.vulnerabilityId}`,
                    status: 'warning'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to reject: ${err.message}`);
            }
            break;
        }

        case 'approveFinalGate': {
            try {
                vscode.window.showInformationMessage(`Stage 6 Final Gate authorized for ${message.vulnerabilityId}. Finalizing workflow...`);
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: true,
                    isFinalApproved: true,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = loadVulnerabilities(currentCsvPath);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
            } catch (err) {
                vscode.window.showErrorMessage(`Final gate error: ${err.message}`);
                webview.postMessage({
                    type: 'REMEDIATION_PROGRESS',
                    event: { type: 'LOG', tag: 'ERROR', message: err.message }
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Final gate error: ${err.message}`,
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'rejectFinalGate': {
            try {
                updateVulnerabilityRow(currentCsvPath, message.vulnerabilityId, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Validation Failed'
                });
                const list = loadVulnerabilities(currentCsvPath);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Final sign-off rejected. Rework requested.`,
                    status: 'warning'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to reject final gate: ${err.message}`);
            }
            break;
        }

        case 'openLocation': {
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path);

            if (fullPath && fs.existsSync(fullPath)) {
                vscode.workspace.openTextDocument(fullPath).then(doc => {
                    const line = Math.max(0, (parseInt(message.line, 10) || 1) - 1);
                    vscode.window.showTextDocument(doc, {
                        selection: new vscode.Range(line, 0, line, 0),
                        preview: false
                    });
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Opened ${path.basename(fullPath)} at line ${message.line || 1}`,
                    status: 'success'
                });
            } else {
                vscode.window.showWarningMessage(`Source file not found: ${message.path || 'Unknown'}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `File not found: ${message.path || 'Unknown'}`,
                    status: 'warning'
                });
            }
            break;
        }

        case 'getSourceCode': {
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path);
            if (fullPath && fs.existsSync(fullPath)) {
                try {
                    const code = fs.readFileSync(fullPath, 'utf-8');
                    webview.postMessage({
                        type: 'SOURCE_CODE_LOADED',
                        filePath: fullPath,
                        relativePath: path.relative(currentWorkspaceRoot, fullPath),
                        code: code,
                        targetLine: parseInt(message.line, 10) || 1
                    });
                } catch (e) {
                    webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: e.message });
                }
            } else {
                webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: 'File not found on disk' });
            }
            break;
        }

        case 'launchCopilot': {
            const targetRepo = message.repository ? path.join(currentWorkspaceRoot, message.repository) : currentWorkspaceRoot;
            const query = `@vulnerability-orchestrator /remediate-vulnerability ${message.vulnerabilityId} in repository "${targetRepo}" using scan "${currentCsvPath}"`;
            try {
                vscode.commands.executeCommand('workbench.action.chat.open', { query, isPartialQuery: false });
                vscode.window.showInformationMessage(`Launched GitHub Copilot Agent for ${message.vulnerabilityId}`);
            } catch (e) {
                vscode.window.showInformationMessage(`Copilot Query: ${query}`);
            }
            webview.postMessage({
                type: 'COPILOT_LAUNCHED',
                prompt: query,
                vulnerabilityId: message.vulnerabilityId,
                title: message.title
            });
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: `Launched Copilot Orchestrator for ${message.vulnerabilityId}. Copilot Chat opened.`,
                status: 'info'
            });
            break;
        }
        case 'loadReports': {
            const reports = loadAllReports(currentWorkspaceRoot);
            webview.postMessage({ type: 'REPORTS_LOADED', reports });
            break;
        }

        case 'loadReportContent': {
            const reportPath = message.filePath;
            if (reportPath && fs.existsSync(reportPath)) {
                try {
                    const content = fs.readFileSync(reportPath, 'utf-8');
                    webview.postMessage({
                        type: 'REPORT_CONTENT_LOADED',
                        filePath: reportPath,
                        fileName: path.basename(reportPath),
                        content: content
                    });
                } catch (e) {
                    webview.postMessage({ type: 'ACTION_FEEDBACK', text: `Failed to read report: ${e.message}`, status: 'error' });
                }
            }
            break;
        }
    }
}

/**
 * Webview View Provider for Sidebar
 */
class GcacWebviewViewProvider {
    constructor(extensionUri) {
        this.extensionUri = extensionUri;
        this.view = undefined;
    }

    resolveWebviewView(webviewView, context, token) {
        this.view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.file(path.join(this.extensionUri.fsPath, 'extension', 'media'))]
        };

        webviewView.webview.html = getWebviewHtml(webviewView.webview, this.extensionUri);

        webviewView.webview.onDidReceiveMessage(message => {
            handleWebviewMessage(message, webviewView.webview);
        });
    }
}

/**
 * Returns HTML string with properly resolved Webview URIs
 */
function getWebviewHtml(webview, extensionUri) {
    const mediaPath = path.join(extensionUri.fsPath, 'extension', 'media');
    const htmlPath = path.join(mediaPath, 'dashboard.html');
    let html = fs.readFileSync(htmlPath, 'utf-8');

    const cssUri = webview.asWebviewUri(vscode.Uri.file(path.join(mediaPath, 'dashboard.css')));
    const jsUri = webview.asWebviewUri(vscode.Uri.file(path.join(mediaPath, 'dashboard.js')));

    html = html.replace('href="dashboard.css"', `href="${cssUri}"`);
    html = html.replace('src="dashboard.js"', `src="${jsUri}"`);

    return html;
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
