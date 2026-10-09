const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { loadVulnerabilities, updateVulnerabilityRow } = require('./csvParser');
const { loadVulnerabilityDetails } = require('./reportParser');

let currentPanel = undefined;

/**
 * Extension Activation Entry Point
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    const workspaceRoot = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
        ? vscode.workspace.workspaceFolders[0].uri.fsPath
        : process.cwd();

    const csvPath = path.join(workspaceRoot, 'vulnerability', 'vulnerabilities.csv');

    // 1. Register Webview View Provider (Sidebar)
    const sidebarProvider = new GcacWebviewViewProvider(context.extensionUri, workspaceRoot, csvPath);
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
                    handleWebviewMessage(message, currentPanel.webview, workspaceRoot, csvPath);
                }, undefined, context.subscriptions);

                currentPanel.onDidDispose(() => {
                    currentPanel = undefined;
                }, null, context.subscriptions);
            }
        })
    );

    // 3. Register Refresh Command
    context.subscriptions.push(
        vscode.commands.registerCommand('gcac.refreshData', () => {
            const data = loadVulnerabilities(csvPath);
            if (currentPanel) {
                currentPanel.webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data });
            }
            if (sidebarProvider.view) {
                sidebarProvider.view.webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data });
            }
            vscode.window.showInformationMessage('GCAC Remediation data refreshed.');
        })
    );

    // 4. Register Workspace File Watchers (Offline real-time sync)
    const csvWatcher = vscode.workspace.createFileSystemWatcher('**/vulnerability/*.csv');
    const outputWatcher = vscode.workspace.createFileSystemWatcher('**/output/**');
    const remWatcher = vscode.workspace.createFileSystemWatcher('**/remediation-output/**');

    const triggerRefresh = () => {
        const data = loadVulnerabilities(csvPath);
        if (currentPanel) {
            currentPanel.webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data });
        }
        if (sidebarProvider.view) {
            sidebarProvider.view.webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: data });
        }
    };

    csvWatcher.onDidChange(triggerRefresh);
    csvWatcher.onDidCreate(triggerRefresh);
    outputWatcher.onDidChange(triggerRefresh);
    outputWatcher.onDidCreate(triggerRefresh);
    remWatcher.onDidChange(triggerRefresh);
    remWatcher.onDidCreate(triggerRefresh);

    context.subscriptions.push(csvWatcher, outputWatcher, remWatcher);
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
function handleWebviewMessage(message, webview, workspaceRoot, csvPath) {
    switch (message.command) {
        case 'requestData':
        case 'refresh': {
            const list = loadVulnerabilities(csvPath);
            webview.postMessage({ type: 'INIT_DATA', vulnerabilities: list });
            break;
        }

        case 'loadDetails': {
            const details = loadVulnerabilityDetails(workspaceRoot, message.vulnerabilityId);
            webview.postMessage({ type: 'DETAILS_LOADED', details });
            break;
        }

        case 'openLocation': {
            const fullPath = resolveSourceFilePath(workspaceRoot, message.repository, message.path);

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
            const fullPath = resolveSourceFilePath(workspaceRoot, message.repository, message.path);
            if (fullPath && fs.existsSync(fullPath)) {
                try {
                    const code = fs.readFileSync(fullPath, 'utf-8');
                    webview.postMessage({
                        type: 'SOURCE_CODE_LOADED',
                        filePath: fullPath,
                        relativePath: path.relative(workspaceRoot, fullPath),
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
            const query = `@vulnerability-orchestrator /remediate-vulnerability ${message.vulnerabilityId}`;
            try {
                vscode.commands.executeCommand('workbench.action.chat.open', { query });
                vscode.window.showInformationMessage(`Launched Copilot Chat for ${message.vulnerabilityId}`);
            } catch (e) {
                vscode.window.showInformationMessage(`Copilot Query: ${query}`);
            }
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: `Triggered Copilot Orchestrator for ${message.vulnerabilityId}`,
                status: 'info'
            });
            break;
        }

        case 'approveRemediation': {
            try {
                updateVulnerabilityRow(csvPath, message.vulnerabilityId, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Approved'
                });
                vscode.window.showInformationMessage(`Authorized fix for ${message.vulnerabilityId}. Governance gate approved.`);
                
                // Reload and push back
                const list = loadVulnerabilities(csvPath);
                webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(workspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Fix authorized for ${message.vulnerabilityId}`,
                    status: 'success'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to record approval: ${err.message}`);
            }
            break;
        }

        case 'rejectRemediation': {
            try {
                updateVulnerabilityRow(csvPath, message.vulnerabilityId, {
                    Requires_Human_Review: 'false',
                    Remediation_Status: 'Rejected'
                });
                vscode.window.showWarningMessage(`Remediation rejected for ${message.vulnerabilityId}.`);
                
                const list = loadVulnerabilities(csvPath);
                webview.postMessage({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(workspaceRoot, message.vulnerabilityId);
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
    }
}

/**
 * Webview View Provider for Sidebar
 */
class GcacWebviewViewProvider {
    constructor(extensionUri, workspaceRoot, csvPath) {
        this.extensionUri = extensionUri;
        this.workspaceRoot = workspaceRoot;
        this.csvPath = csvPath;
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
            handleWebviewMessage(message, webviewView.webview, this.workspaceRoot, this.csvPath);
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
