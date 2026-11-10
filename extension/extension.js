let vscode = null;
try {
    vscode = require('vscode');
} catch (e) {
    vscode = null;
}
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { loadVulnerabilities, updateVulnerabilityRow } = require('./csvParser');
const { loadVulnerabilityDetails, loadAllReports } = require('./reportParser');
const { RemediationEngine } = require('./remediationEngine');
const { llmClient } = require('./llmClient');
const { assertPathWithinWorkspace } = require('./pathUtils');
const { ScanController } = require('./scanning/scanController');
const { FindingsStore } = require('./scanning/findingsStore');
const { ReScanVerifier } = require('./scanning/reScanVerifier');
const {
    recordApprovalDecision,
    COPILOT_APPROVAL_LIMITATION_DISCLOSURE
} = require('./approvalGovernance');

let currentPanel = undefined;
let sidebarProvider = null;
let engine = null;
let findingsStore = null;
let scanController = null;
let reScanVerifier = null;
let currentWorkspaceRoot = '';
let currentCsvPath = '';
let hasUserInitiatedScan = false;
let currentScanTarget = '';

/**
 * Validates IPC messages sent from Webview to Extension Host
 */
const ALLOWED_IPC_COMMANDS = new Set([
    'getConfig',
    'selectCsv',
    'selectRepo',
    'selectFile',
    'selectScanTarget',
    'clearScanResults',
    'setCsvPath',
    'requestData',
    'refresh',
    'loadDetails',
    'runRemediation',
    'retryStage',
    'approveRemediation',
    'rejectRemediation',
    'approveFinalGate',
    'rejectFinalGate',
    'openLocation',
    'getSourceCode',
    'launchCopilot',
    'loadReports',
    'loadReportContent',
    'viewDiff',
    'getScanners',
    'getScanStatus',
    'getScanHistory',
    'scanRepository',
    'cancelScan',
    'reScanFinding',
    'getCodeqlStatus',
    'installCodeql'
]);

/**
 * Combines imported CSV records with active local scanner findings
 * @param {string} csvPath 
 * @param {FindingsStore} store 
 * @returns {object[]}
 */
function getCombinedFindings(csvPath, store) {
    const csvList = (csvPath && fs.existsSync(csvPath)) ? loadVulnerabilities(csvPath) : [];
    for (const r of csvList) {
        if (!r.Source_Origin) r.Source_Origin = 'CSV';
    }
    if (!store) return csvList;
    try {
        const scannedList = store.toCsvCompatibleRecords();
        for (const r of scannedList) {
            r.Source_Origin = 'LocalScanner';
        }
        return [...csvList, ...scannedList];
    } catch (e) {
        return csvList;
    }
}

/**
 * Rolls back local edits (targeting isolated working copy when active) with conflict detection
 * and persists rejection/failure status across either CSV or LocalScanner findings.
 * @param {string} vulnerabilityId
 * @param {string} newStatus
 * @returns {{ restored: boolean, conflictDetected: boolean, conflictReason?: string, list: object[] }}
 */
function persistRejectionAndRollback(vulnerabilityId, newStatus) {
    const combined = getCombinedFindings(currentCsvPath, findingsStore);
    const finding = combined.find(f => f.Vulnerability_ID === vulnerabilityId || f.Finding_Fingerprint === vulnerabilityId);
    const sourceFilePath = finding ? resolveSourceFilePath(currentWorkspaceRoot, finding.Repository, finding.Location_Path) : null;
    const runState = engine && typeof engine.loadRunState === 'function' ? engine.loadRunState(vulnerabilityId) : null;
    const rollbackTarget = (runState && runState.isolatedTargetFile && fs.existsSync(runState.isolatedTargetFile))
        ? runState.isolatedTargetFile
        : sourceFilePath;

    let rollbackRes = { restored: false, conflictDetected: false };
    if (engine) {
        if (typeof engine.rollbackFileDetailed === 'function') {
            rollbackRes = engine.rollbackFileDetailed(vulnerabilityId, rollbackTarget);
        } else {
            rollbackRes = { restored: engine.rollbackFile(vulnerabilityId, rollbackTarget), conflictDetected: false };
        }
    }

    if (runState && engine && typeof engine.saveRunState === 'function') {
        if (runState.pendingApprovalRequest && !runState.approvalRecord) {
            try {
                runState.approvalRecord = recordApprovalDecision(runState.pendingApprovalRequest, {
                    decision: 'REJECTED',
                    localHint: 'local-ide-developer'
                });
            } catch (e) { /* keep run state update best-effort */ }
        }
        runState.status = newStatus === 'Rejected' ? 'REJECTED' : 'FAILED';
        runState.stage4Approved = false;
        runState.updatedAt = new Date().toISOString();
        engine.saveRunState(vulnerabilityId, runState);
    }

    const isScannerFinding = finding && finding.Source_Origin === 'LocalScanner';
    if (isScannerFinding && findingsStore) {
        findingsStore.updateFindingStatus(vulnerabilityId, newStatus);
    } else if (currentCsvPath && fs.existsSync(currentCsvPath)) {
        updateVulnerabilityRow(currentCsvPath, vulnerabilityId, {
            Requires_Human_Review: 'false',
            Remediation_Status: newStatus
        });
    }

    return {
        restored: rollbackRes.restored,
        conflictDetected: rollbackRes.conflictDetected || false,
        conflictReason: rollbackRes.reason,
        list: getCombinedFindings(currentCsvPath, findingsStore)
    };
}

const VULN_ID_REGEX = /^[A-Za-z0-9_.-]{3,64}$/;

function validateWebviewMessage(message) {
    if (!message || typeof message !== 'object') {
        return { valid: false, error: 'Invalid IPC payload: message must be an object' };
    }
    if (!message.command || typeof message.command !== 'string') {
        return { valid: false, error: 'Invalid IPC payload: missing command' };
    }
    if (!ALLOWED_IPC_COMMANDS.has(message.command)) {
        return { valid: false, error: `Unauthorized IPC command: '${message.command}'` };
    }
    if (message.vulnerabilityId !== undefined) {
        if (typeof message.vulnerabilityId !== 'string' || !VULN_ID_REGEX.test(message.vulnerabilityId)) {
            return { valid: false, error: `Invalid vulnerability ID format: '${message.vulnerabilityId}'` };
        }
    }
    return { valid: true };
}

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
    } catch (e) { }

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

    // Do NOT auto-load pre-existing sample CSV on startup so dashboard starts at 0
    currentCsvPath = '';
    hasUserInitiatedScan = false;
    currentScanTarget = '';

    // Initialize local findings store and modular scanning subsystem
    findingsStore = new FindingsStore(currentWorkspaceRoot);
    scanController = new ScanController(currentWorkspaceRoot, {
        findingsStore,
        isWorkspaceTrusted: vscode.workspace ? vscode.workspace.isTrusted : true
    });
    reScanVerifier = new ReScanVerifier(scanController);

    engine = new RemediationEngine(currentWorkspaceRoot, currentCsvPath, {
        findingsStore,
        reScanVerifier
    });

    if (vscode.workspace && typeof vscode.workspace.onDidGrantWorkspaceTrust === 'function') {
        vscode.workspace.onDidGrantWorkspaceTrust(() => {
            if (scanController) scanController.setWorkspaceTrust(true);
        }, null, context.subscriptions);
    }

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

    // 4. Register Native Diff View Command
    context.subscriptions.push(
        vscode.commands.registerCommand('gcac.viewDiff', (vulnerabilityId) => {
            const id = vulnerabilityId;
            if (id && engine) {
                const diffInfo = engine.getDiffSnapshotInfo(id);
                if (diffInfo && diffInfo.originalPath && diffInfo.modifiedPath) {
                    const originalUri = vscode.Uri.file(diffInfo.originalPath);
                    const modifiedUri = vscode.Uri.file(diffInfo.modifiedPath);
                    const title = `${id}: ${path.basename(diffInfo.targetPath)} (Original ↔ Remediated)`;
                    vscode.commands.executeCommand('vscode.diff', originalUri, modifiedUri, title);
                    return;
                }
            }
            vscode.window.showInformationMessage(`No diff snapshot currently on disk for ${vulnerabilityId || 'selection'}.`);
        })
    );

    // 4b. Register Scan Repository Command
    context.subscriptions.push(
        vscode.commands.registerCommand('gcac.scanRepository', async () => {
            if (!vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('Cannot execute vulnerability scan in Restricted Mode. Please trust this workspace first.');
                return;
            }
            if (currentPanel) {
                currentPanel.reveal();
            } else {
                vscode.commands.executeCommand('gcac.openDashboard');
            }
            if (scanController) {
                vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: 'GCAC: Scanning repository for security vulnerabilities...',
                    cancellable: true
                }, async (progress, token) => {
                    token.onCancellationRequested(() => {
                        scanController.cancelScan();
                    });
                    try {
                        const rawTarget = currentScanTarget
                            ? path.resolve(currentWorkspaceRoot, currentScanTarget)
                            : currentWorkspaceRoot;
                        const safeTarget = assertPathWithinWorkspace(rawTarget, currentWorkspaceRoot) || currentWorkspaceRoot;
                        const summary = await scanController.startScan({
                            targetRepo: safeTarget,
                            onProgress: (p) => {
                                if (currentPanel) currentPanel.webview.postMessage({ type: 'SCAN_PROGRESS', event: p });
                            }
                        });
                        hasUserInitiatedScan = true;
                        currentScanTarget = path.relative(currentWorkspaceRoot, safeTarget).replace(/\\/g, '/') || '.';
                        vscode.window.showInformationMessage(`GCAC Scan Complete: ${summary.findingsSummary.total} finding(s) detected.`);
                        if (currentPanel) {
                            currentPanel.webview.postMessage({
                                type: 'SCAN_COMPLETED',
                                result: summary,
                                scanId: summary.scanId,
                                findingsCount: summary.findingsSummary.total,
                                targetPath: safeTarget,
                                summary
                            });
                            const updatedFindings = getCombinedFindings(currentCsvPath, findingsStore);
                            broadcast({ type: 'DATA_UPDATED', vulnerabilities: updatedFindings });
                        }
                    } catch (err) {
                        vscode.window.showErrorMessage(`GCAC Scan Error: ${err.message}`);
                    }
                });
            }
        })
    );

    // 5. Register Workspace File Watchers with 300ms Debounce
    const csvWatcher = vscode.workspace.createFileSystemWatcher('**/*.csv');
    const outputWatcher = vscode.workspace.createFileSystemWatcher('**/output/**');
    const remWatcher = vscode.workspace.createFileSystemWatcher('**/remediation-output/**');

    let refreshTimeout = null;
    const debouncedTriggerRefresh = (uri) => {
        if (refreshTimeout) {
            clearTimeout(refreshTimeout);
        }
        refreshTimeout = setTimeout(() => {
            triggerRefresh(uri);
            refreshTimeout = null;
        }, 300);
    };

    const triggerRefresh = (uri) => {
        const data = loadVulnerabilities(currentCsvPath);
        const preloaded = getPreloadedDetails(currentWorkspaceRoot, data);
        const fileName = uri && uri.fsPath ? path.basename(uri.fsPath) : '';
        const payload = { type: 'DATA_UPDATED', vulnerabilities: data, preloadedDetails: preloaded, updatedFile: fileName };
        broadcast(payload);

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

    csvWatcher.onDidChange(debouncedTriggerRefresh);
    csvWatcher.onDidCreate(debouncedTriggerRefresh);
    csvWatcher.onDidDelete(debouncedTriggerRefresh);
    outputWatcher.onDidChange(debouncedTriggerRefresh);
    outputWatcher.onDidCreate(debouncedTriggerRefresh);
    outputWatcher.onDidDelete(debouncedTriggerRefresh);
    remWatcher.onDidChange(debouncedTriggerRefresh);
    remWatcher.onDidCreate(debouncedTriggerRefresh);
    remWatcher.onDidDelete(debouncedTriggerRefresh);

    context.subscriptions.push(csvWatcher, outputWatcher, remWatcher);

    // 6. Register GitHub Copilot Chat Participant for @vulnerability-orchestrator
    if (vscode.chat && typeof vscode.chat.createChatParticipant === 'function') {
        try {
            const participant = vscode.chat.createChatParticipant('gcac.vulnerability-orchestrator', async (request, context, response, token) => {
                const prompt = request.prompt.trim();
                const command = request.command;

                const match = prompt.match(/(?:GCAS-E2E-\d+|VUL-POC-\d+|SCAN-[A-Za-z0-9_-]+)/i) || prompt.split(/\s+/).find(w => w.includes('-'));
                const vulnId = match ? (Array.isArray(match) ? match[0] : match) : null;

                if (!vulnId) {
                    response.markdown('### 🛡️ GCAC Vulnerability Orchestrator\n\n' +
                        'Welcome to the Multi-Agent Vulnerability Remediation Agent (powered by GitHub Copilot).\n\n' +
                        '**Available Copilot Chat Commands:**\n' +
                        '- `@vulnerability-orchestrator /remediate-vulnerability <ID>`: Initiate pipeline (Classification, RCA, Baseline Testing, Patch -> Pauses at Stage 4 Human Gate)\n' +
                        '- `@vulnerability-orchestrator /approve <ID>`: Authorize Stage 4 Gate -> Applies patch and runs Post-Fix & Regression Tests\n' +
                        '- `@vulnerability-orchestrator /final-approve <ID>`: Sign off Final Gate -> Finalizes Documentation & updates CSV row\n\n' +
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
                    : (isHumanApproved ? 'Authorizing Patch & Executing Genuine Tests' : 'Initiating Multi-Stage Pipeline (Classification, RCA, Baseline Testing)');

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
                        const diffHashLine = result.proposedDiffSha256 ? `- **Proposed Diff SHA-256**: \`${result.proposedDiffSha256}\`\n` : '';
                        response.markdown(`\n\n---\n### 🛡️ Human Approval Gate (Stage 4)\n` +
                            `Baseline testing executed: **${result.baselineValidation ? result.baselineValidation.status : 'NOT EXECUTED'}**\n` +
                            diffHashLine +
                            `- **Identity Status**: \`AUTHENTICATION_NOT_VERIFIED\` (Local PoC mode)\n` +
                            `- **Copilot Control Boundary**: ${COPILOT_APPROVAL_LIMITATION_DISCLOSURE}\n\n` +
                            `Proposed secure patch generated for \`${vulnId}\`:\n\n` +
                            `\`\`\`diff\n${result.patchDiff}\n\`\`\`\n\n` +
                            `**To authorize via Copilot Chat**, enter:\n` +
                            `> \`@vulnerability-orchestrator /approve ${vulnId}\`\n\n` +
                            `*(Or click Approve in the GCAC Remediation Hub)*\n`);
                    } else if (result.isAwaitingFinalApproval) {
                        response.markdown(`\n\n---\n### 🛡️ Final Human Approval Gate (Stage 8)\n` +
                            `- Post-Fix Test Result: **${result.validation ? (result.validation.outcome || result.validation.status) : 'NOT EXECUTED'}**\n` +
                            `- Independent Auditor Rating: **${result.securityReview ? result.securityReview.rating : 'NOT_VERIFIED'}** (Confidence Score: **${result.securityReview ? result.securityReview.score : 0}/100**)\n\n` +
                            `**To sign off and finalize via Copilot Chat**, enter:\n` +
                            `> \`@vulnerability-orchestrator /final-approve ${vulnId}\`\n\n` +
                            `*(Or click Sign-off in the GCAC Remediation Hub)*\n`);
                    } else if (result.isCompleted) {
                        response.markdown(`\n\n---\n### ✅ Remediation Completed\n` +
                            `- **Vulnerability ID**: \`${vulnId}\`\n` +
                            `- **Shared Markdown Report**: \`${result.reportPath}\`\n` +
                            `- **CSV Status**: Updated to \`${result.status}\` (Selected Row Only)\n` +
                            `- **Next Step**: Ready for Non-Agentic Regression Testing & CI/CD Deployment.\n`);
                    }
                } catch (err) {
                    response.markdown(`\n\n❌ **Pipeline Execution Stopped**: ${err.message}\n`);
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
            } catch (e) { }
        }
    }
    return detailsList;
}

/**
 * Helper to locate source files strictly within workspace
 */
function resolveSourceFilePath(workspaceRoot, repository, targetPath) {
    if (!targetPath) return null;

    // 1. Direct path
    const directRel = repository ? path.join(repository, targetPath) : targetPath;
    const directAbs = path.isAbsolute(directRel) ? directRel : path.join(workspaceRoot, directRel);
    const safeDirect = assertPathWithinWorkspace(directAbs, workspaceRoot);
    if (safeDirect && fs.existsSync(safeDirect) && fs.statSync(safeDirect).isFile()) {
        return safeDirect;
    }

    // 2. Relative to workspace
    const wsRel = path.join(workspaceRoot, targetPath);
    const safeWs = assertPathWithinWorkspace(wsRel, workspaceRoot);
    if (safeWs && fs.existsSync(safeWs) && fs.statSync(safeWs).isFile()) {
        return safeWs;
    }

    // 3. Search within repository folder for the base filename
    const repoBase = repository ? path.join(workspaceRoot, repository) : workspaceRoot;
    const safeRepoBase = assertPathWithinWorkspace(repoBase, workspaceRoot);
    if (safeRepoBase && fs.existsSync(safeRepoBase) && fs.statSync(safeRepoBase).isDirectory()) {
        const targetFilename = path.basename(targetPath).toLowerCase();
        const findRecursive = (dir) => {
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    if (['bin', 'obj', 'node_modules', '.git'].includes(entry.name)) continue;
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

/**
 * Handles Webview IPC messages with validation and workspace confinement
 */
async function handleWebviewMessage(message, webview) {
    // 1. Message structure validation
    const validation = validateWebviewMessage(message);
    if (!validation.valid) {
        console.warn(`[GCAC Security] Blocked invalid IPC message: ${validation.error}`);
        webview.postMessage({
            type: 'ACTION_FEEDBACK',
            text: `Security Warning: ${validation.error}`,
            status: 'error'
        });
        return;
    }

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
                const safeCsv = assertPathWithinWorkspace(uris[0].fsPath, currentWorkspaceRoot);
                if (safeCsv) {
                    currentCsvPath = safeCsv;
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
                } else {
                    vscode.window.showErrorMessage('Security Warning: Selected CSV must reside within the workspace boundary.');
                }
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
                const safeDir = assertPathWithinWorkspace(uris[0].fsPath, currentWorkspaceRoot);
                if (safeDir) {
                    const rel = path.relative(currentWorkspaceRoot, safeDir).replace(/\\/g, '/') || '.';
                    currentScanTarget = rel;
                    broadcast({
                        type: 'TARGET_SELECTED',
                        targetPath: rel,
                        isFolder: true,
                        displayName: path.basename(safeDir) || 'Workspace'
                    });
                    vscode.window.showInformationMessage(`Active target folder selected: ${rel}`);
                } else {
                    vscode.window.showErrorMessage('Security Warning: Selected folder must reside within the workspace boundary.');
                }
            }
            break;
        }

        case 'selectFile': {
            const uris = await vscode.window.showOpenDialog({
                canSelectFiles: true,
                canSelectFolders: false,
                canSelectMany: false,
                title: 'Select File to Scan for Vulnerabilities',
                filters: {
                    'All Files': ['*']
                }
            });
            if (uris && uris.length > 0) {
                const safeFile = assertPathWithinWorkspace(uris[0].fsPath, currentWorkspaceRoot);
                if (safeFile) {
                    const rel = path.relative(currentWorkspaceRoot, safeFile).replace(/\\/g, '/');
                    currentScanTarget = rel;
                    broadcast({
                        type: 'TARGET_SELECTED',
                        targetPath: rel,
                        isFolder: false,
                        displayName: path.basename(safeFile)
                    });
                    vscode.window.showInformationMessage(`Target file selected: ${rel}`);
                } else {
                    vscode.window.showErrorMessage('Security Warning: Selected file must reside within the workspace boundary.');
                }
            }
            break;
        }

        case 'selectScanTarget': {
            if (message.targetPath !== undefined) {
                const target = message.targetPath ? path.resolve(currentWorkspaceRoot, message.targetPath) : currentWorkspaceRoot;
                const safeTarget = assertPathWithinWorkspace(target, currentWorkspaceRoot);
                if (safeTarget) {
                    const rel = path.relative(currentWorkspaceRoot, safeTarget).replace(/\\/g, '/') || '.';
                    currentScanTarget = rel;
                    broadcast({
                        type: 'TARGET_SELECTED',
                        targetPath: rel,
                        isFolder: fs.existsSync(safeTarget) && fs.statSync(safeTarget).isDirectory(),
                        displayName: path.basename(safeTarget) || 'Workspace'
                    });
                }
            }
            break;
        }

        case 'clearScanResults': {
            hasUserInitiatedScan = false;
            currentCsvPath = '';
            currentScanTarget = '';
            if (findingsStore) {
                findingsStore.clearFindings();
            }
            broadcast({ type: 'DATA_UPDATED', vulnerabilities: [] });
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: 'Scan results cleared. Dashboard reset to 0.',
                status: 'info'
            });
            break;
        }

        case 'setCsvPath': {
            const safePath = assertPathWithinWorkspace(message.csvPath, currentWorkspaceRoot);
            if (safePath && fs.existsSync(safePath)) {
                currentCsvPath = safePath;
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
            } else {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: CSV path must be within active workspace root.',
                    status: 'error'
                });
            }
            break;
        }

        case 'requestData':
        case 'refresh': {
            const list = hasUserInitiatedScan || (currentCsvPath && fs.existsSync(currentCsvPath))
                ? getCombinedFindings(currentCsvPath, findingsStore)
                : [];
            const preloaded = getPreloadedDetails(currentWorkspaceRoot, list);
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            webview.postMessage({
                type: 'CONFIG_UPDATED',
                activeRepo: currentScanTarget || currentWorkspaceRoot,
                activeCsv: currentCsvPath || '',
                availableCsvs: availableCsvs,
                hasScanned: hasUserInitiatedScan
            });
            webview.postMessage({ type: 'INIT_DATA', vulnerabilities: list, preloadedDetails: preloaded });
            break;
        }

        case 'loadDetails': {
            let details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
            // If report not found in markdown files, check findingsStore
            if (!details || !details.hasEvidence) {
                const combined = getCombinedFindings(currentCsvPath, findingsStore);
                const finding = combined.find(f => f.Vulnerability_ID === message.vulnerabilityId);
                if (finding) {
                    details = {
                        vulnerabilityId: finding.Vulnerability_ID,
                        hasEvidence: true,
                        reportMarkdown: [
                            `# Vulnerability Finding — ${finding.Vulnerability_ID}`,
                            ``,
                            `## Security Finding Details`,
                            `- **Title**: ${finding.Title}`,
                            `- **Severity**: \`${finding.Severity}\``,
                            `- **Rule / Advisory ID**: \`${finding.CVE_ID || 'N/A'}\``,
                            `- **Category**: \`${finding.Detailed_Name || 'Security Finding'}\``,
                            `- **Source Location**: \`${finding.Location_Path}:${finding.Line_Number || 1}\``,
                            `- **Repository**: \`${finding.Repository || 'workspace'}\``,
                            `- **Source Classification**: \`${finding.Source_Classification || 'LocalScanner'}\``,
                            `- **Remediation Guidance**: ${finding.Remediation_Guidance || 'Remediate according to security best practice.'}`,
                            ``,
                            `## Discovered Evidence`,
                            `\`\`\`text`,
                            finding.Agent_Code_Analysis_Output || 'Local scanner finding detected during automated repository security audit.',
                            `\`\`\``
                        ].join('\n'),
                        patchDiff: '',
                        executionTrace: '',
                        sourceCode: '',
                        sourceLocation: `${finding.Location_Path}:${finding.Line_Number || 1}`,
                        validationSummary: finding.Test_Status || 'Pending',
                        confidenceScore: parseInt(finding.Final_Confidence_Score, 10) || 0,
                        timings: null
                    };
                }
            }
            webview.postMessage({ type: 'DETAILS_LOADED', details });
            break;
        }

        case 'getScanners': {
            if (scanController) {
                const scanners = await scanController.getAvailableScanners();
                webview.postMessage({ type: 'SCANNERS_LOADED', scanners });
            }
            break;
        }

        case 'getScanStatus': {
            if (scanController) {
                webview.postMessage({
                    type: 'SCAN_STATUS',
                    isScanning: scanController.isScanning,
                    currentScanId: scanController.currentScanId
                });
            }
            break;
        }

        case 'getScanHistory': {
            if (findingsStore) {
                const history = findingsStore.getScanHistory();
                webview.postMessage({ type: 'SCAN_HISTORY_LOADED', history });
            }
            break;
        }

        case 'scanRepository': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Scanner execution is disabled in Restricted Mode. Please trust this workspace.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Scan blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                return;
            }

            if (!scanController) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Scanner subsystem not initialized.',
                    status: 'error'
                });
                return;
            }

            try {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Starting local vulnerability scan...',
                    status: 'info'
                });

                const requestedTarget = message.targetRepo || message.targetPath || currentScanTarget || currentWorkspaceRoot;
                const resolvedTarget = path.isAbsolute(requestedTarget)
                    ? requestedTarget
                    : path.resolve(currentWorkspaceRoot, requestedTarget);
                const targetPath = assertPathWithinWorkspace(resolvedTarget, currentWorkspaceRoot);
                if (!targetPath) {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: 'Security Warning: Scan target path must remain inside active workspace boundary.',
                        status: 'error'
                    });
                    return;
                }
                const scanResult = await scanController.startScan({
                    scannerIds: message.scannerIds,
                    targetRepo: targetPath,
                    onProgress: (evt) => {
                        webview.postMessage({ type: 'SCAN_PROGRESS', event: evt });
                    }
                });

                hasUserInitiatedScan = true;
                currentScanTarget = targetPath;
                webview.postMessage({
                    type: 'SCAN_COMPLETED',
                    result: scanResult,
                    scanId: scanResult.scanId,
                    findingsCount: scanResult.findingsSummary.total,
                    targetPath: targetPath
                });
                const combined = getCombinedFindings(currentCsvPath, findingsStore);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: combined });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Scan finished: ${scanResult.findingsSummary.total} findings identified (${scanResult.findingsSummary.critical} Critical, ${scanResult.findingsSummary.high} High).`,
                    status: scanResult.errors.length === 0 ? 'success' : 'warning'
                });
            } catch (err) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Scan failed: ${err.message}`,
                    status: 'error'
                });
            }
            break;
        }

        case 'cancelScan': {
            if (scanController) {
                scanController.cancelScan();
                webview.postMessage({ type: 'SCAN_CANCELLED' });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Scan cancelled by user.',
                    status: 'warning'
                });
            }
            break;
        }

        case 'getCodeqlStatus': {
            // Report CodeQL CLI availability and installation path details
            try {
                const { CodeQLScanner } = require('./scanning/adapters/codeqlScanner');
                const codeqlScanner = new CodeQLScanner();
                const avail = await codeqlScanner.isAvailable(currentWorkspaceRoot);
                const localBinPath = require('path').join(currentWorkspaceRoot, 'tools', 'codeql',
                    process.platform === 'win32' ? 'codeql.exe' : 'codeql');
                const setupScriptPath = require('path').join(currentWorkspaceRoot, 'scripts', 'setup-codeql.js');
                webview.postMessage({
                    type: 'CODEQL_STATUS',
                    available: avail.available,
                    version: avail.version || '',
                    binaryPath: avail.binaryPath || '',
                    reason: avail.reason || '',
                    localBinPath,
                    setupScriptPath
                });
            } catch (err) {
                webview.postMessage({
                    type: 'CODEQL_STATUS',
                    available: false,
                    version: '',
                    binaryPath: '',
                    reason: `Status check failed: ${err.message}`,
                    localBinPath: '',
                    setupScriptPath: ''
                });
            }
            break;
        }

        case 'installCodeql': {
            if (vscode && vscode.workspace && !vscode.workspace.isTrusted) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: CodeQL setup execution is blocked in Restricted Mode.',
                    status: 'error'
                });
                return;
            }
            const setupScript = assertPathWithinWorkspace(
                path.join(currentWorkspaceRoot, 'scripts', 'setup-codeql.js'),
                currentWorkspaceRoot
            );
            if (!setupScript || !fs.existsSync(setupScript)) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: setup-codeql.js not found within active workspace.',
                    status: 'error'
                });
                return;
            }
            // Launch setup-codeql.js in VS Code terminal for visibility
            if (vscode && vscode.window) {
                const terminal = vscode.window.createTerminal({ name: 'CodeQL Setup' });
                terminal.show(true);
                terminal.sendText(`node "${setupScript}"`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'CodeQL setup started in terminal. Check the "CodeQL Setup" terminal tab for progress.',
                    status: 'info'
                });
            } else {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Run: node scripts/setup-codeql.js  in your terminal to install CodeQL CLI.',
                    status: 'info'
                });
            }
            break;
        }

        case 'reScanFinding': {
            const combined = getCombinedFindings(currentCsvPath, findingsStore);
            const finding = combined.find(f => f.Vulnerability_ID === message.vulnerabilityId);
            if (!finding) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Finding '${message.vulnerabilityId}' not found.`,
                    status: 'error'
                });
                return;
            }
            try {
                if (reScanVerifier) {
                    const res = await reScanVerifier.verifyRemediation({ originalFinding: finding });
                    webview.postMessage({ type: 'RESCAN_RESULT', vulnerabilityId: message.vulnerabilityId, result: res });
                }
            } catch (err) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Re-scan error: ${err.message}`,
                    status: 'error'
                });
            }
            break;
        }

        case 'runRemediation': {
            // Check workspace trust
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode. Please trust this workspace to proceed.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Action blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                return;
            }

            try {
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: false,
                    isFinalApproved: false,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = getCombinedFindings(currentCsvPath, findingsStore);
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

        case 'retryStage': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                return;
            }
            try {
                await engine.retryStage(message.vulnerabilityId, message.fromStage || 5, {
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = getCombinedFindings(currentCsvPath, findingsStore);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
            } catch (err) {
                vscode.window.showErrorMessage(`Retry error: ${err.message}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Retry error: ${err.message}`,
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'approveRemediation': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                return;
            }

            try {
                vscode.window.showInformationMessage(`Stage 4 Gate authorized for ${message.vulnerabilityId}. Executing genuine testing...`);
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: true,
                    isFinalApproved: false,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = getCombinedFindings(currentCsvPath, findingsStore);
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
                const { restored, conflictDetected, conflictReason, list } = persistRejectionAndRollback(message.vulnerabilityId, 'Rejected');

                const conflictMsg = conflictDetected ? ` Rollback skipped due to external edit conflict: ${conflictReason}` : '';
                vscode.window.showWarningMessage(`Remediation rejected for ${message.vulnerabilityId}.${restored ? ' Target snapshot restored.' : conflictMsg}`);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Remediation rejected for ${message.vulnerabilityId}${restored ? ' (snapshot restored)' : (conflictDetected ? ' (conflict detected — file preserved)' : '')}`,
                    status: 'warning'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to reject: ${err.message}`);
            }
            break;
        }

        case 'approveFinalGate': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                return;
            }

            try {
                vscode.window.showInformationMessage(`Final Gate authorized for ${message.vulnerabilityId}. Finalizing documentation...`);
                await engine.executePipeline(message.vulnerabilityId, {
                    isHumanApproved: true,
                    isFinalApproved: true,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const list = getCombinedFindings(currentCsvPath, findingsStore);
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
                const { restored, conflictDetected, conflictReason, list } = persistRejectionAndRollback(message.vulnerabilityId, 'Validation Failed');
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                const details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
                webview.postMessage({ type: 'DETAILS_LOADED', details });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Final sign-off rejected. Rework requested.${restored ? ' Snapshot restored.' : (conflictDetected ? ` Conflict detected: ${conflictReason}` : '')}`,
                    status: 'warning'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to reject final gate: ${err.message}`);
            }
            break;
        }

        case 'openLocation': {
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path);
            const safePath = fullPath ? assertPathWithinWorkspace(fullPath, currentWorkspaceRoot) : null;

            if (safePath && fs.existsSync(safePath)) {
                vscode.workspace.openTextDocument(safePath).then(doc => {
                    const line = Math.max(0, (parseInt(message.line, 10) || 1) - 1);
                    vscode.window.showTextDocument(doc, {
                        selection: new vscode.Range(line, 0, line, 0),
                        preview: false
                    });
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Opened ${path.basename(safePath)} at line ${message.line || 1}`,
                    status: 'success'
                });
            } else {
                vscode.window.showWarningMessage(`Source file not found or outside workspace: ${message.path || 'Unknown'}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `File not found or outside workspace boundary: ${message.path || 'Unknown'}`,
                    status: 'warning'
                });
            }
            break;
        }

        case 'getSourceCode': {
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path);
            const safePath = fullPath ? assertPathWithinWorkspace(fullPath, currentWorkspaceRoot) : null;

            if (safePath && fs.existsSync(safePath)) {
                try {
                    const code = fs.readFileSync(safePath, 'utf-8');
                    webview.postMessage({
                        type: 'SOURCE_CODE_LOADED',
                        filePath: safePath,
                        relativePath: path.relative(currentWorkspaceRoot, safePath),
                        code: code,
                        targetLine: parseInt(message.line, 10) || 1
                    });
                } catch (e) {
                    webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: e.message });
                }
            } else {
                webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: 'File not found or outside workspace boundary' });
            }
            break;
        }

        case 'launchCopilot': {
            // Verify workspace trust
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Copilot agent invocation is disabled in Restricted Mode. Please trust this workspace.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Action blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                return;
            }

            // Verify vulnerability exists
            const findings = getCombinedFindings(currentCsvPath, findingsStore);
            const finding = findings.find(f => f.Vulnerability_ID === message.vulnerabilityId);
            if (!finding) {
                vscode.window.showErrorMessage(`Vulnerability record '${message.vulnerabilityId}' not found in scan.`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Vulnerability record '${message.vulnerabilityId}' not found.`,
                    status: 'error'
                });
                return;
            }

            const targetRepo = finding.Repository ? path.join(currentWorkspaceRoot, finding.Repository) : currentWorkspaceRoot;
            const query = `@vulnerability-orchestrator /remediate-vulnerability ${finding.Vulnerability_ID} in repository "${targetRepo}" using scan "${currentCsvPath}"`;

            let chatOpened = false;
            try {
                vscode.commands.executeCommand('workbench.action.chat.open', { query, isPartialQuery: false });
                chatOpened = true;
            } catch (e) {
                console.warn('Could not execute workbench.action.chat.open:', e.message);
            }

            webview.postMessage({
                type: 'COPILOT_LAUNCHED',
                prompt: query,
                vulnerabilityId: finding.Vulnerability_ID,
                title: finding.Title,
                manualSubmissionRequired: true
            });
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: `Copilot Chat opened with prefilled query. Press Enter in Copilot Chat to begin.`,
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
            const safePath = assertPathWithinWorkspace(reportPath, currentWorkspaceRoot);
            if (safePath && fs.existsSync(safePath)) {
                try {
                    const content = fs.readFileSync(safePath, 'utf-8');
                    webview.postMessage({
                        type: 'REPORT_CONTENT_LOADED',
                        filePath: safePath,
                        fileName: path.basename(safePath),
                        content: content
                    });
                } catch (e) {
                    webview.postMessage({ type: 'ACTION_FEEDBACK', text: `Failed to read report: ${e.message}`, status: 'error' });
                }
            } else {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: Report path must be within active workspace boundary.',
                    status: 'error'
                });
            }
            break;
        }

        case 'viewDiff': {
            if (!message.vulnerabilityId) break;
            const diffInfo = engine.getDiffSnapshotInfo(message.vulnerabilityId);
            if (diffInfo && diffInfo.originalPath && diffInfo.modifiedPath) {
                const originalUri = vscode.Uri.file(diffInfo.originalPath);
                const modifiedUri = vscode.Uri.file(diffInfo.modifiedPath);
                const title = `${message.vulnerabilityId}: ${path.basename(diffInfo.targetPath)} (Original ↔ Remediated)`;
                vscode.commands.executeCommand('vscode.diff', originalUri, modifiedUri, title);
            } else {
                vscode.window.showInformationMessage(`No diff snapshot currently on disk for ${message.vulnerabilityId}. View diff in Evidence tab.`);
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
 * Generates cryptographically secure nonce for CSP
 */
function getNonce() {
    return crypto.randomBytes(24).toString('base64url');
}

/**
 * Returns HTML string with properly resolved Webview URIs and strict Content Security Policy
 */
function getWebviewHtml(webview, extensionUri) {
    const mediaPath = path.join(extensionUri.fsPath, 'extension', 'media');
    const htmlPath = path.join(mediaPath, 'dashboard.html');
    let html = fs.readFileSync(htmlPath, 'utf-8');

    const nonce = getNonce();
    const cssUri = webview.asWebviewUri(vscode.Uri.file(path.join(mediaPath, 'dashboard.css')));
    const jsUri = webview.asWebviewUri(vscode.Uri.file(path.join(mediaPath, 'dashboard.js')));

    const csp = [
        "default-src 'none'",
        `img-src ${webview.cspSource} data:`,
        `script-src 'nonce-${nonce}' ${webview.cspSource}`,
        `style-src ${webview.cspSource}`,
        `font-src ${webview.cspSource}`,
        "connect-src 'none'"
    ].join('; ');

    html = html.replace('{{CSP_POLICY}}', csp);
    html = html.replace('href="dashboard.css"', `href="${cssUri}"`);
    html = html.replace('src="dashboard.js"', `src="${jsUri}" nonce="${nonce}"`);

    return html;
}

function deactivate() {
    if (engine) {
        engine.activeRuns.clear();
    }
}

module.exports = {
    activate,
    deactivate,
    assertPathWithinWorkspace,
    validateWebviewMessage,
    getWebviewHtml,
    getNonce,
    getCombinedFindings,
    ALLOWED_IPC_COMMANDS
};
