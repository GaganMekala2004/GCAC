const { isStage4ConsentEligible } = require('./baselineEligibility');
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
const { GitHubPublication } = require('./githubPublication');
const { discoverEnvironment } = require('./sandbox/environmentDiscovery');
const { TrustedExecutionGateway } = require('./sandbox/trustedExecutionGateway');
const { loadAndVerifyToolchainRegistry, isTemplateDigestProfile } = require('./sandbox/toolchainProfiles');
const { llmClient } = require('./llmClient');
const { assertPathWithinWorkspace } = require('./pathUtils');
const {
    canonicalizePath,
    isSensitiveSystemOrCredentialRoot,
    assertPathWithinAuthorizedRoots,
    isUninitializedGitSubmodule,
    inspectRepositoryTarget,
    RepositoryContextRegistry,
    validateFindingContextContract
} = require('./repositoryContext');
const { ScanController } = require('./scanning/scanController');
const { FindingsStore } = require('./scanning/findingsStore');
const { ReScanVerifier } = require('./scanning/reScanVerifier');
const {
    recordApprovalDecision,
    resolveApprovalIntent,
    COPILOT_APPROVAL_LIMITATION_DISCLOSURE
} = require('./approvalGovernance');
const { RunStateManager } = require('./runStateContract');
const { buildEvidenceChecklist } = require('./evidenceChecklist');
const {
    formatHelpMarkdown,
    formatRunHeaderMarkdown,
    formatStageEventMarkdown,
    formatGateMarkdown,
    formatTerminalConclusionMarkdown,
    formatErrorMarkdown
} = require('./copilotOutputFormatter');

let currentPanel = undefined;
let sidebarProvider = null;
let engine = null;
let findingsStore = null;
let scanController = null;
let reScanVerifier = null;
let registry = null;
let currentWorkspaceRoot = '';
let providerHost;
let extensionRootPath = path.resolve(__dirname, '..');
let currentCsvPath = '';
let hasUserInitiatedScan = false;
let currentScanTarget = '';
let activeRepoContext = null;
const explicitExternalRoots = new Set();

/**
 * Validates IPC messages sent from Webview to Extension Host
 */
const ALLOWED_IPC_COMMANDS = new Set([
    'getConfig',
    'selectCsv',
    'selectRepo',
    'selectFile',
    'selectScanTarget',
    'selectWorkspaceFolder',
    'clearScanResults',
    'setCsvPath',
    'requestData',
    'refresh',
    'loadDetails',
    'syncRunState',
    'retryStage',
    'reviseFix',
    'mapFindingRepository',
    'approveRemediation',
    'acknowledgeDevelopmentBaseline',
    'rejectRemediation',
    'approveFinalGate',
    'rejectFinalGate',
    'openLocation',
    'getSourceCode',
    'launchCopilot',
    'configureProvider',
    'providerStatus',
    'runProvider',
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
    'installCodeql',
    'getSandboxStatus',
    'recoverSandboxInstances'
]);

function getWorkspaceFoldersSnapshot() {
    const folders = [];
    const seen = new Set();
    const wsFolders = (vscode && vscode.workspace && Array.isArray(vscode.workspace.workspaceFolders))
        ? vscode.workspace.workspaceFolders
        : [];
    for (const f of wsFolders) {
        const fsPath = f?.uri?.fsPath;
        if (fsPath && fs.existsSync(fsPath)) {
            const canon = canonicalizePath(fsPath);
            if (!seen.has(canon.toLowerCase())) {
                seen.add(canon.toLowerCase());
                folders.push({
                    name: f.name || path.basename(canon),
                    path: canon
                });
            }
        }
    }
    if (currentWorkspaceRoot && fs.existsSync(currentWorkspaceRoot)) {
        const canonWs = canonicalizePath(currentWorkspaceRoot);
        if (!seen.has(canonWs.toLowerCase())) {
            seen.add(canonWs.toLowerCase());
            folders.unshift({ name: path.basename(canonWs) || 'Workspace', path: canonWs });
        }
    }
    return folders;
}

function buildAuthorizedRoots() {
    const set = new Map();
    const add = (candidate) => {
        if (!candidate || typeof candidate !== 'string' || !fs.existsSync(candidate)) return;
        const canon = canonicalizePath(candidate);
        if (isSensitiveSystemOrCredentialRoot(canon)) return;
        set.set(canon.toLowerCase(), canon);
    };
    for (const wf of getWorkspaceFoldersSnapshot()) add(wf.path);
    add(currentWorkspaceRoot);
    if (currentScanTarget && path.isAbsolute(currentScanTarget)) add(currentScanTarget);
    for (const ext of explicitExternalRoots) add(ext);
    if (registry) {
        for (const r of registry.getAllAuthorizedRepositoryRoots()) add(r);
    }
    return Array.from(set.values());
}

function syncAuthorizedRoots() {
    const roots = buildAuthorizedRoots();
    if (scanController && typeof scanController.setAuthorizedRoots === 'function') {
        scanController.setAuthorizedRoots(roots);
    }
    if (engine && typeof engine.setAuthorizedRoots === 'function') {
        engine.setAuthorizedRoots(roots);
    }
    return roots;
}

function resolveAuthorizedTarget(candidateTarget) {
    if (!candidateTarget || !currentWorkspaceRoot) return null;
    const raw = String(candidateTarget).trim();
    const abs = path.isAbsolute(raw) ? raw : path.resolve(currentWorkspaceRoot, raw);
    const roots = buildAuthorizedRoots();
    const match = assertPathWithinAuthorizedRoots(abs, roots);
    if (match && fs.existsSync(match.canonicalPath)) return match.canonicalPath;
    for (const wf of getWorkspaceFoldersSnapshot()) {
        const wfCand = path.resolve(wf.path, raw);
        const safe = assertPathWithinWorkspace(wfCand, wf.path);
        if (safe && fs.existsSync(safe)) return safe;
    }
    return null;
}

function githubPublicationService() {
    return new GitHubPublication({ getToken: async () => {
        const session = await vscode.authentication?.getSession('github', ['repo'], { createIfNone: true });
        if (!session?.accessToken) throw new Error('GitHub sign-in is required to publish the reviewed pull request.');
        return session.accessToken;
    } });
}
async function requestPublicationConsent(vulnerabilityId) {
    const state = engine.loadRunState(vulnerabilityId);
    const plan = state?.publicationPlan;
    if (state?.formalClosure === 'RESOLVED_CLOSED') return {};
    if (plan?.status === 'READY') {
        const answer = await vscode.window.showWarningMessage(
            `Final sign-off will push the reviewed isolated branch ${plan.branch} and create a draft PR in ${plan.owner}/${plan.repository}, targeting ${plan.baseBranch}. Diff SHA-256: ${state.proposedDiffSha256}. It will not merge the PR.`,
            { modal: true }, 'Approve and create draft PR');
        if (answer !== 'Approve and create draft PR') throw new Error('Final sign-off cancelled; no remote action performed.');
        return { publishPullRequest: true };
    }
    const answer = await vscode.window.showWarningMessage(
        `${plan?.reason || 'GitHub publication is not configured.'} No pull request will be created.`,
        { modal: true }, 'Close local evidence only');
    if (answer !== 'Close local evidence only') throw new Error('Final sign-off cancelled. Configure a GitHub origin before preparing a new publication plan.');
    return {};
}

async function requestLocalDiffConsent(vulnerabilityId) {
    const state = engine.loadRunState(vulnerabilityId);
    if (!engine?.isLocalDevelopment && (!state?.provider || state.provider.id === 'copilot')) return {};
    if (!state?.proposedDiffSha256 || !state.patchDiff) throw new Error('No real proposed diff is available for local consent.');
    await vscode.commands.executeCommand('gcac.viewDiff', vulnerabilityId);
    const answer = await vscode.window.showInformationMessage(
        `${engine.executionMode}: Apply this exact diff in the isolated worktree? Finding ${vulnerabilityId}; run ${state.runId}; SHA-256 ${state.proposedDiffSha256}. Local consent is not enterprise authentication. Native Copilot tools remain outside GCAC interception.`,
        { modal: true }, 'Apply this diff');
    if (answer !== 'Apply this diff') throw new Error('Local developer declined or cancelled exact-diff consent.');
    return { approvedRunId: state.runId, approvedDiffSha256: state.proposedDiffSha256 };
}

async function acknowledgeLocalBaseline(vulnerabilityId, onProgress) {
    if (!engine?.isLocalDevelopment || !vscode.workspace.isTrusted) throw new Error('Trusted LOCAL_DEVELOPMENT mode is required.');
    const state = engine.loadRunState(vulnerabilityId);
    const { canAcknowledgeMissingBaseline } = require('./executionMode');
    if (!canAcknowledgeMissingBaseline(state?.baselineValidation)) throw new Error('This baseline requires technical correction; a development exception is unavailable.');
    const answer = await vscode.window.showWarningMessage(
        `DEVELOPMENT BASELINE EXCEPTION: ${state.baselineValidation.rootError || state.baselineValidation.summary}. Continue to proposal review without claiming baseline validation succeeded? No patch will be applied until separate exact-diff consent.`,
        { modal: true }, 'Acknowledge missing baseline');
    if (answer !== 'Acknowledge missing baseline') return;
    const rationale = await vscode.window.showInputBox({ prompt: 'Record why this disposable development run may proceed without baseline tests.', ignoreFocusOut: true });
    if (!rationale?.trim()) return;
    return engine.acknowledgeDevelopmentBaselineException(vulnerabilityId, { acknowledged: true, rationale }, {
        workspaceTrusted: true, authorizedRoots: buildAuthorizedRoots(), onProgress
    });
}

function buildConfigPayload(extra = {}) {
    const wsFolders = getWorkspaceFoldersSnapshot();
    const activeTargetAbs = currentScanTarget
        ? (resolveAuthorizedTarget(currentScanTarget) || currentWorkspaceRoot)
        : currentWorkspaceRoot;
    if (!activeRepoContext && activeTargetAbs && fs.existsSync(activeTargetAbs)) {
        try {
            activeRepoContext = inspectRepositoryTarget(activeTargetAbs, currentWorkspaceRoot, registry);
        } catch {}
    }
    const historicalCount = findingsStore
        ? findingsStore.getFindings({ includeHistorical: true }).filter(f => f.isHistorical === true).length
        : 0;
    return {
        type: 'CONFIG_UPDATED',
        provider: providerHost?.selection() || { id: 'copilot' },
        executionMode: engine?.executionMode || 'ENTERPRISE',
        activeRepo: currentScanTarget || currentWorkspaceRoot,
        activeRepoPath: activeTargetAbs,
        activeRepoContext,
        activeCsv: currentCsvPath || '',
        workspaceFolders: wsFolders,
        isWorkspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true,
        hasScanned: hasUserInitiatedScan,
        historicalFindingsCount: historicalCount,
        ...extra
    };
}

function getSandboxUiSnapshot(workspaceRoot, gateway = null) {
    let env;
    try {
        env = discoverEnvironment(workspaceRoot, { useCache: true });
    } catch (err) {
        env = {
            sandboxAvailable: false,
            sandboxStatus: 'SANDBOX_UNAVAILABLE',
            selectedRuntime: null,
            os: { platform: process.platform, arch: process.arch },
            prerequisites: [err.message],
            limitations: ['Environment discovery failed.']
        };
    }

    let approvedProfiles = [];
    let profileManifestError = null;
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
    } catch (err) {
        profileManifestError = err.message;
    }

    return {
        sandboxAvailable: Boolean(env.sandboxAvailable),
        sandboxStatus: env.sandboxAvailable ? 'SANDBOX READY' : 'SANDBOX UNAVAILABLE',
        backendType: env.sandboxAvailable ? 'CONTAINER_SANDBOX' : 'NONE',
        selectedRuntime: env.selectedRuntime || 'None',
        osPlatform: `${env.os?.platform || process.platform} (${env.os?.arch || process.arch})`,
        approvedProfiles,
        hasTemplateDigests,
        profileManifestError,
        prerequisites: env.prerequisites || [],
        limitations: env.limitations || [],
        recentDecisions: gateway ? gateway.getAuditDecisions().slice(-10) : []
    };
}

/**
 * Combines imported CSV records with active local scanner findings
 * @param {string} csvPath 
 * @param {FindingsStore} store 
 * @returns {object[]}
 */
function getCombinedFindings(csvPath, store, options = {}) {
    const canonicalRows = rows => rows.map(row => {
        const state = engine?.loadRunState ? engine.loadRunState(row.Vulnerability_ID) : null;
        return { ...row, GCAC_Approval_Eligible: isStage4ConsentEligible(state),
            GCAC_Run_ID: state?.runId || null, GCAC_Execution_Mode: state?.executionMode || engine?.executionMode || 'ENTERPRISE',
            GCAC_Local_Outcome: state?.localOutcome || null,
            ...(state?.localOutcome ? { Remediation_Status: state.localOutcome } : {}) };
    });
    const csvList = (csvPath && fs.existsSync(csvPath)) ? loadVulnerabilities(csvPath) : [];
    for (const r of csvList) {
        if (!r.Source_Origin) r.Source_Origin = 'CSV';
    }
    if (!store) return canonicalRows(csvList);
    try {
        const scannedList = store.toCsvCompatibleRecords({
            repositoryRoot: options.repositoryRoot || undefined,
            canonicalRepositoryId: options.canonicalRepositoryId || undefined,
            includeHistorical: options.includeHistorical === true
        });
        for (const r of scannedList) {
            r.Source_Origin ||= 'LocalScanner';
        }
        return canonicalRows([...csvList, ...scannedList]);
    } catch (e) {
        return canonicalRows(csvList);
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
    if (['configureProvider','providerStatus','runProvider'].includes(message.command) &&
        (Object.keys(message).some(key => !['command','vulnerabilityId'].includes(key)) ||
        (message.command === 'runProvider' && !message.vulnerabilityId))) return { valid: false, error: 'Invalid provider action' };
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
    providerHost = new (require('./providers/host').ProviderHost)(vscode, context);
    extensionRootPath = context?.extensionUri?.fsPath || path.resolve(__dirname, '..');
    currentWorkspaceRoot = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
        ? vscode.workspace.workspaceFolders[0].uri.fsPath
        : extensionRootPath;

    // Do NOT auto-load pre-existing sample CSV on startup so dashboard starts at 0
    currentCsvPath = '';
    hasUserInitiatedScan = false;
    currentScanTarget = '';
    activeRepoContext = null;
    explicitExternalRoots.clear();

    registry = new RepositoryContextRegistry({
        workspaceRoot: currentWorkspaceRoot,
        extensionRoot: extensionRootPath
    });

    const authRoots = buildAuthorizedRoots();

    // Initialize local findings store and modular scanning subsystem
    findingsStore = new FindingsStore(currentWorkspaceRoot);
    scanController = new ScanController(currentWorkspaceRoot, {
        extensionRoot: extensionRootPath,
        findingsStore,
        registry,
        authorizedRoots: authRoots,
        isWorkspaceTrusted: vscode.workspace ? vscode.workspace.isTrusted : true
    });
    reScanVerifier = new ReScanVerifier(scanController);

    engine = new RemediationEngine(currentWorkspaceRoot, currentCsvPath, {
        extensionRoot: extensionRootPath,
        providerHost,
        publicationService: githubPublicationService(),
        findingsStore,
        reScanVerifier,
        registry,
        authorizedRoots: authRoots
    });

    // Safe non-mutating crash recovery of stale sandbox instances & interrupted runs on activation
    if (typeof engine.recoverOrphanedSandboxes === 'function') {
        engine.recoverOrphanedSandboxes().catch(() => {});
    }
    if (typeof engine.reconcileInterruptedRuns === 'function') {
        try {
            engine.reconcileInterruptedRuns();
        } catch {}
    }

    if (vscode.workspace && typeof vscode.workspace.onDidGrantWorkspaceTrust === 'function') {
        vscode.workspace.onDidGrantWorkspaceTrust(() => {
            if (scanController) scanController.setWorkspaceTrust(true);
            syncAuthorizedRoots();
            broadcast(buildConfigPayload({}));
        }, null, context.subscriptions);
    }

    if (vscode.workspace && typeof vscode.workspace.onDidChangeWorkspaceFolders === 'function') {
        vscode.workspace.onDidChangeWorkspaceFolders(async () => {
            syncAuthorizedRoots();
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            broadcast(buildConfigPayload({ availableCsvs }));
        }, null, context.subscriptions);
    }

    // 1. Register Webview View Provider (Sidebar)
    sidebarProvider = new GcacWebviewViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('gcac.remediationView', sidebarProvider)
    );

    // 2. Register Dashboard Panel Command (Full Editor tab)
    context.subscriptions.push(vscode.commands.registerCommand('gcac.openRemediatedSource', async (reference) => {
        const state = reference?.vulnerabilityId && engine?.loadRunState(reference.vulnerabilityId);
        if (!state?.patchAppliedAtStage5 || state.runId !== reference.runId) {
            vscode.window.showErrorMessage('No applied source exists for this run.'); return;
        }
        const file = assertPathWithinWorkspace(state.isolatedTargetFile || state.sourceFilePath, state.isolatedWorkspace?.worktreeDir);
        if (!file || !fs.existsSync(file)) { vscode.window.showErrorMessage('The isolated remediated source is unavailable.'); return; }
        const document = await vscode.workspace.openTextDocument(file);
        await vscode.window.showTextDocument(document, { preview: false });
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.reviewCryptoMigration', async (id) => {
        try {
            if (vscode.workspace?.isTrusted === false) throw new Error('Trust the workspace before reviewing a source migration.');
            const choice = await vscode.window.showQuickPick([
                'No legacy ciphertext: review a new AES-GCM contract',
                'Legacy ciphertext must remain readable'
            ], { title: 'Cryptographic migration compatibility', placeHolder: 'Choose the actual data compatibility requirement' });
            if (!choice) return;
            if (choice.startsWith('Legacy')) {
                vscode.window.showInformationMessage('Legacy compatibility requires a versioned dual-reader/data migration design. Automated editing remains blocked until that contract is specified.');
                return;
            }
            const state = engine.loadRunState(id);
            const answer = await vscode.window.showWarningMessage(
                `Review migration for ${id}, source SHA-256 ${state?.baseTargetSha256}: AES-256-GCM; 32-byte key; caller supplies a unique 12-byte nonce; output is version byte 1, nonce, 16-byte tag, ciphertext. Existing callers must adopt this contract. You confirm there is no legacy ciphertext to preserve. Round-trip and tamper-rejection tests are mandatory. This does not approve the eventual code diff.`,
                { modal: true }, 'Approve migration contract');
            if (answer !== 'Approve migration contract') return;
            engine.approveCryptoMigrationContract(id, { acknowledged: true, legacyData: 'NONE' });
            if (state.provider && state.provider.id !== 'copilot') {
                await engine.executePipeline(id, {provider:state.provider, workspaceTrusted:vscode.workspace.isTrusted,
                    authorizedRoots:buildAuthorizedRoots(), onProgress:event => broadcast({type:'REMEDIATION_PROGRESS',event})});
                broadcast({type:'DETAILS_LOADED',details:loadVulnerabilityDetails(currentWorkspaceRoot,id)});
                return;
            }
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: `@vulnerability-orchestrator /remediate-vulnerability ${id}`, isPartialQuery: false });
        } catch (error) { vscode.window.showErrorMessage(error.message); }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.approveFinalGate', async (proposal) => {
        const state = proposal?.vulnerabilityId && engine?.loadRunState(proposal.vulnerabilityId);
        if (!state || state.runId !== proposal.runId || state.proposedDiffSha256 !== proposal.proposedDiffSha256 || state.approvalDecision !== 'PENDING_STAGE8') {
            vscode.window.showErrorMessage('GCAC: Final sign-off requires the current validated proposal awaiting Stage 8.');
            return;
        }
        await vscode.commands.executeCommand('workbench.action.chat.open', { query: `@vulnerability-orchestrator /final-approve ${proposal.vulnerabilityId} run "${state.runId}" diff "${state.proposedDiffSha256}"`, isPartialQuery: false });
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.approveRemediation', async (proposal) => {
        const state = proposal?.vulnerabilityId && engine?.loadRunState(proposal.vulnerabilityId);
        if (!state || state.runId !== proposal.runId || state.proposedDiffSha256 !== proposal.proposedDiffSha256) {
            vscode.window.showErrorMessage('GCAC: This approval button belongs to an older proposal. Review the current proposal before approving.');
            return;
        }
        await vscode.commands.executeCommand('workbench.action.chat.open', { query: `@vulnerability-orchestrator /approve ${proposal.vulnerabilityId} run "${state.runId}" diff "${state.proposedDiffSha256}"`, isPartialQuery: false });
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.cancelRemediation', async (id) => {
        const findingId = typeof id === 'string' ? id : await vscode.window.showInputBox({ prompt: 'Finding ID of the active run to cancel' });
        if (findingId && engine) vscode.window.showInformationMessage(engine.cancelRun(findingId) ? 'Cancellation requested for the owned GCAC run.' : 'No active GCAC run for this finding.');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.registerDevelopmentRepository', async () => {
        try {
            if (!engine?.isLocalDevelopment || !vscode.workspace.isTrusted) throw new Error('Start VS Code with GCAC_EXECUTION_MODE=LOCAL_DEVELOPMENT and trust the workspace first.');
            const picked = await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, canSelectMany: false, openLabel: 'Select disposable development repository' });
            if (!picked?.[0]) return;
            const repo = picked[0].fsPath;
            const answer = await vscode.window.showWarningMessage(`Register ${repo} as a trusted, disposable development repository? It must not be a production deployment. GCAC will not push, publish, or merge.`, { modal: true }, 'Register disposable repository');
            if (answer !== 'Register disposable repository') return;
            registry.registerDevelopmentRepository(repo, { acknowledged: true, trusted: true, disposable: true });
            syncAuthorizedRoots();
            broadcast(buildConfigPayload());
        } catch (err) { vscode.window.showErrorMessage(`GCAC: ${err.message}`); }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('gcac.acknowledgeDevelopmentBaseline', async (id) => {
        try {
            const findingId = typeof id === 'string' ? id : await vscode.window.showInputBox({ prompt: 'Finding ID for the development baseline exception' });
            if (!findingId) return;
            await acknowledgeLocalBaseline(findingId, event => broadcast({ type: 'REMEDIATION_PROGRESS', event }));
            broadcast({ type: 'DETAILS_LOADED', details: loadVulnerabilityDetails(currentWorkspaceRoot, findingId) });
        } catch (err) { vscode.window.showErrorMessage(`GCAC: ${err.message}`); }
    }));

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
            syncAuthorizedRoots();
            const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                : { includeHistorical: false };
            const data = (hasUserInitiatedScan || (currentCsvPath && fs.existsSync(currentCsvPath)))
                ? getCombinedFindings(currentCsvPath, findingsStore, repoFilter)
                : [];
            const preloaded = getPreloadedDetails(currentWorkspaceRoot, data);
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            broadcast(buildConfigPayload({ availableCsvs }));
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
                        syncAuthorizedRoots();
                        const rawTarget = currentScanTarget
                            ? (path.isAbsolute(currentScanTarget) ? currentScanTarget : path.resolve(currentWorkspaceRoot, currentScanTarget))
                            : currentWorkspaceRoot;
                        const safeTarget = resolveAuthorizedTarget(rawTarget) || currentWorkspaceRoot;
                        const summary = await scanController.startScan({
                            targetRepo: safeTarget,
                            persistRegistration: true,
                            onProgress: (p) => {
                                if (currentPanel) currentPanel.webview.postMessage({ type: 'SCAN_PROGRESS', event: p });
                            }
                        });
                        hasUserInitiatedScan = true;
                        activeRepoContext = summary.repositoryContext || inspectRepositoryTarget(safeTarget, currentWorkspaceRoot, registry);
                        currentScanTarget = assertPathWithinWorkspace(safeTarget, currentWorkspaceRoot)
                            ? (path.relative(currentWorkspaceRoot, safeTarget).replace(/\\/g, '/') || '.')
                            : canonicalizePath(safeTarget);
                        syncAuthorizedRoots();

                        if (summary.status === 'No Scannable Inputs' || summary.status === 'Unsupported Repository') {
                            vscode.window.showWarningMessage(`GCAC Scan: ${summary.status} (${summary.unsupportedReason || 'No supported scannable source/manifest files found.'})`);
                        } else if (summary.errors && summary.errors.length > 0) {
                            vscode.window.showWarningMessage(`GCAC Scan completed with ${summary.errors.length} scanner error(s) — coverage incomplete. Findings: ${summary.findingsSummary.total}.`);
                        } else {
                            vscode.window.showInformationMessage(`GCAC Scan Complete: ${summary.findingsSummary.total} finding(s) detected.`);
                        }

                        const updatedFindings = getCombinedFindings(currentCsvPath, findingsStore, {
                            repositoryRoot: activeRepoContext?.canonicalRepositoryPath || safeTarget,
                            includeHistorical: false
                        });
                        broadcast(buildConfigPayload({ availableCsvs: await getAvailableCsvFiles(currentWorkspaceRoot) }));
                        if (currentPanel) {
                            currentPanel.webview.postMessage({
                                type: 'SCAN_COMPLETED',
                                result: summary,
                                scanId: summary.scanId,
                                findingsCount: summary.findingsSummary.total,
                                targetPath: safeTarget,
                                summary
                            });
                        }
                        broadcast({ type: 'DATA_UPDATED', vulnerabilities: updatedFindings });
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
        const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
            ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
            : { includeHistorical: false };
        const data = (hasUserInitiatedScan || (currentCsvPath && fs.existsSync(currentCsvPath)))
            ? getCombinedFindings(currentCsvPath, findingsStore, repoFilter)
            : [];
        const preloaded = getPreloadedDetails(currentWorkspaceRoot, data);
        const fileName = uri && uri.fsPath ? path.basename(uri.fsPath) : '';
        const payload = { type: 'DATA_UPDATED', vulnerabilities: data, preloadedDetails: preloaded, updatedFile: fileName };
        broadcast(payload);

        if (uri && uri.fsPath) {
            const match = path.basename(uri.fsPath).match(/(?:GCAS-E2E-\d+|VUL-POC-\d+|SCAN-[A-Za-z0-9_-]+)/i) ||
                path.dirname(uri.fsPath).match(/(?:GCAS-E2E-\d+|VUL-POC-\d+|SCAN-[A-Za-z0-9_-]+)/i);
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
                    response.markdown(formatHelpMarkdown());
                    return;
                }

                const lowerPrompt = prompt.toLowerCase();
                const approvalIntent = resolveApprovalIntent(command, prompt);
                const isApproveCmd = approvalIntent === 'STAGE4';
                const isFinalApproveCmd = approvalIntent === 'STAGE8';

                const isHumanApproved = isApproveCmd || isFinalApproveCmd;
                const isFinalApproved = isFinalApproveCmd;
                if (isHumanApproved) {
                    const boundRun = prompt.match(/\brun\s+"([^"]+)"/i)?.[1];
                    const boundDiff = prompt.match(/\bdiff\s+"([a-f0-9]{64})"/i)?.[1];
                    const current = engine.loadRunState(vulnId);
                    if ((boundRun && current?.runId !== boundRun) || (boundDiff && current?.proposedDiffSha256 !== boundDiff)) {
                        response.markdown('This approval belongs to an older run or diff. Review the current proposal before approving.');
                        return;
                    }
                }

                // Extract optional repository hint if explicitly supplied inside prompt
                const repoArgMatch = prompt.match(/in\s+repository\s+"([^"]+)"/i);
                const requestedRepoArg = repoArgMatch ? repoArgMatch[1].trim() : null;
                const authRoots = buildAuthorizedRoots();
                if (requestedRepoArg && path.isAbsolute(requestedRepoArg)) {
                    const matched = assertPathWithinAuthorizedRoots(requestedRepoArg, authRoots);
                    if (!matched) {
                        response.markdown(formatErrorMarkdown(
                            'SEC-02 / Boundary Blocked',
                            `Repository '${requestedRepoArg}' is outside authorized workspace/registered roots. Select or map it via the GCAC Remediation Hub first.`
                        ));
                        return;
                    }
                }

                const runModeDesc = isFinalApproved
                    ? 'Final Sign-off & Completion'
                    : (isHumanApproved ? 'Authorizing Patch & Executing Genuine Tests' : 'Initiating 9-Stage Pipeline (Intake, Classification, Analysis, Proposal)');

                response.markdown(formatRunHeaderMarkdown(vulnId, runModeDesc));

                try {
                    const syncWebviewAfterRun = () => {
                        try {
                            const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                                ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                                : { includeHistorical: false };
                            const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                            broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                            const refreshed = loadVulnerabilityDetails(currentWorkspaceRoot, vulnId);
                            if (refreshed && engine) {
                                refreshed.retryEligibility = engine.evaluateRetryEligibility(
                                    refreshed.runState || vulnId,
                                    { workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true }
                                );
                            }
                            broadcast({ type: 'DETAILS_LOADED', details: refreshed });
                        } catch { }
                    };

                    const localConsent = isHumanApproved && !isFinalApproved ? await requestLocalDiffConsent(vulnId) : {};
                    const publicationConsent = isFinalApproved ? await requestPublicationConsent(vulnId) : {};
                    const result = await engine.executePipeline(vulnId, {
                        ...localConsent,
                        ...publicationConsent,
                        cancellationToken: token,
                        isHumanApproved,
                        isFinalApproved,
                        origin: 'COPILOT_CHAT_PARTICIPANT',
                        authorizedRoots: authRoots,
                        workspaceTrusted: vscode.workspace ? vscode.workspace.isTrusted !== false : true,
                        onProgress: (evt) => {
                            broadcast({ type: 'REMEDIATION_PROGRESS', event: evt });
                            const stageMd = formatStageEventMarkdown(evt);
                            if (stageMd) {
                                response.markdown(stageMd);
                            }
                        }
                    });
                    syncWebviewAfterRun();
                    const sourceState = engine.loadRunState(vulnId);
                    if (sourceState?.patchAppliedAtStage5 && typeof response.button === 'function') {
                        response.button({ command: 'gcac.openRemediatedSource', title: 'Open actual remediated source',
                            arguments: [{ vulnerabilityId: vulnId, runId: sourceState.runId }] });
                    }

                    if (result.isAwaitingApproval || (result.isAwaitingFinalApproval && !result.finalGateBlocked)) {
                        response.markdown(formatGateMarkdown(vulnId, result));
                        if (result.isAwaitingApproval && typeof response.button === 'function') {
                            response.button({ command: 'gcac.approveRemediation', title: 'Approve reviewed Stage 4 patch',
                                arguments: [{ vulnerabilityId: vulnId, runId: result.runId, proposedDiffSha256: result.proposedDiffSha256 }] });
                        }
                        if (result.isAwaitingFinalApproval && !result.finalGateBlocked && typeof response.button === 'function') {
                            response.button({ command: 'gcac.approveFinalGate', title: 'Review and confirm Stage 8 sign-off',
                                arguments: [{ vulnerabilityId: vulnId, runId: result.runId,
                                    proposedDiffSha256: result.proposedDiffSha256 || engine.loadRunState(vulnId)?.proposedDiffSha256 }] });
                        }
                    } else {
                        response.markdown(formatTerminalConclusionMarkdown(vulnId, result));
                        if (result.isManualReview && result.remediationDecision?.vulnerabilityType === 'WEAK_CRYPTO_MIGRATION' && typeof response.button === 'function') {
                            response.button({ command: 'gcac.reviewCryptoMigration', title: 'Review crypto migration contract', arguments: [vulnId] });
                        }
                    }
                } catch (err) {
                    try {
                        const refreshed = loadVulnerabilityDetails(currentWorkspaceRoot, vulnId);
                        broadcast({ type: 'DETAILS_LOADED', details: refreshed });
                    } catch { }
                    response.markdown(formatErrorMarkdown('Pipeline Execution Stopped', err.message));
                    if (err.failureCategory === 'PATCH_INVALID') {
                        response.markdown('\nNo Stage 4 approval request was created because the proposed edits could not be validated. Approval becomes available only after a valid diff and passing baseline exist.\n');
                    }
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
                    if (engine) {
                        const liveState = engine.loadRunState(id);
                        det.retryEligibility = engine.evaluateRetryEligibility(
                            liveState || id,
                            {
                                finding: v,
                                workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true
                            }
                        );
                    }
                    detailsList.push(det);
                }
            } catch (e) { }
        }
    }
    return detailsList;
}

/**
 * Helper to locate source files strictly within authorized repository roots (including external repos)
 */
function resolveSourceFilePath(workspaceRoot, repository, targetPath, authorizedRootsList = null) {
    if (!targetPath) return null;
    const roots = Array.isArray(authorizedRootsList) && authorizedRootsList.length > 0
        ? authorizedRootsList
        : (buildAuthorizedRoots().length > 0 ? buildAuthorizedRoots() : (workspaceRoot ? [workspaceRoot] : []));

    const repoRef = (repository || '').trim();
    if (repoRef) {
        if (path.isAbsolute(repoRef)) {
            const authRepo = assertPathWithinAuthorizedRoots(repoRef, roots);
            if (authRepo && fs.existsSync(authRepo.canonicalPath)) {
                const candidate = assertPathWithinWorkspace(path.resolve(authRepo.canonicalPath, targetPath), authRepo.canonicalPath);
                if (candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
                    return candidate;
                }
            }
        } else {
            for (const root of roots) {
                const repoDir = path.resolve(root, repoRef);
                const safeRepoDir = assertPathWithinWorkspace(repoDir, root);
                if (safeRepoDir && fs.existsSync(safeRepoDir)) {
                    const candidate = assertPathWithinWorkspace(path.resolve(safeRepoDir, targetPath), safeRepoDir);
                    if (candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
                        return candidate;
                    }
                }
            }
        }
    }

    // Check active workspace or authorized roots directly if targetPath is relative to repo/root
    for (const root of roots) {
        const cand = path.resolve(root, targetPath);
        const safeCand = assertPathWithinWorkspace(cand, root);
        if (safeCand && fs.existsSync(safeCand) && fs.statSync(safeCand).isFile()) {
            return safeCand;
        }
    }

    // Search within explicit repository folder only (never scan arbitrary parent dirs)
    let searchBase = null;
    if (repoRef) {
        if (path.isAbsolute(repoRef)) {
            const authRepo = assertPathWithinAuthorizedRoots(repoRef, roots);
            if (authRepo) searchBase = authRepo.canonicalPath;
        } else if (workspaceRoot) {
            searchBase = assertPathWithinWorkspace(path.resolve(workspaceRoot, repoRef), workspaceRoot);
        }
    }
    if (searchBase && fs.existsSync(searchBase) && fs.statSync(searchBase).isDirectory()) {
        const targetFilename = path.basename(targetPath).toLowerCase();
        const findRecursive = (dir, depth = 0) => {
            if (depth > 8) return null;
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    if (['bin', 'obj', 'node_modules', '.git', '.gcac-runs'].includes(entry.name)) continue;
                    const full = path.join(dir, entry.name);
                    if (entry.isFile() && entry.name.toLowerCase() === targetFilename) {
                        return assertPathWithinAuthorizedRoots(full, roots)?.canonicalPath || null;
                    }
                    if (entry.isDirectory()) {
                        const res = findRecursive(full, depth + 1);
                        if (res) return res;
                    }
                }
            } catch (e) { }
            return null;
        };
        const found = findRecursive(searchBase, 0);
        if (found) return found;
    }

    return null;
}

/**
 * Canonical Copilot Chat remediation prompt builder (Block C).
 * Enforces SEC-02 fail-closed metadata validation and never emits empty scan arguments.
 */
const { fixtureReviewReason } = require('./findingSourceEvidence');

function buildCopilotRemediationPrompt(finding, csvPath = '', options = {}) {
    const authRoots = Array.isArray(options.authorizedRoots) && options.authorizedRoots.length > 0
        ? options.authorizedRoots
        : buildAuthorizedRoots();
    const activeReg = options.registry || registry;
    const ctxCheck = validateFindingContextContract(finding, {
        authorizedRoots: authRoots,
        registry: activeReg
    });

    if (!ctxCheck.valid) {
        return {
            ok: false,
            requiresMapping: ctxCheck.requiresMapping === true,
            reasonCode: ctxCheck.reasonCode,
            reason: ctxCheck.reason,
            finding
        };
    }

    const reason = fixtureReviewReason(ctxCheck.resolvedRepositoryPath, finding);
    if (reason) return { ok: false, reasonCode: 'FIXTURE_REVIEW', reason, finding };
    const ctx = ctxCheck.context;
    const isScanned = ctx.sourceOrigin === 'LocalScanner' || Boolean(ctx.scanExecutionId || ctx.scannerId);
    const hasCsv = !isScanned && Boolean(csvPath && String(csvPath).trim().length > 0);
    const scanArg = hasCsv
        ? String(csvPath).trim()
        : (ctx.scanExecutionId || ctx.scannerId || 'local-scan');
    const scannerMeta = ctx.scannerId ? `, scanner "${ctx.scannerId}"` : '';
    const query = `@vulnerability-orchestrator /remediate-vulnerability ${ctx.findingId} in repository "${ctx.repositoryPath}" using scan "${scanArg}" (application "${ctx.applicationId}"${scannerMeta})`;

    return {
        ok: true,
        query,
        context: ctx
    };
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

    if (!engine) {
        engine = new RemediationEngine(currentWorkspaceRoot, currentCsvPath, {
            extensionRoot: extensionRootPath,
            providerHost,
            publicationService: githubPublicationService(),
            findingsStore,
            reScanVerifier,
            registry,
            authorizedRoots: buildAuthorizedRoots()
        });
    }

    switch (message.command) {
        case 'getConfig': {
            syncAuthorizedRoots();
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            webview.postMessage(buildConfigPayload({ availableCsvs }));
            webview.postMessage({
                type: 'SANDBOX_STATUS_UPDATED',
                ...getSandboxUiSnapshot(currentWorkspaceRoot, engine?.executionGateway)
            });
            break;
        }

        case 'getSandboxStatus': {
            webview.postMessage({
                type: 'SANDBOX_STATUS_UPDATED',
                ...getSandboxUiSnapshot(currentWorkspaceRoot, engine?.executionGateway)
            });
            break;
        }

        case 'recoverSandboxInstances': {
            const rec = engine ? await engine.recoverOrphanedSandboxes() : { recovered: [] };
            webview.postMessage({
                type: 'SANDBOX_STATUS_UPDATED',
                ...getSandboxUiSnapshot(currentWorkspaceRoot, engine?.executionGateway),
                recoveredCount: rec.recovered?.length || 0
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
                const safeCsv = assertPathWithinAuthorizedRoots(uris[0].fsPath, buildAuthorizedRoots());
                if (safeCsv) {
                    currentCsvPath = safeCsv.canonicalPath;
                    engine.updatePaths(currentWorkspaceRoot, currentCsvPath);
                    const list = loadVulnerabilities(currentCsvPath);
                    const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                    broadcast(buildConfigPayload({ availableCsvs }));
                    broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                    vscode.window.showInformationMessage(`Loaded CSV: ${path.basename(currentCsvPath)}`);
                } else {
                    vscode.window.showErrorMessage('Security Warning: Selected CSV must reside within an authorized workspace or repository root.');
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
                const selectedRaw = uris[0].fsPath;
                if (vscode.workspace && !vscode.workspace.isTrusted && !assertPathWithinWorkspace(selectedRaw, currentWorkspaceRoot)) {
                    vscode.window.showErrorMessage('Restricted Mode: Grant Workspace Trust before authorizing external repositories.');
                    return;
                }
                const canonSelected = canonicalizePath(selectedRaw);
                if (!fs.existsSync(canonSelected) || !fs.statSync(canonSelected).isDirectory() || isSensitiveSystemOrCredentialRoot(canonSelected)) {
                    vscode.window.showErrorMessage('Blocked: Selected folder is invalid, inaccessible, or a restricted system/credential directory.');
                    return;
                }

                explicitExternalRoots.add(canonSelected);
                const repoInspection = inspectRepositoryTarget(canonSelected, currentWorkspaceRoot, registry);
                if (repoInspection.isUninitializedSubmodule) {
                    vscode.window.showWarningMessage('Selected folder is an uninitialized Git submodule / gitlink without checked-out source files.');
                } else if (registry && repoInspection.canonicalRepositoryPath) {
                    registry.resolveOrRegisterRepository(repoInspection.canonicalRepositoryPath);
                }
                activeRepoContext = repoInspection;
                currentScanTarget = assertPathWithinWorkspace(canonSelected, currentWorkspaceRoot)
                    ? (path.relative(currentWorkspaceRoot, canonSelected).replace(/\\/g, '/') || '.')
                    : canonSelected;
                syncAuthorizedRoots();

                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast({
                    type: 'TARGET_SELECTED',
                    targetPath: currentScanTarget,
                    canonicalPath: canonSelected,
                    isFolder: true,
                    displayName: path.basename(canonSelected) || 'Workspace',
                    repoContext: activeRepoContext
                });
                broadcast(buildConfigPayload({ availableCsvs }));
                vscode.window.showInformationMessage(`Active repository selected: ${canonSelected} (${activeRepoContext.detectedTechnology})`);
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
                const selectedFile = canonicalizePath(uris[0].fsPath);
                if (isSensitiveSystemOrCredentialRoot(selectedFile) || !fs.existsSync(selectedFile)) {
                    vscode.window.showErrorMessage('Blocked: Selected file is inaccessible or within a restricted directory.');
                    return;
                }
                const inWs = assertPathWithinWorkspace(selectedFile, currentWorkspaceRoot);
                if (!inWs && vscode.workspace && !vscode.workspace.isTrusted) {
                    vscode.window.showErrorMessage('Restricted Mode: Grant Workspace Trust before selecting external files.');
                    return;
                }
                const fileInspection = inspectRepositoryTarget(selectedFile, currentWorkspaceRoot, registry);
                const repoRootForFile = fileInspection.canonicalRepositoryPath || path.dirname(selectedFile);
                explicitExternalRoots.add(repoRootForFile);
                if (registry && !isSensitiveSystemOrCredentialRoot(repoRootForFile)) {
                    registry.resolveOrRegisterRepository(repoRootForFile);
                }
                activeRepoContext = fileInspection;
                currentScanTarget = inWs
                    ? path.relative(currentWorkspaceRoot, selectedFile).replace(/\\/g, '/')
                    : selectedFile;
                syncAuthorizedRoots();

                broadcast({
                    type: 'TARGET_SELECTED',
                    targetPath: currentScanTarget,
                    canonicalPath: selectedFile,
                    isFolder: false,
                    displayName: path.basename(selectedFile),
                    repoContext: activeRepoContext
                });
                broadcast(buildConfigPayload({}));
                vscode.window.showInformationMessage(`Target file selected: ${currentScanTarget}`);
            }
            break;
        }

        case 'selectScanTarget':
        case 'selectWorkspaceFolder': {
            const rawReq = message.folderPath !== undefined ? message.folderPath : message.targetPath;
            if (rawReq !== undefined) {
                const target = rawReq ? (path.isAbsolute(rawReq) ? rawReq : path.resolve(currentWorkspaceRoot, rawReq)) : currentWorkspaceRoot;
                const safeTarget = resolveAuthorizedTarget(target);
                if (safeTarget) {
                    const rel = assertPathWithinWorkspace(safeTarget, currentWorkspaceRoot)
                        ? (path.relative(currentWorkspaceRoot, safeTarget).replace(/\\/g, '/') || '.')
                        : canonicalizePath(safeTarget);
                    currentScanTarget = rel;
                    activeRepoContext = inspectRepositoryTarget(safeTarget, currentWorkspaceRoot, registry);
                    syncAuthorizedRoots();
                    const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                    broadcast({
                        type: 'TARGET_SELECTED',
                        targetPath: rel,
                        canonicalPath: safeTarget,
                        isFolder: fs.existsSync(safeTarget) && fs.statSync(safeTarget).isDirectory(),
                        displayName: path.basename(safeTarget) || 'Workspace',
                        repoContext: activeRepoContext
                    });
                    broadcast(buildConfigPayload({ availableCsvs }));
                } else {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: 'Blocked: Target path is outside authorized workspace and registered repository roots.',
                        status: 'error'
                    });
                }
            }
            break;
        }

        case 'clearScanResults': {
            hasUserInitiatedScan = false;
            currentCsvPath = '';
            currentScanTarget = '';
            activeRepoContext = null;
            if (findingsStore) {
                findingsStore.clearFindings();
            }
            broadcast({ type: 'DATA_UPDATED', vulnerabilities: [] });
            broadcast(buildConfigPayload({}));
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: 'Scan results cleared. Dashboard reset to 0.',
                status: 'info'
            });
            break;
        }

        case 'setCsvPath': {
            const safeMatch = assertPathWithinAuthorizedRoots(message.csvPath, buildAuthorizedRoots());
            if (safeMatch && fs.existsSync(safeMatch.canonicalPath)) {
                currentCsvPath = safeMatch.canonicalPath;
                engine.updatePaths(currentWorkspaceRoot, currentCsvPath);
                const list = loadVulnerabilities(currentCsvPath);
                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast(buildConfigPayload({ availableCsvs }));
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                vscode.window.showInformationMessage(`Switched CSV to: ${path.basename(currentCsvPath)}`);
            } else {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: CSV path must be within an authorized workspace or repository root.',
                    status: 'error'
                });
            }
            break;
        }

        case 'requestData':
        case 'refresh': {
            syncAuthorizedRoots();
            const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                : { includeHistorical: false };
            const list = (hasUserInitiatedScan || (currentCsvPath && fs.existsSync(currentCsvPath)))
                ? getCombinedFindings(currentCsvPath, findingsStore, repoFilter)
                : [];
            const preloaded = getPreloadedDetails(currentWorkspaceRoot, list);
            const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
            webview.postMessage(buildConfigPayload({ availableCsvs }));
            webview.postMessage({ type: 'INIT_DATA', vulnerabilities: list, preloadedDetails: preloaded });
            webview.postMessage({
                type: 'SANDBOX_STATUS_UPDATED',
                ...getSandboxUiSnapshot(currentWorkspaceRoot, engine?.executionGateway)
            });
            break;
        }

        case 'loadDetails': {
            let details = loadVulnerabilityDetails(currentWorkspaceRoot, message.vulnerabilityId);
            const combined = getCombinedFindings(currentCsvPath, findingsStore, { includeHistorical: true });
            const finding = combined.find(f => f.Vulnerability_ID === message.vulnerabilityId);

            if (!details || !details.hasEvidence) {
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
                            `- **Detection Method**: \`${finding.Detection_Method || 'LOCAL_SCAN'}\``,
                            `- **Originating Scanner**: \`${finding.Scanner_ID || 'N/A'}\` (Scan ID: \`${finding.Scan_ID || 'N/A'}\`)`,
                            `- **Application Identity**: \`${finding.Application_Number || 'UNMAPPED'}\``,
                            `- **Source Location**: \`${finding.Location_Path}:${finding.Line_Number || 1}\``,
                            `- **Repository**: \`${finding.Repository_Root || finding.Repository || 'UNMAPPED'}\``,
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
                        evidenceChecklist: buildEvidenceChecklist({ finding }),
                        timings: null
                    };
                }
            }

            if (details && engine) {
                const liveState = engine.loadRunState(message.vulnerabilityId);
                if (liveState) {
                    details.runState = liveState;
                    details.provider = liveState.provider;
                    details.runId = liveState.runId || details.runId || null;
                    details.attemptId = liveState.attemptId || details.attemptId || null;
                    details.attemptNumber = Number(liveState.attemptNumber || details.attemptNumber || 1);
                    details.retryCount = Number(liveState.retryCount ?? details.retryCount ?? 0);
                    details.attemptHistory = Array.isArray(liveState.attemptHistory) ? liveState.attemptHistory : (details.attemptHistory || []);
                    details.failedStage = liveState.failedStage ?? details.failedStage ?? null;
                    details.failedStageId = liveState.failedStageId || details.failedStageId || null;
                    details.failureCategory = liveState.failureCategory || details.failureCategory || null;
                    details.failureReason = liveState.failureReason || details.failureReason || null;
                    details.diagnostics = liveState.diagnostics || details.diagnostics || details.validation || null;
                    details.baselineValidation = details.baselineValidation || liveState.baselineValidation || null;
                    details.reScanVerification = details.reScanVerification || liveState.reScanVerification || null;
                    if (liveState.workflowLifecycle) details.workflowLifecycle = liveState.workflowLifecycle;
                    if (liveState.securityValidationOutcome) details.securityValidationOutcome = liveState.securityValidationOutcome;
                    if (liveState.approvalDecision) details.approvalDecision = liveState.approvalDecision;
                    if (liveState.formalClosure) details.formalClosure = liveState.formalClosure;
                    if (liveState.findingState) details.findingState = liveState.findingState;
                    if (liveState.terminalBanner) details.terminalBanner = liveState.terminalBanner;
                    if (liveState.handoff) details.handoff = liveState.handoff;
                    if (liveState.evidenceChecklist) details.evidenceChecklist = liveState.evidenceChecklist;
                }
                if (details && !details.evidenceChecklist) {
                    details.evidenceChecklist = buildEvidenceChecklist({
                        finding: finding || details.finding || { Vulnerability_ID: message.vulnerabilityId },
                        classification: details.classification,
                        validation: details.validation || details.diagnostics,
                        reScanVerification: details.reScanVerification,
                        patchDiff: details.patchDiff,
                        approvalRecord: details.approvalRecord,
                        securityReview: details.securityReview,
                        integrityVerification: details.integrityVerification
                    });
                }
                details.retryEligibility = engine.evaluateRetryEligibility(
                    liveState || message.vulnerabilityId,
                    {
                        finding,
                        workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true
                    }
                );
            }
            webview.postMessage({ type: 'DETAILS_LOADED', details });
            break;
        }

        case 'syncRunState': {
            if (!message.vulnerabilityId) return;
            const runMgr = new RunStateManager(currentWorkspaceRoot);
            const existing = runMgr.loadState(message.vulnerabilityId);
            if (existing && existing.handoff && existing.workflowLifecycle === 'HANDED_OFF_TO_COPILOT') {
                existing.handoff.lastSyncedAt = new Date().toISOString();
                runMgr.saveState(message.vulnerabilityId, existing);
            }
            await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: existing
                    ? `Synchronized state for ${message.vulnerabilityId}: ${existing.terminalBanner || existing.findingState || existing.status}`
                    : `No persisted run state yet for ${message.vulnerabilityId}.`,
                status: 'info'
            });
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
                syncAuthorizedRoots();
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Starting local vulnerability scan...',
                    status: 'info'
                });

                const requestedTarget = message.targetRepo || message.targetPath || currentScanTarget || currentWorkspaceRoot;
                const resolvedTarget = path.isAbsolute(requestedTarget)
                    ? requestedTarget
                    : path.resolve(currentWorkspaceRoot, requestedTarget);
                const targetPath = resolveAuthorizedTarget(resolvedTarget);
                if (!targetPath) {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Security Warning: Scan target '${requestedTarget}' is missing, restricted, or outside authorized repositories. Select a repository folder first.`,
                        status: 'error'
                    });
                    return;
                }
                const scanResult = await scanController.startScan({
                    scannerIds: message.scannerIds,
                    selectCandidateContext: async root => {
                        const selected = providerHost.selection();
                        if (selected.id === 'copilot') throw Error('Choose a direct inference provider for candidate review.');
                        const items = vscode.window.visibleTextEditors.filter(editor => !editor.selection.isEmpty &&
                            editor.document.uri.scheme === 'file' && !editor.document.isDirty &&
                            assertPathWithinWorkspace(editor.document.uri.fsPath,root)).map(editor => ({
                                label: path.relative(root,editor.document.uri.fsPath),
                                description: 'Lines ' + (editor.selection.start.line+1) + '–' + (editor.selection.end.line+1),
                                file:editor.document.uri.fsPath,start:editor.selection.start.line+1,end:editor.selection.end.line+1
                            }));
                        if (!items.length) throw Error('Select up to 60 lines in a saved source editor and use the Remediation sidebar.');
                        const item = await vscode.window.showQuickPick(items,{title:'Approve selected lines for ' + selected.id + ' · ' + selected.model});
                        if (item) return {...item,provider:selected.id,model:selected.model,client:providerHost.client(selected,root)};
                    },
                    approvePackages: async packages => (await vscode.window.showWarningMessage(
                        'Query api.osv.dev with these public npm package versions?', {modal:true,detail:packages.join('\n')}, 'Query OSV')) === 'Query OSV',
                    mode: message.scanMode || message.mode || 'comprehensive',
                    bypassCache: Boolean(message.bypassCache),
                    targetRepo: targetPath,
                    persistRegistration: true,
                    onProgress: (evt) => {
                        webview.postMessage({ type: 'SCAN_PROGRESS', event: evt });
                    }
                });

                hasUserInitiatedScan = true;
                activeRepoContext = scanResult.repositoryContext || scanResult.repoContext || inspectRepositoryTarget(targetPath, currentWorkspaceRoot, registry);
                currentScanTarget = assertPathWithinWorkspace(targetPath, currentWorkspaceRoot)
                    ? (path.relative(currentWorkspaceRoot, targetPath).replace(/\\/g, '/') || '.')
                    : canonicalizePath(targetPath);
                syncAuthorizedRoots();

                const availableCsvs = await getAvailableCsvFiles(currentWorkspaceRoot);
                broadcast(buildConfigPayload({ availableCsvs }));
                webview.postMessage({
                    type: 'SCAN_COMPLETED',
                    result: scanResult,
                    scanId: scanResult.scanId,
                    scanMode: scanResult.scanMode,
                    coverageDisclosure: scanResult.coverageDisclosure || '',
                    omittedScanners: scanResult.omittedScanners || [],
                    cancelled: Boolean(scanResult.cancelled),
                    timedOut: Boolean(scanResult.timedOut),
                    fromCache: Boolean(scanResult.fromCache),
                    cacheHits: scanResult.cacheHits || 0,
                    cacheMisses: scanResult.cacheMisses || 0,
                    findingsCount: scanResult.findingsSummary.total,
                    targetPath: targetPath,
                    repoContext: activeRepoContext,
                    status: scanResult.status,
                    unverifiedCoverage: Boolean(scanResult.unverifiedCoverage)
                });
                const combined = getCombinedFindings(currentCsvPath, findingsStore, {
                    repositoryRoot: activeRepoContext?.canonicalRepositoryPath || targetPath,
                    includeHistorical: false
                });
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: combined });

                if (scanResult.cancelled) {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Scan cancelled (${scanResult.scanId}). Coverage incomplete; child processes terminated.`,
                        status: 'warning'
                    });
                } else if (scanResult.status === 'No Scannable Inputs' || scanResult.status === 'Unsupported Repository') {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Scan skipped (${scanResult.status}): ${scanResult.unsupportedReason || 'No supported source/manifest inputs found in target repository.'}`,
                        status: 'warning'
                    });
                } else if (scanResult.errors && scanResult.errors.length > 0) {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Scan finished (${scanResult.scanMode || 'comprehensive'}) with ${scanResult.errors.length} scanner issue(s) — coverage incomplete. Findings: ${scanResult.findingsSummary.total}.`,
                        status: 'warning'
                    });
                } else {
                    const cacheTag = scanResult.cacheHits > 0 ? ` (${scanResult.cacheHits} cached, hash-verified)` : '';
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `${scanResult.scanMode === 'quick' ? 'Quick' : 'Comprehensive'} scan finished${cacheTag}: ${scanResult.findingsSummary.total} finding(s) (${scanResult.findingsSummary.critical} Critical, ${scanResult.findingsSummary.high} High).`,
                        status: scanResult.scanMode === 'quick' ? 'info' : 'success'
                    });
                }
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
            try {
                const { CodeQLScanner } = require('./scanning/adapters/codeqlScanner');
                const codeqlScanner = new CodeQLScanner();
                const avail = await codeqlScanner.isAvailable(currentWorkspaceRoot, extensionRootPath);
                const toolRoot = fs.existsSync(path.join(currentWorkspaceRoot, 'scripts', 'setup-codeql.js'))
                    ? currentWorkspaceRoot
                    : extensionRootPath;
                const localBinPath = path.join(toolRoot, 'tools', 'codeql',
                    process.platform === 'win32' ? 'codeql.exe' : 'codeql');
                const setupScriptPath = path.join(toolRoot, 'scripts', 'setup-codeql.js');
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
            const scriptCandidates = [
                assertPathWithinWorkspace(path.join(currentWorkspaceRoot, 'scripts', 'setup-codeql.js'), currentWorkspaceRoot),
                assertPathWithinWorkspace(path.join(extensionRootPath, 'scripts', 'setup-codeql.js'), extensionRootPath)
            ].filter(Boolean);
            const setupScript = scriptCandidates.find(p => fs.existsSync(p));
            if (!setupScript) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Security Warning: setup-codeql.js not found within active workspace or extension installation.',
                    status: 'error'
                });
                return;
            }
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

        case 'retryStage': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Retry blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                webview.postMessage({
                    type: 'RETRY_UNAVAILABLE',
                    vulnerabilityId: message.vulnerabilityId,
                    reasonCode: 'UNTRUSTED_WORKSPACE',
                    reason: 'Workspace is untrusted (Restricted Mode).'
                });
                return;
            }
            try {
                syncAuthorizedRoots();
                const workspaceTrusted = vscode?.workspace ? vscode.workspace.isTrusted !== false : true;
                const combinedAll = getCombinedFindings(currentCsvPath, findingsStore, { includeHistorical: true });
                const finding = combinedAll.find(f => f.Vulnerability_ID === message.vulnerabilityId) || null;
                const liveState = engine.loadRunState(message.vulnerabilityId);
                const eligibility = engine.evaluateRetryEligibility(liveState || message.vulnerabilityId, {
                    targetStage: Number.isInteger(message.fromStage) ? message.fromStage : undefined,
                    finding,
                    workspaceTrusted,
                    environmentRecovered: message.environmentRecovered === true ? true : undefined
                });

                if (!eligibility.retryEligible) {
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Retry unavailable (${eligibility.reasonCode}): ${eligibility.reason}`,
                        status: 'warning'
                    });
                    webview.postMessage({
                        type: 'RETRY_UNAVAILABLE',
                        vulnerabilityId: message.vulnerabilityId,
                        eligibility,
                        reasonCode: eligibility.reasonCode,
                        reason: eligibility.reason
                    });
                    await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
                    return;
                }

                await engine.retryStage(message.vulnerabilityId, message.fromStage ?? eligibility.recommendedStage, {
                    expectedRunId: message.runId || eligibility.runId || undefined,
                    workspaceTrusted,
                    authorizedRoots: buildAuthorizedRoots(),
                    environmentRecovered: message.environmentRecovered === true ? true : undefined,
                    onProgress: (event) => {
                        broadcast({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                    ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                    : { includeHistorical: false };
                const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
            } catch (err) {
                vscode.window.showErrorMessage(`Retry error: ${err.message}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Retry error: ${err.message}`,
                    status: 'error'
                });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
                webview.postMessage({ type: 'RETRY_UNAVAILABLE', vulnerabilityId: message.vulnerabilityId, reason: err.message });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'reviseFix': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Revise Fix blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: 'Workspace is untrusted (Restricted Mode).' });
                return;
            }
            try {
                syncAuthorizedRoots();
                await engine.reviseFix(message.vulnerabilityId, {
                    expectedRunId: message.runId || undefined,
                    developerNotes: message.developerNotes || '',
                    workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true,
                    authorizedRoots: buildAuthorizedRoots(),
                    onProgress: (event) => {
                        broadcast({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                    ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                    : { includeHistorical: false };
                const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
            } catch (err) {
                vscode.window.showErrorMessage(`Fix revision error: ${err.message}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Fix revision error: ${err.message}`,
                    status: 'error'
                });
                webview.postMessage({ type: 'REMEDIATION_ERROR', error: err.message });
            }
            break;
        }

        case 'mapFindingRepository': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('Restricted Mode: Cannot bind finding repository in untrusted workspace.');
                return;
            }
            const vulnId = message.vulnerabilityId;
            if (!vulnId) return;

            let chosenRepoPath = message.repositoryPath ? String(message.repositoryPath).trim() : '';
            if (!chosenRepoPath) {
                const uris = await vscode.window.showOpenDialog({
                    canSelectFiles: false,
                    canSelectFolders: true,
                    canSelectMany: false,
                    title: `Select Local Repository for Finding ${vulnId}`
                });
                if (!uris || uris.length === 0) return;
                chosenRepoPath = uris[0].fsPath;
            }

            const canonRepo = canonicalizePath(chosenRepoPath);
            if (!fs.existsSync(canonRepo) || !fs.statSync(canonRepo).isDirectory() || isSensitiveSystemOrCredentialRoot(canonRepo)) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Blocked: Repository path is missing or points to a restricted OS/credential folder.',
                    status: 'error'
                });
                return;
            }
            if (isUninitializedGitSubmodule(canonRepo, currentWorkspaceRoot)) {
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Blocked: Target directory is an uninitialized Git submodule / gitlink.',
                    status: 'error'
                });
                return;
            }

            explicitExternalRoots.add(canonRepo);
            const resolvedMeta = registry
                ? registry.resolveOrRegisterRepository(canonRepo, { explicitApplicationId: message.applicationNumber || '' })
                : null;
            syncAuthorizedRoots();

            const mappedAppId = resolvedMeta?.applicationNumber || '';
            const mappedCanonicalId = resolvedMeta?.canonicalRepositoryId || '';
            const mappedTech = resolvedMeta?.technology || undefined;

            let updated = false;
            if (findingsStore && findingsStore.getFindingById(vulnId)) {
                findingsStore.updateFindingMapping(vulnId, {
                    applicationNumber: mappedAppId,
                    applicationName: resolvedMeta?.applicationName || path.basename(canonRepo),
                    applicationIdentitySource: resolvedMeta?.identitySource || 'LOCAL_REGISTERED',
                    repository: canonRepo,
                    repositoryRoot: canonRepo,
                    canonicalRepositoryId: mappedCanonicalId,
                    technology: mappedTech
                });
                updated = true;
            } else if (currentCsvPath && fs.existsSync(currentCsvPath)) {
                updated = updateVulnerabilityRow(currentCsvPath, vulnId, {
                    Application_Number: mappedAppId,
                    Repository: canonRepo
                });
            }

            if (updated) {
                const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                    ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                    : { includeHistorical: false };
                const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                broadcast(buildConfigPayload({}));
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: vulnId }, webview);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `Mapped '${vulnId}' to repository '${canonRepo}' (Identity: ${mappedAppId}).`,
                    status: 'success'
                });
            }
            break;
        }

        case 'acknowledgeDevelopmentBaseline': {
            try {
                await acknowledgeLocalBaseline(message.vulnerabilityId, event => broadcast({ type: 'REMEDIATION_PROGRESS', event }));
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
            } catch (err) { webview.postMessage({ type: 'ACTION_FEEDBACK', text: err.message, status: 'error' }); }
            break;
        }

        case 'approveRemediation': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Remediation actions are disabled in Restricted Mode.');
                return;
            }

            try {
                syncAuthorizedRoots();
                const existingRunState = engine?.loadRunState ? engine.loadRunState(message.vulnerabilityId) : null;
                if (engine?.activeRuns?.has(message.vulnerabilityId)) {
                    webview.postMessage({ type: 'ACTION_FEEDBACK', text: 'This run is already executing. Approval was not submitted again.', status: 'info' });
                    return;
                }
                if (existingRunState?.approvalRecord?.consumedAtStage5 && existingRunState.patchAppliedAtStage5) {
                    webview.postMessage({ type: 'ACTION_FEEDBACK', text: 'Stage 4 was already applied. Review the current validation result or Stage 8 sign-off; the patch will not be applied again.', status: 'info' });
                    await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
                    return;
                }
                if (existingRunState && (existingRunState.workflowLifecycle === 'BLOCKED' || existingRunState.status === 'BLOCKED' || existingRunState.stages?.[2]?.status === 'blocked')) {
                    vscode.window.showErrorMessage(`GCAC: Approval blocked. Stage 3 baseline testing did not succeed for ${message.vulnerabilityId}.`);
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Approval blocked: Stage 3 baseline did not run or is blocked. Resolve prerequisites before approving.`,
                        status: 'error'
                    });
                    return;
                }
                if (!existingRunState || !existingRunState.proposedDiffSha256 || !existingRunState.patchDiff || !/^[a-f0-9]{64}$/i.test(existingRunState.proposedDiffSha256)) {
                    vscode.window.showErrorMessage(`GCAC: Approval blocked. No verified diff SHA-256 digest exists for ${message.vulnerabilityId}.`);
                    webview.postMessage({
                        type: 'ACTION_FEEDBACK',
                        text: `Approval blocked: No verified diff SHA-256 digest exists.`,
                        status: 'error'
                    });
                    return;
                }
                const localConsent = await requestLocalDiffConsent(message.vulnerabilityId);
                vscode.window.showInformationMessage(`Stage 4 Gate authorized for ${message.vulnerabilityId}. Executing genuine testing...`);
                await engine.executePipeline(message.vulnerabilityId, {
                    ...localConsent,
                    isHumanApproved: true,
                    isFinalApproved: false,
                    authorizedRoots: buildAuthorizedRoots(),
                    workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                    ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                    : { includeHistorical: false };
                const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
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
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
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
                syncAuthorizedRoots();
                vscode.window.showInformationMessage(`Final Gate authorized for ${message.vulnerabilityId}. Finalizing documentation...`);
                const publicationConsent = await requestPublicationConsent(message.vulnerabilityId);
                await engine.executePipeline(message.vulnerabilityId, {
                    ...publicationConsent,
                    isHumanApproved: true,
                    isFinalApproved: true,
                    authorizedRoots: buildAuthorizedRoots(),
                    workspaceTrusted: vscode?.workspace ? vscode.workspace.isTrusted !== false : true,
                    onProgress: (event) => {
                        webview.postMessage({ type: 'REMEDIATION_PROGRESS', event });
                    }
                });
                const repoFilter = (hasUserInitiatedScan && activeRepoContext?.canonicalRepositoryPath)
                    ? { repositoryRoot: activeRepoContext.canonicalRepositoryPath, includeHistorical: false }
                    : { includeHistorical: false };
                const list = getCombinedFindings(currentCsvPath, findingsStore, repoFilter);
                broadcast({ type: 'DATA_UPDATED', vulnerabilities: list });
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
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
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: message.vulnerabilityId }, webview);
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
            const authRoots = buildAuthorizedRoots();
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path, authRoots);
            const safeMatch = fullPath ? assertPathWithinAuthorizedRoots(fullPath, authRoots) : null;
            const safePath = safeMatch ? safeMatch.canonicalPath : null;

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
                vscode.window.showWarningMessage(`Source file not found or outside authorized repositories: ${message.path || 'Unknown'}`);
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: `File not found or outside authorized repository boundary: ${message.path || 'Unknown'}`,
                    status: 'warning'
                });
            }
            break;
        }

        case 'getSourceCode': {
            const authRoots = buildAuthorizedRoots();
            const fullPath = resolveSourceFilePath(currentWorkspaceRoot, message.repository, message.path, authRoots);
            const safeMatch = fullPath ? assertPathWithinAuthorizedRoots(fullPath, authRoots) : null;
            const safePath = safeMatch ? safeMatch.canonicalPath : null;

            if (safePath && fs.existsSync(safePath)) {
                try {
                    const code = fs.readFileSync(safePath, 'utf-8');
                    webview.postMessage({
                        type: 'SOURCE_CODE_LOADED',
                        filePath: safePath,
                        relativePath: path.relative(safeMatch.authorizedRoot || currentWorkspaceRoot, safePath),
                        code: code,
                        targetLine: parseInt(message.line, 10) || 1
                    });
                } catch (e) {
                    webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: e.message });
                }
            } else {
                webview.postMessage({ type: 'SOURCE_CODE_ERROR', error: 'File not found or outside authorized repository boundary' });
            }
            break;
        }

        case 'providerStatus': {
            if (!vscode.workspace.isTrusted) return;
            const status = await providerHost.status(resolveAuthorizedTarget(currentScanTarget || currentWorkspaceRoot));
            webview.postMessage({ type:'PROVIDER_STATUS', status });
            break;
        }
        case 'configureProvider': {
            if (!vscode.workspace.isTrusted) return;
            try {
                await providerHost.configure(resolveAuthorizedTarget(currentScanTarget || currentWorkspaceRoot));
                broadcast(buildConfigPayload());
            } catch (error) { webview.postMessage({ type: 'ACTION_FEEDBACK', text: error.message, status: 'error' }); }
            break;
        }
        case 'runProvider':
        case 'launchCopilot': {
            if (vscode.workspace && !vscode.workspace.isTrusted) {
                vscode.window.showErrorMessage('GCAC: Copilot agent invocation is disabled in Restricted Mode. Please trust this workspace.');
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: 'Action blocked: Workspace is untrusted (Restricted Mode).',
                    status: 'error'
                });
                return;
            }

            syncAuthorizedRoots();
            const findings = getCombinedFindings(currentCsvPath, findingsStore, { includeHistorical: true });
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

            if (finding.Source_Classification === 'AI_CANDIDATE' || finding.Is_Historical === 'true') {
                webview.postMessage({type:'ACTION_FEEDBACK',text:'Remediation requires a current, independently confirmed finding.',status:'warning'}); return;
            }
            const promptRes = buildCopilotRemediationPrompt(finding, currentCsvPath, {
                authorizedRoots: buildAuthorizedRoots(),
                registry
            });

            if (!promptRes.ok) {
                if (vscode.window && typeof vscode.window.showWarningMessage === 'function') {
                    vscode.window.showWarningMessage(promptRes.reason);
                }
                if (promptRes.requiresMapping) webview.postMessage({
                    type: 'REPOSITORY_MAPPING_REQUIRED',
                    vulnerabilityId: finding.Vulnerability_ID,
                    reasonCode: promptRes.reasonCode,
                    reason: promptRes.reason,
                    finding
                });
                webview.postMessage({
                    type: 'ACTION_FEEDBACK',
                    text: promptRes.reason,
                    status: 'warning'
                });
                return;
            }

            if (message.command === 'runProvider') {
                try {
                    const provider = providerHost.selection();
                    if (provider.id === 'copilot') throw Error('Select a direct inference provider first.');
                    await engine.executePipeline(finding.Vulnerability_ID, {
                        provider, workspaceTrusted: vscode.workspace.isTrusted, authorizedRoots: buildAuthorizedRoots(),
                        onProgress: event => broadcast({ type: 'REMEDIATION_PROGRESS', event })
                    });
                } catch (error) { webview.postMessage({ type: 'ACTION_FEEDBACK', text: error.message, status: 'error' }); }
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: finding.Vulnerability_ID }, webview);
                break;
            }
            const query = promptRes.query;
            try {
                await require('./providers/copilot').copilot.handoff(vscode.commands, query);
            } catch (e) {
                webview.postMessage({ type: 'ACTION_FEEDBACK', text: 'Could not open Copilot Chat.', status: 'error' });
                return;
            }

            let handoffRes = null;
            try {
                const runMgr = new RunStateManager(currentWorkspaceRoot);
                handoffRes = runMgr.recordCopilotHandoff(finding.Vulnerability_ID, {
                    repositoryId: finding.canonicalRepositoryId || promptRes.context?.canonicalRepositoryId || '',
                    queryIssued: true
                });
            } catch (e) {
                console.warn('Could not persist Copilot handoff state:', e.message);
            }

            if (handoffRes?.state) {
                await handleWebviewMessage({ command: 'loadDetails', vulnerabilityId: finding.Vulnerability_ID }, webview);
            }

            webview.postMessage({
                type: 'COPILOT_LAUNCHED',
                prompt: query,
                vulnerabilityId: finding.Vulnerability_ID,
                title: finding.Title,
                findingContext: promptRes.context,
                handoffState: handoffRes?.state?.handoff || { state: 'HANDED_OFF_TO_COPILOT', displayState: 'AWAITING_VERIFIED_RESULT' },
                runId: handoffRes?.state?.runId || null,
                workflowLifecycle: handoffRes?.state?.workflowLifecycle || 'HANDED_OFF_TO_COPILOT',
                findingState: handoffRes?.state?.findingState || 'AWAITING_VERIFIED_RESULT',
                manualSubmissionRequired: true
            });
            webview.postMessage({
                type: 'ACTION_FEEDBACK',
                text: `Copilot Chat opened (${finding.Vulnerability_ID}): State set to Awaiting Verified Result until @vulnerability-orchestrator executes.`,
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
            const authRoots = buildAuthorizedRoots();
            const safeMatch = assertPathWithinAuthorizedRoots(reportPath, authRoots);
            const safePath = safeMatch ? safeMatch.canonicalPath : null;
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
                    text: 'Security Warning: Report path must be within an authorized workspace or repository root.',
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
    resolveSourceFilePath,
    buildCopilotRemediationPrompt,
    ALLOWED_IPC_COMMANDS
};
