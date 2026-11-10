/**
 * GCAC Vulnerability Remediation Hub — Modern Enterprise SaaS Controller
 * Minimal • SaaS Aesthetic • Local-First • 7-Stage Governance
 */
(function () {
    // --------------------------------------------------------------------------
    // Pure Data Aggregators & CSP-Safe CSSOM Style Application
    // --------------------------------------------------------------------------
    function applyDynamicStyles(root) {
        if (!root || typeof root.querySelectorAll !== 'function') return;
        root.querySelectorAll('[data-bar-width]').forEach(el => {
            el.style.width = el.getAttribute('data-bar-width');
        });
    }

    function aggregateActivityTrend(data) {
        if (!Array.isArray(data) || data.length === 0) {
            return { labels: [], totalCounts: [], remediatedCounts: [] };
        }

        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const buckets = new Map();

        for (const item of data) {
            const rawDate = item.Finding_Date || item.Timestamp || '';
            const parsed = rawDate ? new Date(rawDate) : null;
            let key = '9999-99';
            let label = 'Undated';

            if (parsed && !Number.isNaN(parsed.getTime())) {
                const yyyy = parsed.getUTCFullYear();
                const mm = String(parsed.getUTCMonth() + 1).padStart(2, '0');
                key = `${yyyy}-${mm}`;
                label = `${monthNames[parsed.getUTCMonth()]} ${String(yyyy).slice(-2)}`;
            }

            if (!buckets.has(key)) {
                buckets.set(key, { key, label, total: 0, remediated: 0 });
            }
            const bucket = buckets.get(key);
            bucket.total += 1;
            if ((item.Remediation_Status || '').toLowerCase() === 'remediated') {
                bucket.remediated += 1;
            }
        }

        const ordered = Array.from(buckets.values()).sort((a, b) => a.key.localeCompare(b.key)).slice(-6);
        return {
            labels: ordered.map(b => b.label),
            totalCounts: ordered.map(b => b.total),
            remediatedCounts: ordered.map(b => b.remediated)
        };
    }

    function computeStatusBreakdown(data) {
        const list = Array.isArray(data) ? data : [];
        return {
            remediated: list.filter(v => (v.Remediation_Status || '').toLowerCase() === 'remediated').length,
            approved: list.filter(v => (v.Remediation_Status || '').toLowerCase() === 'approved').length,
            review: list.filter(v => (v.Requires_Human_Review || '').toLowerCase() === 'true' || (v.Remediation_Status || '').toLowerCase().includes('review')).length,
            inProgress: list.filter(v => (v.Remediation_Status || '').toLowerCase().includes('progress')).length,
            pending: list.filter(v => (v.Remediation_Status || '').toLowerCase() === 'pending').length
        };
    }

    function aggregateStageDurations(detailsList) {
        const acc = {
            analysis: { sum: 0, count: 0 },
            remediation: { sum: 0, count: 0 },
            approvalWait: { sum: 0, count: 0 },
            test: { sum: 0, count: 0 },
            validation: { sum: 0, count: 0 }
        };

        for (const det of (detailsList || [])) {
            const t = det && det.timings;
            if (!t) continue;
            if (typeof t.analysisDurationSec === 'number') { acc.analysis.sum += t.analysisDurationSec; acc.analysis.count++; }
            if (typeof t.remediationDurationSec === 'number') { acc.remediation.sum += t.remediationDurationSec; acc.remediation.count++; }
            if (typeof t.approvalWaitDurationSec === 'number') { acc.approvalWait.sum += t.approvalWaitDurationSec; acc.approvalWait.count++; }
            if (typeof t.testDurationSec === 'number') { acc.test.sum += t.testDurationSec; acc.test.count++; }
            if (typeof t.validationDurationSec === 'number') { acc.validation.sum += t.validationDurationSec; acc.validation.count++; }
        }

        const avg = (slot) => slot.count > 0 ? parseFloat((slot.sum / slot.count).toFixed(2)) : null;
        const stages = [
            { label: 'Code Analysis', duration: avg(acc.analysis), colorClass: 'legend-bg-info' },
            { label: 'Remediation', duration: avg(acc.remediation), colorClass: 'legend-bg-warning' },
            { label: 'Human Gate', duration: avg(acc.approvalWait), colorClass: 'legend-bg-stage4' },
            { label: 'Bench Test', duration: avg(acc.test), colorClass: 'legend-bg-success' },
            { label: 'Final Validation', duration: avg(acc.validation), colorClass: 'legend-bg-stage6' }
        ];
        const hasData = stages.some(s => s.duration !== null);
        return { hasData, stages };
    }

    function normalizeScanProgressEvent(data) {
        if (!data || typeof data !== 'object') return null;
        const evt = (data.event && typeof data.event === 'object') ? data.event : data;

        let percent = evt.percent;
        if (percent === undefined || percent === null) {
            if (typeof evt.totalScanners === 'number' && evt.totalScanners > 0 && typeof evt.progressIndex === 'number') {
                percent = Math.round((evt.progressIndex / evt.totalScanners) * 100);
            } else if (evt.type === 'SCAN_FINISHED') {
                percent = 100;
            } else if (evt.type === 'SCAN_STARTED') {
                percent = 5;
            }
        }
        if (typeof percent === 'number') {
            percent = Math.min(100, Math.max(5, percent));
        }

        let message = evt.message;
        if (!message) {
            if (evt.type === 'SCAN_STARTED') {
                message = 'Starting local security scan...';
            } else if (evt.type === 'SCANNER_START') {
                message = `Running ${evt.scannerName || evt.scannerId || 'scanner'}...`;
            } else if (evt.type === 'SCANNER_COMPLETE') {
                message = `Completed ${evt.scannerName || evt.scannerId || 'scanner'} (${evt.findingsCount ?? 0} findings)`;
            } else if (evt.type === 'SCAN_FINISHED') {
                message = `Scan complete (${evt.findingsCount ?? 0} total findings)`;
            }
        }

        return { percent, message };
    }

    function formatScanHistoryEntry(item) {
        const rawTime = item.timestamp || item.startTime;
        const parsedTime = rawTime ? new Date(rawTime) : null;
        const dateStr = (parsedTime && !Number.isNaN(parsedTime.getTime())) ? parsedTime.toLocaleTimeString() : '--';
        const rawTarget = item.targetPath || item.targetDir || '';
        const targetBase = rawTarget ? (rawTarget.split(/[/\\]/).filter(Boolean).pop() || 'workspace') : 'workspace';
        const durationSec = item.durationMs ? `${(item.durationMs / 1000).toFixed(1)}s` : '--';
        const counts = item.findingsSummary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const status = item.status || 'Completed';

        return {
            scanId: item.scanId || '--',
            dateStr,
            targetBase,
            durationSec,
            status,
            counts
        };
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            aggregateActivityTrend,
            computeStatusBreakdown,
            aggregateStageDurations,
            normalizeScanProgressEvent,
            formatScanHistoryEntry
        };
    }

    if (typeof document === 'undefined') {
        return;
    }

    // Acquire VS Code API or mock fallback for standalone preview
    let vscode = null;
    try {
        if (typeof acquireVsCodeApi === 'function') {
            vscode = acquireVsCodeApi();
        }
    } catch (e) {
        console.log('Running outside VS Code extension host');
    }

    // Application State
    let allVulnerabilities = [];
    let selectedVulnerability = null;
    let currentDetails = null;
    let currentReports = [];
    let selectedReport = null;
    let currentActiveView = 'dashboard';
    let currentTheme = 'auto';
    let isRemediating = false;
    let activeQuickFilter = 'ALL';
    let tableSortColumn = 'id';
    let tableSortAsc = true;

    // Active Target Configuration State
    let currentConfig = {
        activeRepo: '',
        activeCsv: '',
        availableCsvs: []
    };

    // Cache of loaded details for accurate metrics calculation
    const detailsCache = new Map();

    // View Titles Dictionary
    const viewTitles = {
        'dashboard': {
            title: 'Vulnerability Dashboard',
            sub: 'Real-time overview of remediation activity and security posture.'
        },
        'vulnerabilities': {
            title: 'Vulnerabilities',
            sub: 'Monitor, remediate and validate security findings.'
        },
        'active-runs': {
            title: 'Active Remediation Pipeline',
            sub: 'Real-time status of 7-stage autonomous execution & verification.'
        },
        'review-queue': {
            title: 'Human Review Queue',
            sub: 'Actionable governance gates awaiting developer authorization.'
        },
        'reports': {
            title: 'Audit Reports & Evidence Store',
            sub: 'Shared Markdown reports, patch artifacts, and independent validation outputs.'
        },
        'scans': {
            title: 'Local Security Scanners',
            sub: 'Run authorized local static analyzers, secret detectors, and dependency audit checks.'
        },
        'settings': {
            title: 'Workspace Settings',
            sub: 'Local repository bounding, theme configuration, and security policy verification.'
        }
    };

    // DOM Elements - App Shell & Nav
    const appShell = document.getElementById('appShell');
    const appSidebar = document.getElementById('appSidebar');
    const btnToggleSidebar = document.getElementById('btnToggleSidebar');
    const btnMobileMenu = document.getElementById('btnMobileMenu');
    const navItems = document.querySelectorAll('.nav-item');
    const appViews = document.querySelectorAll('.app-view');
    const navCountVulns = document.getElementById('navCountVulns');
    const navCountReview = document.getElementById('navCountReview');
    const navActiveRunPulse = document.getElementById('navActiveRunPulse');

    // DOM Elements - Header
    const pageTitle = document.getElementById('pageTitle');
    const pageSubtitle = document.getElementById('pageSubtitle');
    const globalSearchInput = document.getElementById('globalSearchInput');
    const btnGlobalSearchClear = document.getElementById('btnGlobalSearchClear');
    const headerRunIndicator = document.getElementById('headerRunIndicator');
    const headerRunText = document.getElementById('headerRunText');
    const btnHeaderRefresh = document.getElementById('btnHeaderRefresh');
    const themeSwitcher = document.getElementById('themeSwitcher');
    const btnThemeToggle = document.getElementById('btnThemeToggle');
    const themeDropdown = document.getElementById('themeDropdown');
    const themeCurrentIcon = document.getElementById('themeCurrentIcon');
    const themeCurrentLabel = document.getElementById('themeCurrentLabel');
    const btnHeaderQuickRun = document.getElementById('btnHeaderQuickRun');

    // DOM Elements - Target Context
    const displayRepoName = document.getElementById('displayRepoName');
    const btnBrowseRepo = document.getElementById('btnBrowseRepo');
    const selectTargetCsv = document.getElementById('selectTargetCsv');
    const btnBrowseCsv = document.getElementById('btnBrowseCsv');
    const targetContextStatusText = document.getElementById('targetContextStatusText');

    // DOM Elements - Dashboard View
    const dashFilterApp = document.getElementById('dashFilterApp');
    const dashFilterSeverity = document.getElementById('dashFilterSeverity');
    const dashFilterStatus = document.getElementById('dashFilterStatus');
    const btnResetDashFilters = document.getElementById('btnResetDashFilters');

    const dashKpiTotal = document.getElementById('dashKpiTotal');
    const dashKpiCritical = document.getElementById('dashKpiCritical');
    const dashKpiInProgress = document.getElementById('dashKpiInProgress');
    const dashKpiRemediated = document.getElementById('dashKpiRemediated');
    const dashKpiReview = document.getElementById('dashKpiReview');
    const dashKpiSuccessRate = document.getElementById('dashKpiSuccessRate');
    const dashKpiAvgDuration = document.getElementById('dashKpiAvgDuration');

    const timeMetricAnalysis = document.getElementById('timeMetricAnalysis');
    const timeMetricRemediation = document.getElementById('timeMetricRemediation');
    const timeMetricTest = document.getElementById('timeMetricTest');
    const timeMetricApproval = document.getElementById('timeMetricApproval');

    const qualityMetricFirstPass = document.getElementById('qualityMetricFirstPass');
    const qualityMetricTestPass = document.getElementById('qualityMetricTestPass');
    const qualityMetricValidation = document.getElementById('qualityMetricValidation');
    const qualityMetricRetries = document.getElementById('qualityMetricRetries');

    const chartCategoryContainer = document.getElementById('chartCategoryContainer');
    const chartSeverityContainer = document.getElementById('chartSeverityContainer');
    const chartStatusContainer = document.getElementById('chartStatusContainer');
    const chartStageDurationContainer = document.getElementById('chartStageDurationContainer');

    const dashPendingCount = document.getElementById('dashPendingCount');
    const dashPendingReviewsList = document.getElementById('dashPendingReviewsList');
    const dashRecentRunsCount = document.getElementById('dashRecentRunsCount');
    const dashRecentRunsList = document.getElementById('dashRecentRunsList');
    const btnGoToReviewQueue = document.getElementById('btnGoToReviewQueue');
    const btnGoToVulnerabilities = document.getElementById('btnGoToVulnerabilities');

    // DOM Elements - Vulnerabilities View
    const miniKpiTotal = document.getElementById('miniKpiTotal');
    const miniKpiCritical = document.getElementById('miniKpiCritical');
    const miniKpiReview = document.getElementById('miniKpiReview');
    const miniKpiRemediated = document.getElementById('miniKpiRemediated');
    const miniKpiChips = document.querySelectorAll('.mini-kpi-chip');

    const vulnWorkspaceLayout = document.getElementById('vulnWorkspaceLayout');
    const tableVulnCounter = document.getElementById('tableVulnCounter');
    const filterChips = document.querySelectorAll('.filter-chips-row .chip');
    const tableSearchInput = document.getElementById('tableSearchInput');
    const btnTableClearSearch = document.getElementById('btnTableClearSearch');
    const tableSeverityFilter = document.getElementById('tableSeverityFilter');
    const tableStatusFilter = document.getElementById('tableStatusFilter');
    const tableRepoFilter = document.getElementById('tableRepoFilter');
    const vulnTableBody = document.getElementById('vulnTableBody');
    const tableSortHeaders = document.querySelectorAll('.vuln-table th.sortable');

    // DOM Elements - Inspector Drawer
    const detailPanel = document.getElementById('detailPanel');
    const btnCloseDetail = document.getElementById('btnCloseDetail');
    const detailId = document.getElementById('detailId');
    const detailTitle = document.getElementById('detailTitle');
    const detailCve = document.getElementById('detailCve');
    const detailSeverity = document.getElementById('detailSeverity');
    const detailApp = document.getElementById('detailApp');
    const detailRepo = document.getElementById('detailRepo');
    const detailTech = document.getElementById('detailTech');
    const detailSla = document.getElementById('detailSla');
    const detailLocation = document.getElementById('detailLocation');
    const detailGuidance = document.getElementById('detailGuidance');

    const btnLaunchCopilot = document.getElementById('btnLaunchCopilot');
    const btnRunRemediation = document.getElementById('btnRunRemediation');
    const btnRunRemediationText = document.getElementById('btnRunRemediationText');
    const btnOpenLocation = document.getElementById('btnOpenLocation');
    const btnViewCodeModal = document.getElementById('btnViewCodeModal');

    const pipelineStepper = document.getElementById('pipelineStepper');
    const pipelineOverallStatus = document.getElementById('pipelineOverallStatus');

    const humanGateCard = document.getElementById('humanGateCard');
    const btnApprove = document.getElementById('btnApprove');
    const btnReject = document.getElementById('btnReject');
    const btnRejectFinalSubtle = document.getElementById('btnRejectFinalSubtle');
    const gate4PatchSummary = document.getElementById('gate4PatchSummary');

    const finalGateCard = document.getElementById('finalGateCard');
    const btnFinalApprove = document.getElementById('btnFinalApprove');
    const btnFinalReject = document.getElementById('btnFinalReject');

    const failureRecoveryCard = document.getElementById('failureRecoveryCard');
    const failureStageTitle = document.getElementById('failureStageTitle');
    const failureSummaryText = document.getElementById('failureSummaryText');
    const btnRetryStage = document.getElementById('btnRetryStage');
    const btnReviewDiffFromFailure = document.getElementById('btnReviewDiffFromFailure');

    const evidenceTabBtns = document.querySelectorAll('.evidence-tabs-header .tab-btn');
    const evidenceTabPanes = document.querySelectorAll('.evidence-tab-panes .tab-pane');
    const reportContent = document.getElementById('reportContent');
    const diffContent = document.getElementById('diffContent');
    const diffSummaryBar = document.getElementById('diffSummaryBar');
    const diffStatFile = document.getElementById('diffStatFile');
    const diffStatAdd = document.getElementById('diffStatAdd');
    const diffStatDel = document.getElementById('diffStatDel');
    const btnCopyDiff = document.getElementById('btnCopyDiff');
    const btnOpenNativeDiff = document.getElementById('btnOpenNativeDiff');
    const valContent = document.getElementById('valContent');
    const traceContent = document.getElementById('traceContent');
    const btnCopyTrace = document.getElementById('btnCopyTrace');

    // DOM Elements - Active Runs View
    const activeRunStatusPill = document.getElementById('activeRunStatusPill');
    const activeRunsStepper = document.getElementById('activeRunsStepper');
    const activeRunsTerminal = document.getElementById('activeRunsTerminal');
    const btnClearTerminal = document.getElementById('btnClearTerminal');
    const activeRunVulnTitle = document.getElementById('activeRunVulnTitle');
    const activeRunVulnSubtitle = document.getElementById('activeRunVulnSubtitle');
    const activeRunSummaryId = document.getElementById('activeRunSummaryId');
    const activeRunSummaryStage = document.getElementById('activeRunSummaryStage');
    const activeRunSummaryFiles = document.getElementById('activeRunSummaryFiles');
    const activeRunSummaryTests = document.getElementById('activeRunSummaryTests');
    const activeRunSummaryRetries = document.getElementById('activeRunSummaryRetries');
    const activeRunSummaryStatus = document.getElementById('activeRunSummaryStatus');

    // DOM Elements - Review Queue View
    const queueTotalBadge = document.getElementById('queueTotalBadge');
    const reviewQueueCardsList = document.getElementById('reviewQueueCardsList');

    // DOM Elements - Reports View
    const reportsSearchInput = document.getElementById('reportsSearchInput');
    const reportsItemsList = document.getElementById('reportsItemsList');
    const reportViewerTitle = document.getElementById('reportViewerTitle');
    const reportViewerBody = document.getElementById('reportViewerBody');
    const btnCopyReportMarkdown = document.getElementById('btnCopyReportMarkdown');

    // DOM Elements - Scans View & Controls
    const btnHeaderScan = document.getElementById('btnHeaderScan');
    const tableSourceFilter = document.getElementById('tableSourceFilter');
    const btnStartScan = document.getElementById('btnStartScan');
    const btnCancelScan = document.getElementById('btnCancelScan');
    const scanProgressCard = document.getElementById('scanProgressCard');
    const scanProgressText = document.getElementById('scanProgressText');
    const scanProgressTimer = document.getElementById('scanProgressTimer');
    const scanProgressBarFill = document.getElementById('scanProgressBarFill');
    const scannersCardsGrid = document.getElementById('scannersCardsGrid');
    const chkScanSecrets = document.getElementById('chkScanSecrets');
    const chkScanDotnet = document.getElementById('chkScanDotnet');
    const chkScanNuget = document.getElementById('chkScanNuget');
    const chkScanCodeql = document.getElementById('chkScanCodeql');
    const scanHistoryTableBody = document.getElementById('scanHistoryTableBody');
    let scanTimerInterval = null;
    let scanStartTime = 0;

    // DOM Elements - CodeQL Status Panel
    const codeqlStatusBadge    = document.getElementById('codeqlStatusBadge');
    const codeqlStatusText     = document.getElementById('codeqlStatusText');
    const codeqlInstallGuide   = document.getElementById('codeqlInstallGuide');
    const codeqlInstalledInfo  = document.getElementById('codeqlInstalledInfo');
    const codeqlVersionDisplay = document.getElementById('codeqlVersionDisplay');
    const codeqlBinaryDisplay  = document.getElementById('codeqlBinaryDisplay');
    const codeqlInstallCmd     = document.getElementById('codeqlInstallCmd');
    const btnRefreshCodeqlStatus   = document.getElementById('btnRefreshCodeqlStatus');
    const btnInstallCodeql         = document.getElementById('btnInstallCodeql');
    const btnCopyCodeqlInstallCmd  = document.getElementById('btnCopyCodeqlInstallCmd');

    // DOM Elements - Target Selection & Scan Chooser
    const dashZeroStateBanner = document.getElementById('dashZeroStateBanner');
    const btnDashScanNow = document.getElementById('btnDashScanNow');
    const selectScanPreset = document.getElementById('selectScanPreset');
    const btnChooseFolder = document.getElementById('btnChooseFolder');
    const btnChooseFile = document.getElementById('btnChooseFile');
    const inputScanTargetPath = document.getElementById('inputScanTargetPath');
    const btnClearScanTarget = document.getElementById('btnClearScanTarget');
    const selectedTargetBadge = document.getElementById('selectedTargetBadge');
    const btnResetScanToZero = document.getElementById('btnResetScanToZero');
    const targetPickerModal = document.getElementById('targetPickerModal');
    const btnTargetPickerClose = document.getElementById('btnTargetPickerClose');
    const targetPickerSearch = document.getElementById('targetPickerSearch');
    const targetPickerList = document.getElementById('targetPickerList');

    // DOM Elements - Settings View
    const settingsRepoVal = document.getElementById('settingsRepoVal');
    const settingsCsvVal = document.getElementById('settingsCsvVal');
    const btnSettingsBrowseRepo = document.getElementById('btnSettingsBrowseRepo');
    const btnSettingsBrowseCsv = document.getElementById('btnSettingsBrowseCsv');
    const settingsThemeRadios = document.querySelectorAll('input[name="settingsTheme"]');

    // DOM Elements - Modals & Toast
    const codeModal = document.getElementById('codeModal');
    const btnModalClose = document.getElementById('btnModalClose');
    const modalFileName = document.getElementById('modalFileName');
    const modalFileLine = document.getElementById('modalFileLine');
    const modalCodeContainer = document.getElementById('modalCodeContainer');

    const copilotModal = document.getElementById('copilotModal');
    const btnCopilotModalClose = document.getElementById('btnCopilotModalClose');
    const copilotCommandText = document.getElementById('copilotCommandText');
    const btnCopyCopilotCommand = document.getElementById('btnCopyCopilotCommand');
    const toastContainer = document.getElementById('toastContainer');

    // --------------------------------------------------------------------------
    // Initializer
    // --------------------------------------------------------------------------
    function init() {
        initTheme();
        setupEventListeners();
        setupMessageListener();

        // Load initial config and data from extension host
        postToHost({ command: 'getConfig' });
        postToHost({ command: 'requestData' });
        postToHost({ command: 'loadReports' });
    }

    function postToHost(msg) {
        if (vscode) {
            vscode.postMessage(msg);
        } else {
            console.log('IPC Outbound:', msg);
        }
    }

    // --------------------------------------------------------------------------
    // Theme System (Light, Dark, Follow VS Code - Default: Follow VS Code)
    // --------------------------------------------------------------------------
    function initTheme() {
        const savedTheme = localStorage.getItem('gcac-theme') || 'auto';
        setTheme(savedTheme);
    }

    function setTheme(theme) {
        currentTheme = theme;
        localStorage.setItem('gcac-theme', theme);

        let effectiveTheme = 'light';
        if (theme === 'auto') {
            const isVsCodeDark = document.body.classList.contains('vscode-dark') || document.body.classList.contains('vscode-high-contrast');
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            effectiveTheme = (isVsCodeDark || prefersDark) ? 'dark' : 'light';
        } else {
            effectiveTheme = theme;
        }

        document.documentElement.setAttribute('data-theme', effectiveTheme);
        document.body.className = effectiveTheme === 'dark' ? 'theme-dark' : 'theme-light';

        // Update header switcher UI
        if (themeCurrentIcon && themeCurrentLabel) {
            if (theme === 'dark') {
                themeCurrentIcon.textContent = '🌙';
                themeCurrentLabel.textContent = 'Dark';
            } else if (theme === 'light') {
                themeCurrentIcon.textContent = '☀️';
                themeCurrentLabel.textContent = 'Light';
            } else {
                themeCurrentIcon.textContent = '💻';
                themeCurrentLabel.textContent = 'VS Code';
            }
        }

        // Update settings radios
        settingsThemeRadios.forEach(radio => {
            radio.checked = (radio.value === theme);
        });

        // Re-render charts with new theme colors
        if (allVulnerabilities.length > 0) {
            renderDashboardCharts();
        }
    }

    // --------------------------------------------------------------------------
    // Navigation & View Switching
    // --------------------------------------------------------------------------
    function switchView(viewId) {
        currentActiveView = viewId;

        // Update Nav items active state
        navItems.forEach(item => {
            const itemTarget = item.getAttribute('data-view');
            item.classList.toggle('active', itemTarget === viewId);
        });

        // Update Header Titles
        if (pageTitle && pageSubtitle && viewTitles[viewId]) {
            pageTitle.textContent = viewTitles[viewId].title;
            pageSubtitle.textContent = viewTitles[viewId].sub;
        }

        // Update Views display
        appViews.forEach(view => {
            const target = view.getAttribute('data-view-id');
            const isActive = target === viewId;
            view.classList.toggle('active', isActive);
            if (isActive) {
                onViewActivated(viewId);
            }
        });
    }

    function onViewActivated(viewId) {
        if (viewId === 'dashboard') {
            renderDashboardMetrics();
            renderDashboardCharts();
        } else if (viewId === 'vulnerabilities') {
            renderTable();
        } else if (viewId === 'active-runs') {
            if (selectedVulnerability) {
                updateActiveRunView(selectedVulnerability);
            }
        } else if (viewId === 'review-queue') {
            renderReviewQueueView();
        } else if (viewId === 'reports') {
            postToHost({ command: 'loadReports' });
        } else if (viewId === 'scans') {
            postToHost({ command: 'getScanners' });
            postToHost({ command: 'getScanHistory' });
            postToHost({ command: 'getCodeqlStatus' });
        }
    }

    // --------------------------------------------------------------------------
    // Event Listeners Setup
    // --------------------------------------------------------------------------
    function setupEventListeners() {
        // Sidebar Navigation clicks
        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const targetView = item.getAttribute('data-view');
                if (targetView) switchView(targetView);
                appSidebar.classList.remove('expanded');
                appSidebar.classList.remove('mobile-open');
            });
        });

        // Sidebar collapse & rail expand toggle
        function toggleSidebarRail() {
            if (appSidebar.classList.contains('expanded')) {
                appSidebar.classList.remove('expanded');
                appSidebar.classList.add('collapsed');
            } else {
                appSidebar.classList.remove('collapsed');
                appSidebar.classList.add('expanded');
            }
        }

        if (btnToggleSidebar) {
            btnToggleSidebar.addEventListener('click', toggleSidebarRail);
        }

        // Header rail toggle button
        if (btnMobileMenu) {
            btnMobileMenu.addEventListener('click', toggleSidebarRail);
        }

        // Header Theme Toggle
        if (btnThemeToggle && themeDropdown) {
            btnThemeToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                themeDropdown.classList.toggle('show');
            });

            document.querySelectorAll('.theme-opt').forEach(opt => {
                opt.addEventListener('click', () => {
                    const val = opt.getAttribute('data-theme-val');
                    setTheme(val);
                    themeDropdown.classList.remove('show');
                });
            });

            window.addEventListener('click', (e) => {
                if (!themeSwitcher.contains(e.target)) {
                    themeDropdown.classList.remove('show');
                }
            });
        }

        // Settings Theme radio buttons
        settingsThemeRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                if (radio.checked) setTheme(radio.value);
            });
        });

        // Header Refresh button
        if (btnHeaderRefresh) {
            btnHeaderRefresh.addEventListener('click', () => {
                btnHeaderRefresh.classList.add('rotating');
                postToHost({ command: 'refresh' });
                postToHost({ command: 'loadReports' });
                if (selectedVulnerability) {
                    postToHost({ command: 'loadDetails', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
                }
                setTimeout(() => btnHeaderRefresh.classList.remove('rotating'), 600);
            });
        }

        // Header Quick Run CTA
        if (btnHeaderQuickRun) {
            btnHeaderQuickRun.addEventListener('click', () => {
                if (selectedVulnerability) {
                    startRemediation(selectedVulnerability.Vulnerability_ID);
                } else if (allVulnerabilities.length > 0) {
                    const firstTarget = allVulnerabilities.find(v => (v.Severity || '').toUpperCase() === 'CRITICAL') || allVulnerabilities[0];
                    switchView('vulnerabilities');
                    selectVulnerability(firstTarget, true);
                    startRemediation(firstTarget.Vulnerability_ID);
                }
            });
        }

        // Header Scan CTA
        if (btnHeaderScan) {
            btnHeaderScan.addEventListener('click', () => {
                switchView('scans');
            });
        }

        // Dashboard Zero State Call-to-Action
        if (btnDashScanNow) {
            btnDashScanNow.addEventListener('click', () => {
                switchView('scans');
            });
        }

        // Target Selection & File Chooser Controls
        if (selectScanPreset) {
            selectScanPreset.addEventListener('change', () => {
                const val = selectScanPreset.value;
                if (inputScanTargetPath) inputScanTargetPath.value = val;
                updateSelectedTargetDisplay(val, true);
                postToHost({ command: 'selectScanTarget', targetPath: val });
            });
        }

        if (btnChooseFolder) {
            btnChooseFolder.addEventListener('click', () => {
                postToHost({ command: 'selectRepo' });
            });
        }

        if (btnChooseFile) {
            btnChooseFile.addEventListener('click', () => {
                postToHost({ command: 'selectFile' });
            });
        }

        if (btnClearScanTarget) {
            btnClearScanTarget.addEventListener('click', () => {
                if (inputScanTargetPath) inputScanTargetPath.value = '';
                if (selectScanPreset) selectScanPreset.value = '';
                updateSelectedTargetDisplay('', false);
                postToHost({ command: 'selectScanTarget', targetPath: '' });
                showToast('Target cleared. Will scan workspace root if run.', 'info');
            });
        }

        if (inputScanTargetPath) {
            inputScanTargetPath.addEventListener('change', () => {
                const val = inputScanTargetPath.value.trim();
                updateSelectedTargetDisplay(val, false);
                postToHost({ command: 'selectScanTarget', targetPath: val });
            });
        }

        if (btnResetScanToZero) {
            btnResetScanToZero.addEventListener('click', () => {
                postToHost({ command: 'clearScanResults' });
            });
        }

        if (btnTargetPickerClose) {
            btnTargetPickerClose.addEventListener('click', () => {
                closeTargetPickerModal();
            });
        }

        if (targetPickerSearch) {
            targetPickerSearch.addEventListener('input', () => {
                const q = targetPickerSearch.value.toLowerCase().trim();
                if (targetPickerList) {
                    targetPickerList.querySelectorAll('.dash-list-item').forEach(el => {
                        const txt = el.textContent.toLowerCase();
                        el.style.display = txt.includes(q) ? 'flex' : 'none';
                    });
                }
            });
        }

        // Scans View Execution Controls
        if (btnStartScan) {
            btnStartScan.addEventListener('click', () => {
                triggerScanExecution();
            });
        }

        if (btnCancelScan) {
            btnCancelScan.addEventListener('click', () => {
                postToHost({ command: 'cancelScan' });
                showToast('Cancelling vulnerability scan...', 'warning');
            });
        }

        // ── CodeQL Status Panel ──────────────────────────────────────────────
        if (btnRefreshCodeqlStatus) {
            btnRefreshCodeqlStatus.addEventListener('click', () => {
                if (codeqlStatusBadge) { codeqlStatusBadge.className = 'badge badge-secondary'; codeqlStatusBadge.textContent = 'Checking...'; }
                if (codeqlStatusText) codeqlStatusText.textContent = 'Re-checking CodeQL CLI status...';
                postToHost({ command: 'getCodeqlStatus' });
            });
        }
        if (btnInstallCodeql) {
            btnInstallCodeql.addEventListener('click', () => {
                postToHost({ command: 'installCodeql' });
                showToast('CodeQL install initiated — check the terminal for progress.', 'info');
            });
        }
        if (btnCopyCodeqlInstallCmd) {
            btnCopyCodeqlInstallCmd.addEventListener('click', () => {
                const cmd = codeqlInstallCmd ? codeqlInstallCmd.textContent : 'node scripts/setup-codeql.js';
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(cmd).then(() => showToast('Install command copied to clipboard', 'success'));
                }
            });
        }

        // Global Search
        if (globalSearchInput) {
            globalSearchInput.addEventListener('input', () => {
                const query = globalSearchInput.value.trim();
                if (btnGlobalSearchClear) btnGlobalSearchClear.classList.toggle('visible', query.length > 0);
                if (currentActiveView !== 'vulnerabilities') {
                    switchView('vulnerabilities');
                }
                if (tableSearchInput) {
                    tableSearchInput.value = query;
                    renderTable();
                }
            });
        }

        if (btnGlobalSearchClear) {
            btnGlobalSearchClear.addEventListener('click', () => {
                globalSearchInput.value = '';
                btnGlobalSearchClear.classList.remove('visible');
                if (tableSearchInput) tableSearchInput.value = '';
                renderTable();
            });
        }

        // Dashboard Filters
        if (dashFilterApp) dashFilterApp.addEventListener('change', () => { renderDashboardMetrics(); renderDashboardCharts(); });
        if (dashFilterSeverity) dashFilterSeverity.addEventListener('change', () => { renderDashboardMetrics(); renderDashboardCharts(); });
        if (dashFilterStatus) dashFilterStatus.addEventListener('change', () => { renderDashboardMetrics(); renderDashboardCharts(); });
        if (btnResetDashFilters) {
            btnResetDashFilters.addEventListener('click', () => {
                if (dashFilterApp) dashFilterApp.value = 'ALL';
                if (dashFilterSeverity) dashFilterSeverity.value = 'ALL';
                if (dashFilterStatus) dashFilterStatus.value = 'ALL';
                renderDashboardMetrics();
                renderDashboardCharts();
            });
        }

        if (btnGoToReviewQueue) btnGoToReviewQueue.addEventListener('click', () => switchView('review-queue'));
        if (btnGoToVulnerabilities) btnGoToVulnerabilities.addEventListener('click', () => switchView('vulnerabilities'));

        // Mini KPI Chips in Vulnerabilities view
        miniKpiChips.forEach(chip => {
            chip.addEventListener('click', () => {
                const filter = chip.getAttribute('data-quick-filter');
                applyQuickFilter(filter);
            });
        });

        // Filter Chips in Table
        filterChips.forEach(chip => {
            chip.addEventListener('click', () => {
                const filter = chip.getAttribute('data-chip');
                applyQuickFilter(filter);
            });
        });

        // Table Search & Select Filters
        if (tableSearchInput) {
            tableSearchInput.addEventListener('input', () => {
                if (btnTableClearSearch) btnTableClearSearch.classList.toggle('visible', tableSearchInput.value.length > 0);
                renderTable();
            });
        }

        if (btnTableClearSearch) {
            btnTableClearSearch.addEventListener('click', () => {
                tableSearchInput.value = '';
                btnTableClearSearch.classList.remove('visible');
                renderTable();
            });
        }

        if (tableSeverityFilter) tableSeverityFilter.addEventListener('change', renderTable);
        if (tableStatusFilter) tableStatusFilter.addEventListener('change', renderTable);
        if (tableRepoFilter) tableRepoFilter.addEventListener('change', renderTable);
        if (tableSourceFilter) tableSourceFilter.addEventListener('change', renderTable);

        // Table Sortable Headers
        tableSortHeaders.forEach(th => {
            th.addEventListener('click', () => {
                const col = th.getAttribute('data-sort');
                if (tableSortColumn === col) {
                    tableSortAsc = !tableSortAsc;
                } else {
                    tableSortColumn = col;
                    tableSortAsc = true;
                }
                renderTable();
            });
        });

        // Detail Panel Close
        if (btnCloseDetail) {
            btnCloseDetail.addEventListener('click', () => {
                detailPanel.classList.remove('visible');
                vulnWorkspaceLayout.classList.remove('with-detail');
                document.querySelectorAll('.vuln-row').forEach(r => r.classList.remove('active'));
                selectedVulnerability = null;
            });
        }

        // Action Buttons in Inspector
        if (btnLaunchCopilot) {
            btnLaunchCopilot.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'launchCopilot',
                    vulnerabilityId: selectedVulnerability.Vulnerability_ID,
                    title: selectedVulnerability.Title,
                    repository: selectedVulnerability.Repository
                });
            });
        }

        if (btnRunRemediation) {
            btnRunRemediation.addEventListener('click', () => {
                if (!selectedVulnerability || isRemediating) return;
                startRemediation(selectedVulnerability.Vulnerability_ID);
            });
        }

        if (btnOpenLocation) {
            btnOpenLocation.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'openLocation',
                    repository: selectedVulnerability.Repository,
                    path: selectedVulnerability.Location_Path,
                    line: selectedVulnerability.Line_Number
                });
            });
        }

        if (btnViewCodeModal) {
            btnViewCodeModal.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'getSourceCode',
                    repository: selectedVulnerability.Repository,
                    path: selectedVulnerability.Location_Path,
                    line: selectedVulnerability.Line_Number
                });
            });
        }

        // Stage 4 Human Gate Actions
        if (btnApprove) {
            btnApprove.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({ command: 'approveRemediation', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
            });
        }

        if (btnReject) {
            btnReject.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({ command: 'rejectRemediation', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
            });
        }

        if (btnRejectFinalSubtle) {
            btnRejectFinalSubtle.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({ command: 'rejectRemediation', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
            });
        }

        // Stage 6 Final Gate Actions
        if (btnFinalApprove) {
            btnFinalApprove.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({ command: 'approveFinalGate', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
            });
        }

        if (btnFinalReject) {
            btnFinalReject.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({ command: 'rejectFinalGate', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
            });
        }

        // Failure Recovery Actions
        if (btnRetryStage) {
            btnRetryStage.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                startRemediation(selectedVulnerability.Vulnerability_ID);
            });
        }

        if (btnReviewDiffFromFailure) {
            btnReviewDiffFromFailure.addEventListener('click', () => {
                switchEvidenceTab('diff');
            });
        }

        // Evidence Workspace Tab Buttons
        evidenceTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.getAttribute('data-tab');
                switchEvidenceTab(targetTab);
            });
        });

        // Copy Buttons
        if (btnCopyDiff) {
            btnCopyDiff.addEventListener('click', () => {
                if (currentDetails && currentDetails.patchDiff) {
                    navigator.clipboard.writeText(currentDetails.patchDiff).then(() => {
                        showToast('Patch diff copied to clipboard', 'success');
                    });
                }
            });
        }

        if (btnOpenNativeDiff) {
            btnOpenNativeDiff.addEventListener('click', () => {
                if (selectedVulnerability) {
                    postToHost({
                        command: 'viewDiff',
                        vulnerabilityId: selectedVulnerability.Vulnerability_ID
                    });
                } else {
                    showToast('Please select a vulnerability first', 'warning');
                }
            });
        }

        if (btnCopyTrace) {
            btnCopyTrace.addEventListener('click', () => {
                if (currentDetails && currentDetails.traceLog) {
                    navigator.clipboard.writeText(currentDetails.traceLog).then(() => {
                        showToast('Execution trace log copied', 'success');
                    });
                }
            });
        }

        if (btnClearTerminal) {
            btnClearTerminal.addEventListener('click', () => {
                if (activeRunsTerminal) {
                    activeRunsTerminal.innerHTML = '<div class="log-entry"><span class="log-ts">[SYSTEM]</span><span class="log-msg">Terminal output cleared.</span></div>';
                }
            });
        }

        if (btnCopyReportMarkdown) {
            btnCopyReportMarkdown.addEventListener('click', () => {
                if (selectedReport && selectedReport.content) {
                    navigator.clipboard.writeText(selectedReport.content).then(() => {
                        showToast('Report markdown copied', 'success');
                    });
                }
            });
        }

        // Reports Search
        if (reportsSearchInput) {
            reportsSearchInput.addEventListener('input', () => {
                renderReportsList();
            });
        }

        // Modal Close Handlers
        if (btnModalClose) {
            btnModalClose.addEventListener('click', () => { codeModal.style.display = 'none'; });
        }
        if (btnCopilotModalClose) {
            btnCopilotModalClose.addEventListener('click', () => { copilotModal.style.display = 'none'; });
        }
        if (btnCopyCopilotCommand) {
            btnCopyCopilotCommand.addEventListener('click', () => {
                if (copilotCommandText) {
                    navigator.clipboard.writeText(copilotCommandText.textContent).then(() => {
                        showToast('Copilot prompt copied', 'success');
                    });
                }
            });
        }

        // Target Context Bar & Settings Handlers
        if (btnBrowseRepo) {
            btnBrowseRepo.addEventListener('click', () => postToHost({ command: 'selectRepo' }));
        }
        if (btnSettingsBrowseRepo) {
            btnSettingsBrowseRepo.addEventListener('click', () => postToHost({ command: 'selectRepo' }));
        }
        if (btnBrowseCsv) {
            btnBrowseCsv.addEventListener('click', () => postToHost({ command: 'selectCsv' }));
        }
        if (btnSettingsBrowseCsv) {
            btnSettingsBrowseCsv.addEventListener('click', () => postToHost({ command: 'selectCsv' }));
        }
        if (selectTargetCsv) {
            selectTargetCsv.addEventListener('change', () => {
                const val = selectTargetCsv.value;
                if (val) {
                    postToHost({ command: 'setCsvPath', csvPath: val });
                }
            });
        }

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (codeModal) codeModal.style.display = 'none';
                if (copilotModal) copilotModal.style.display = 'none';
            }
        });
    }

    // --------------------------------------------------------------------------
    // IPC Message Listener
    // --------------------------------------------------------------------------
    function setupMessageListener() {
        window.addEventListener('message', (event) => {
            const message = event.data;
            if (!message) return;

            switch (message.type) {
                case 'CONFIG_UPDATED':
                    currentConfig = {
                        activeRepo: message.activeRepo || '',
                        activeCsv: message.activeCsv || '',
                        availableCsvs: message.availableCsvs || []
                    };
                    renderConfigContext();
                    break;

                case 'INIT_DATA':
                case 'DATA_UPDATED':
                    allVulnerabilities = message.vulnerabilities || [];
                    if (message.preloadedDetails && Array.isArray(message.preloadedDetails)) {
                        message.preloadedDetails.forEach(det => {
                            if (det && det.vulnerabilityId) {
                                detailsCache.set(det.vulnerabilityId, det);
                            }
                        });
                    }
                    updateFilterDropdowns();
                    renderDashboardMetrics();
                    renderDashboardCharts();
                    renderTable();
                    renderReviewQueueView();

                    // If a finding was selected, refresh its details
                    if (selectedVulnerability) {
                        const updated = allVulnerabilities.find(v => v.Vulnerability_ID === selectedVulnerability.Vulnerability_ID);
                        if (updated) {
                            selectVulnerability(updated, true);
                        }
                    }

                    if (message.updatedFile) {
                        showToast(`Live Sync: Updated from ${message.updatedFile}`, 'info');
                    }
                    break;

                case 'DETAILS_LOADED':
                    currentDetails = message.details;
                    if (currentDetails && currentDetails.vulnerabilityId) {
                        detailsCache.set(currentDetails.vulnerabilityId, currentDetails);
                    }
                    renderInspectorDetails(currentDetails);
                    renderDashboardMetrics();
                    break;

                case 'REPORTS_LOADED':
                    currentReports = message.reports || [];
                    renderReportsList();
                    break;

                case 'REPORT_CONTENT_LOADED':
                    selectedReport = message;
                    if (reportViewerTitle) reportViewerTitle.textContent = message.fileName;
                    if (reportViewerBody) reportViewerBody.innerHTML = renderMarkdown(message.content);
                    break;

                case 'REMEDIATION_PROGRESS':
                    handleRemediationProgress(message.event);
                    break;

                case 'SOURCE_CODE_LOADED':
                    renderSourceCodeModal(message);
                    break;

                case 'SOURCE_CODE_ERROR':
                    showToast(message.error || 'Failed to locate source file', 'warning');
                    break;

                case 'COPILOT_LAUNCHED':
                    openCopilotModal(message.prompt, message.manualSubmissionRequired !== false);
                    break;

                case 'ACTION_FEEDBACK':
                    showToast(message.text, message.status || 'info');
                    break;

                case 'REMEDIATION_ERROR':
                    isRemediating = false;
                    if (headerRunIndicator) headerRunIndicator.style.display = 'none';
                    if (navActiveRunPulse) navActiveRunPulse.style.display = 'none';
                    if (btnRunRemediationText) btnRunRemediationText.textContent = 'Execute Engine';
                    showToast(message.error || 'Remediation pipeline error', 'error');
                    break;

                case 'TARGET_SELECTED':
                    if (inputScanTargetPath) inputScanTargetPath.value = message.targetPath || '';
                    if (selectScanPreset && message.targetPath) {
                        selectScanPreset.value = message.targetPath;
                    }
                    updateSelectedTargetDisplay(message.targetPath, message.isFolder);
                    break;

                case 'SHOW_TARGET_PICKER':
                    openTargetPickerModal(message.targets, message.mode);
                    break;

                case 'SCANNERS_LOADED':
                    renderScannersCards(message.scanners);
                    break;

                case 'CODEQL_STATUS':
                    handleCodeqlStatus(message);
                    break;

                case 'SCAN_HISTORY_LOADED':
                    renderScanHistory(message.history);
                    break;

                case 'SCAN_PROGRESS':
                    handleScanProgress(message);
                    break;

                case 'SCAN_COMPLETED':
                    handleScanCompleted(message);
                    break;

                case 'SCAN_ERROR':
                    handleScanError(message);
                    break;
            }
        });
    }

    // --------------------------------------------------------------------------
    // Target Context & Workspace Configuration
    // --------------------------------------------------------------------------
    function renderConfigContext() {
        const repoBaseName = currentConfig.activeRepo ? currentConfig.activeRepo.split(/[/\\]/).filter(Boolean).pop() : 'Not Set';
        const csvBaseName = currentConfig.activeCsv ? currentConfig.activeCsv.split(/[/\\]/).filter(Boolean).pop() : 'Not Set';

        if (displayRepoName) {
            displayRepoName.textContent = repoBaseName;
            displayRepoName.title = currentConfig.activeRepo || 'No repository selected';
        }
        if (settingsRepoVal) {
            settingsRepoVal.textContent = currentConfig.activeRepo || 'No repository selected';
        }
        if (settingsCsvVal) {
            settingsCsvVal.textContent = currentConfig.activeCsv || 'No CSV selected';
        }

        if (selectTargetCsv) {
            const list = currentConfig.availableCsvs || [];
            let html = '';
            if (list.length === 0 && currentConfig.activeCsv) {
                html += `<option value="${escapeHtml(currentConfig.activeCsv)}" selected>${escapeHtml(csvBaseName)}</option>`;
            } else {
                list.forEach(c => {
                    const isSelected = c.fsPath === currentConfig.activeCsv;
                    html += `<option value="${escapeHtml(c.fsPath)}" ${isSelected ? 'selected' : ''}>${escapeHtml(c.relPath || c.name)}</option>`;
                });
            }
            selectTargetCsv.innerHTML = html;
        }

        if (targetContextStatusText) {
            targetContextStatusText.textContent = repoBaseName !== 'Not Set' && csvBaseName !== 'Not Set'
                ? `Bounded: ${repoBaseName}`
                : 'Configure Target';
        }
    }

    // --------------------------------------------------------------------------
    // Live Remediation Execution Tracking
    // --------------------------------------------------------------------------
    function startRemediation(vulnerabilityId) {
        isRemediating = true;

        // Update header & buttons
        if (headerRunIndicator) headerRunIndicator.style.display = 'flex';
        if (headerRunText) headerRunText.textContent = `Remediating ${vulnerabilityId}...`;
        if (navActiveRunPulse) navActiveRunPulse.style.display = 'block';

        if (btnRunRemediationText) btnRunRemediationText.textContent = 'Executing...';

        // Update active run view
        const target = allVulnerabilities.find(v => v.Vulnerability_ID === vulnerabilityId);
        if (target) updateActiveRunView(target);

        // Switch to terminal tab in inspector
        switchEvidenceTab('trace');
        appendTerminalLog('DISCOVERY', `Initiating 7-stage autonomous pipeline for ${vulnerabilityId}...`);

        postToHost({ command: 'runRemediation', vulnerabilityId });
    }

    function handleRemediationProgress(evt) {
        if (!evt) return;

        switch (evt.type) {
            case 'STAGE_START':
                setStageStatus(evt.stageNumber - 1, 'in_progress', `Stage ${evt.stageNumber} executing...`);
                if (headerRunText) headerRunText.textContent = `Stage ${evt.stageNumber} Active (${evt.stageId})`;
                if (btnRunRemediationText) btnRunRemediationText.textContent = `Stage ${evt.stageNumber}...`;
                if (activeRunSummaryStage) activeRunSummaryStage.textContent = `Stage ${evt.stageNumber} (${evt.stageId})`;
                break;

            case 'STAGE_COMPLETE':
                setStageStatus(evt.stageNumber - 1, 'completed', evt.summary);
                if (evt.patchDiff && currentDetails) {
                    currentDetails.patchDiff = evt.patchDiff;
                    renderDiffView(evt.patchDiff);
                }
                if (evt.validation && currentDetails) {
                    currentDetails.validation = evt.validation;
                    renderTestEvidenceView(currentDetails);
                }
                break;

            case 'LOG':
                appendTerminalLog(evt.tag, evt.message);
                break;

            case 'GATE_REQUIRED':
                isRemediating = false;
                if (headerRunIndicator) headerRunIndicator.style.display = 'flex';
                if (headerRunText) headerRunText.textContent = 'Awaiting Gate 4 Approval';
                if (btnRunRemediationText) btnRunRemediationText.textContent = 'Awaiting Gate 4';
                if (activeRunSummaryStage) activeRunSummaryStage.textContent = 'Stage 4 (Human Review Gate)';
                setStageStatus(3, 'awaiting_review', 'Paused at Stage 4: Human Review & Proposed Fix Authorization.');
                if (humanGateCard) humanGateCard.style.display = 'flex';
                showToast(`Stage 4 Governance Gate: Authorization required for ${evt.vulnerabilityId}`, 'warning');
                break;

            case 'FINAL_GATE_REQUIRED':
                isRemediating = false;
                if (headerRunIndicator) headerRunIndicator.style.display = 'flex';
                if (headerRunText) headerRunText.textContent = 'Awaiting Gate 6 Sign-off';
                if (btnRunRemediationText) btnRunRemediationText.textContent = 'Awaiting Gate 6';
                if (activeRunSummaryStage) activeRunSummaryStage.textContent = 'Stage 6 (Final Sign-off Gate)';
                setStageStatus(5, 'awaiting_review', 'Paused at Stage 6: Final Human Approval Gate.');
                if (finalGateCard) finalGateCard.style.display = 'flex';
                showToast(`Stage 6 Final Gate: Sign-off required for ${evt.vulnerabilityId}`, 'info');
                break;

            case 'WORKFLOW_COMPLETE':
                isRemediating = false;
                if (headerRunIndicator) headerRunIndicator.style.display = 'none';
                if (navActiveRunPulse) navActiveRunPulse.style.display = 'none';
                if (btnRunRemediationText) btnRunRemediationText.textContent = '✓ Remediated';
                if (activeRunSummaryStage) activeRunSummaryStage.textContent = 'Completed (Ready for CI/CD)';
                if (activeRunSummaryStatus) activeRunSummaryStatus.textContent = 'Remediated';
                setStageStatus(6, 'completed', 'Ready for Application Owner CI/CD Deployment.');
                showToast(`Remediation pipeline completed for ${evt.vulnerabilityId}!`, 'success');
                postToHost({ command: 'requestData' });
                postToHost({ command: 'loadReports' });
                if (selectedVulnerability) {
                    postToHost({ command: 'loadDetails', vulnerabilityId: selectedVulnerability.Vulnerability_ID });
                }
                break;
        }
    }

    function setStageStatus(stageIdx, status, summary) {
        if (!currentDetails || !currentDetails.stages || !currentDetails.stages[stageIdx]) return;
        currentDetails.stages[stageIdx].status = status;
        if (summary) currentDetails.stages[stageIdx].summary = summary;
        renderInspectorDetails(currentDetails);
    }

    function appendTerminalLog(tag, msg) {
        const now = new Date().toISOString().replace('T', ' ').substring(11, 19);
        const tagClass = tag ? `log-tag ${escapeHtml(tag)}` : '';
        const entryHtml = `
            <div class="log-entry">
                <span class="log-ts">[${now}]</span>
                ${tag ? `<span class="${tagClass}">${escapeHtml(tag)}</span>` : ''}
                <span class="log-msg">${escapeHtml(msg)}</span>
            </div>
        `;

        // Append to Inspector trace log
        const inspectorTrace = document.getElementById('traceContent');
        if (inspectorTrace) {
            let term = inspectorTrace.querySelector('.log-terminal');
            if (!term) {
                inspectorTrace.innerHTML = '<div class="log-terminal"></div>';
                term = inspectorTrace.querySelector('.log-terminal');
            }
            term.insertAdjacentHTML('beforeend', entryHtml);
            term.scrollTop = term.scrollHeight;
        }

        // Append to Active Runs dedicated terminal
        if (activeRunsTerminal) {
            activeRunsTerminal.insertAdjacentHTML('beforeend', entryHtml);
            activeRunsTerminal.scrollTop = activeRunsTerminal.scrollHeight;
        }
    }

    // --------------------------------------------------------------------------
    // Dashboard Analytics & Real Local KPI Calculations
    // --------------------------------------------------------------------------
    function getDashboardFilteredData() {
        const app = dashFilterApp?.value || 'ALL';
        const sev = dashFilterSeverity?.value || 'ALL';
        const st = dashFilterStatus?.value || 'ALL';

        return allVulnerabilities.filter(v => {
            if (app !== 'ALL' && v.Application_Name !== app) return false;
            if (sev !== 'ALL' && (v.Severity || '').toUpperCase() !== sev) return false;
            if (st !== 'ALL') {
                const status = (v.Remediation_Status || 'Pending').toUpperCase();
                if (st === 'REMEDIATED' && status !== 'REMEDIATED') return false;
                if (st === 'APPROVED' && status !== 'APPROVED') return false;
                if (st === 'REVIEW' && (v.Requires_Human_Review || '').toLowerCase() !== 'true' && status !== 'AWAITING HUMAN REVIEW') return false;
                if (st === 'PENDING' && status !== 'PENDING') return false;
            }
            return true;
        });
    }

    function renderDashboardMetrics() {
        const data = getDashboardFilteredData();
        const total = data.length;

        // Count metrics accurately from local data
        const critical = data.filter(v => (v.Severity || '').toUpperCase() === 'CRITICAL').length;
        const remediated = data.filter(v => (v.Remediation_Status || '').toLowerCase() === 'remediated').length;
        const review = data.filter(v => (v.Requires_Human_Review || '').toLowerCase() === 'true' || (v.Remediation_Status || '').toLowerCase().includes('review')).length;
        const inProgress = data.filter(v => (v.Remediation_Status || '').toLowerCase().includes('progress')).length;
        const failed = data.filter(v => {
            const st = (v.Remediation_Status || '').toLowerCase();
            return st.includes('fail') || st === 'rejected';
        }).length;

        // KPI values
        if (dashKpiTotal) dashKpiTotal.textContent = total;
        if (dashKpiCritical) dashKpiCritical.textContent = critical;
        if (dashKpiInProgress) dashKpiInProgress.textContent = inProgress;
        if (dashKpiRemediated) dashKpiRemediated.textContent = remediated;
        if (dashKpiReview) dashKpiReview.textContent = review;

        // Success rate: computed strictly on completed attempts
        const completedRuns = remediated + failed;
        if (completedRuns > 0) {
            const rate = Math.round((remediated / completedRuns) * 100);
            if (dashKpiSuccessRate) dashKpiSuccessRate.textContent = `${rate}%`;
        } else {
            if (dashKpiSuccessRate) dashKpiSuccessRate.textContent = total === 0 ? '0%' : 'N/A';
        }

        // Timing metrics from detailsCache or reports
        let totalDurationSum = 0;
        let analysisDurationSum = 0;
        let remediationDurationSum = 0;
        let testDurationSum = 0;
        let approvalWaitSum = 0;

        let totalDurationCount = 0;
        let analysisDurationCount = 0;
        let remediationDurationCount = 0;
        let testDurationCount = 0;
        let approvalWaitCount = 0;

        detailsCache.forEach(det => {
            if (det.timings) {
                if (det.timings.totalDurationSec !== null && det.timings.totalDurationSec !== undefined) {
                    totalDurationSum += det.timings.totalDurationSec;
                    totalDurationCount++;
                }
                if (det.timings.analysisDurationSec !== null && det.timings.analysisDurationSec !== undefined) {
                    analysisDurationSum += det.timings.analysisDurationSec;
                    analysisDurationCount++;
                }
                if (det.timings.remediationDurationSec !== null && det.timings.remediationDurationSec !== undefined) {
                    remediationDurationSum += det.timings.remediationDurationSec;
                    remediationDurationCount++;
                }
                if (det.timings.testDurationSec !== null && det.timings.testDurationSec !== undefined) {
                    testDurationSum += det.timings.testDurationSec;
                    testDurationCount++;
                }
                if (det.timings.approvalWaitDurationSec !== null && det.timings.approvalWaitDurationSec !== undefined) {
                    approvalWaitSum += det.timings.approvalWaitDurationSec;
                    approvalWaitCount++;
                }
            }
        });

        if (dashKpiAvgDuration) dashKpiAvgDuration.textContent = totalDurationCount > 0 ? `${(totalDurationSum / totalDurationCount).toFixed(1)}s` : (total === 0 ? '0s' : 'N/A');
        if (timeMetricAnalysis) timeMetricAnalysis.textContent = analysisDurationCount > 0 ? `${(analysisDurationSum / analysisDurationCount).toFixed(1)}s` : (total === 0 ? '0s' : 'N/A');
        if (timeMetricRemediation) timeMetricRemediation.textContent = remediationDurationCount > 0 ? `${(remediationDurationSum / remediationDurationCount).toFixed(1)}s` : (total === 0 ? '0s' : 'N/A');
        if (timeMetricTest) timeMetricTest.textContent = testDurationCount > 0 ? `${(testDurationSum / testDurationCount).toFixed(1)}s` : (total === 0 ? '0s' : 'N/A');
        if (timeMetricApproval) timeMetricApproval.textContent = approvalWaitCount > 0 ? `${(approvalWaitSum / approvalWaitCount).toFixed(1)}s` : (total === 0 ? '0s' : 'N/A');

        // Quality Metrics
        if (qualityMetricFirstPass) qualityMetricFirstPass.textContent = completedRuns > 0 ? `${Math.round((remediated / completedRuns) * 100)}%` : (total === 0 ? '0%' : 'N/A');

        if (dashZeroStateBanner) {
            dashZeroStateBanner.style.display = total === 0 ? 'flex' : 'none';
        }

        // Calculate genuine test pass rate from detailsCache
        let genuineTestsPassed = 0;
        let genuineTestsTotal = 0;
        let hasGenuineTestData = false;
        let validationPassCount = 0;
        let validationPartialCount = 0;
        let validationFailCount = 0;

        detailsCache.forEach(det => {
            if (det.validation && det.validation.executed) {
                hasGenuineTestData = true;
                genuineTestsPassed += (det.validation.testsPassed || 0);
                genuineTestsTotal += (det.validation.testsTotal || 0);
            }
            if (det.securityReview && det.securityReview.rating) {
                const r = det.securityReview.rating.toUpperCase();
                if (r === 'PASS') validationPassCount++;
                else if (r === 'PARTIAL') validationPartialCount++;
                else if (r === 'FAIL') validationFailCount++;
            }
        });

        if (qualityMetricTestPass) {
            if (hasGenuineTestData && genuineTestsTotal > 0) {
                qualityMetricTestPass.textContent = `${Math.round((genuineTestsPassed / genuineTestsTotal) * 100)}%`;
            } else {
                qualityMetricTestPass.textContent = 'N/A';
            }
        }

        if (qualityMetricValidation) {
            const totalValidated = validationPassCount + validationPartialCount + validationFailCount;
            if (totalValidated > 0) {
                qualityMetricValidation.textContent = `${validationPassCount} PASS / ${validationPartialCount} PARTIAL / ${validationFailCount} FAIL`;
            } else {
                qualityMetricValidation.textContent = remediated > 0 ? `${remediated} PASS` : 'Pending';
            }
        }

        if (qualityMetricRetries) {
            qualityMetricRetries.textContent = 'N/A';
        }

        // Update nav counters
        if (navCountVulns) navCountVulns.textContent = total;
        if (navCountReview) navCountReview.textContent = review;

        // Mini KPI cards
        if (miniKpiTotal) miniKpiTotal.textContent = total;
        if (miniKpiCritical) miniKpiCritical.textContent = critical;
        if (miniKpiReview) miniKpiReview.textContent = review;
        if (miniKpiRemediated) miniKpiRemediated.textContent = remediated;

        // Render Pending Reviews & Recent Runs lists
        renderDashboardBottomPanels();
    }

    function renderDashboardBottomPanels() {
        // 1. Pending Reviews List
        const pendingItems = allVulnerabilities.filter(v => (v.Requires_Human_Review || '').toLowerCase() === 'true' || (v.Remediation_Status || '').toLowerCase().includes('review'));
        if (dashPendingCount) dashPendingCount.textContent = `${pendingItems.length} required`;

        if (dashPendingReviewsList) {
            if (pendingItems.length === 0) {
                dashPendingReviewsList.innerHTML = '<div class="empty-state"><p>No pending human review gates currently awaiting authorization.</p></div>';
            } else {
                dashPendingReviewsList.innerHTML = pendingItems.map(item => `
                    <div class="dash-list-item" data-id="${escapeHtml(item.Vulnerability_ID)}">
                        <div>
                            <div class="u-fw-600 u-text-primary">${escapeHtml(item.Vulnerability_ID)}: ${escapeHtml(item.Title)}</div>
                            <div class="u-font-11 u-text-muted u-mt-1">${escapeHtml(item.Application_Name)} • ${escapeHtml(item.Severity)}</div>
                        </div>
                        <button class="btn btn-secondary btn-sm btn-dash-review" data-id="${escapeHtml(item.Vulnerability_ID)}">Review ➔</button>
                    </div>
                `).join('');

                dashPendingReviewsList.querySelectorAll('.btn-dash-review').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const id = btn.getAttribute('data-id');
                        const target = allVulnerabilities.find(v => v.Vulnerability_ID === id);
                        if (target) {
                            switchView('vulnerabilities');
                            selectVulnerability(target, true);
                        }
                    });
                });
            }
        }

        // 2. Recent Runs List
        const recentRuns = allVulnerabilities.filter(v => (v.Remediation_Status || '').toLowerCase() !== 'pending');
        if (dashRecentRunsCount) dashRecentRunsCount.textContent = `${recentRuns.length} runs`;

        if (dashRecentRunsList) {
            if (recentRuns.length === 0) {
                dashRecentRunsList.innerHTML = '<div class="empty-state"><p>No recent remediation runs recorded.</p></div>';
            } else {
                dashRecentRunsList.innerHTML = recentRuns.slice(0, 6).map(item => {
                    const statusClass = getStatusBadgeClass(item.Remediation_Status, item.Requires_Human_Review);
                    return `
                        <div class="dash-list-item" data-id="${escapeHtml(item.Vulnerability_ID)}">
                            <div>
                                <div class="u-fw-600 u-text-primary">${escapeHtml(item.Vulnerability_ID)}</div>
                                <div class="u-font-11 u-text-muted u-mt-1">${escapeHtml(item.Title)}</div>
                            </div>
                            <div class="u-flex-row u-gap-8">
                                <span class="badge ${statusClass}">${escapeHtml(item.Remediation_Status || 'Done')}</span>
                                <button class="btn btn-secondary btn-sm btn-dash-view" data-id="${escapeHtml(item.Vulnerability_ID)}">Inspect</button>
                            </div>
                        </div>
                    `;
                }).join('');

                dashRecentRunsList.querySelectorAll('.btn-dash-view').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const id = btn.getAttribute('data-id');
                        const target = allVulnerabilities.find(v => v.Vulnerability_ID === id);
                        if (target) {
                            switchView('vulnerabilities');
                            selectVulnerability(target, true);
                        }
                    });
                });
            }
        }
    }

    // --------------------------------------------------------------------------
    // Native SVG Chart Renderers (Enterprise Minimal SaaS Style)
    // --------------------------------------------------------------------------
    function renderDashboardCharts() {
        const data = getDashboardFilteredData();

        // 1. Remediation Activity / Trend (Area Chart)
        renderActivityTrendChart(data);

        // 2. Findings by Severity (Donut Chart)
        renderSeverityDonutChart(data);

        // 3. Findings by Status (Bar Chart)
        renderStatusBarChart(data);

        // 4. Average Stage Durations (Horizontal Bar Chart)
        renderStageDurationChart();
    }

    function renderActivityTrendChart(data) {
        if (!chartCategoryContainer) return;

        if (!data || data.length === 0) {
            chartCategoryContainer.innerHTML = `
                <div class="empty-state u-p-30 u-text-center u-w-full">
                    <p class="u-fw-500 u-text-muted u-font-13">No scan activity recorded yet.</p>
                    <p class="u-font-11 u-text-muted u-mt-4">Run a vulnerability scan to populate trend data.</p>
                </div>
            `;
            return;
        }

        const trend = aggregateActivityTrend(data);
        const months = trend.labels;
        const totalCounts = trend.totalCounts;
        const remediatedCounts = trend.remediatedCounts;

        const width = 460;
        const height = 180;
        const padX = 40;
        const padY = 24;
        const graphW = width - padX * 2;
        const graphH = height - padY * 2;
        const maxVal = Math.max(...totalCounts, 1);

        const xAt = (idx) => months.length <= 1 ? (padX + graphW / 2) : (padX + (idx / (months.length - 1)) * graphW);

        // Calculate points
        const pointsTotal = totalCounts.map((val, idx) => ({
            x: xAt(idx),
            y: height - padY - (val / maxVal) * graphH,
            val
        }));

        const pointsRemediated = remediatedCounts.map((val, idx) => ({
            x: xAt(idx),
            y: height - padY - (val / maxVal) * graphH,
            val
        }));

        const lineTotalPath = pointsTotal.map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`)).join(' ');
        const areaTotalPath = months.length > 1
            ? `${lineTotalPath} L ${pointsTotal[pointsTotal.length - 1].x} ${height - padY} L ${pointsTotal[0].x} ${height - padY} Z`
            : '';

        const lineRemPath = pointsRemediated.map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`)).join(' ');

        chartCategoryContainer.innerHTML = `
            <div class="u-flex-col-items-center">
                <svg viewBox="0 0 ${width} ${height}" class="activity-trend-svg">
                    <defs>
                        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.2" />
                            <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.0" />
                        </linearGradient>
                    </defs>

                    <!-- Horizontal Grid lines -->
                    <line x1="${padX}" y1="${padY}" x2="${width - padX}" y2="${padY}" stroke="var(--border-subtle)" stroke-dasharray="3,3" />
                    <line x1="${padX}" y1="${padY + graphH * 0.5}" x2="${width - padX}" y2="${padY + graphH * 0.5}" stroke="var(--border-subtle)" stroke-dasharray="3,3" />
                    <line x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}" stroke="var(--border-subtle)" />

                    <!-- Area & Line Paths -->
                    ${areaTotalPath ? `<path d="${areaTotalPath}" fill="url(#areaGrad)" />` : ''}
                    ${months.length > 1 ? `<path d="${lineTotalPath}" fill="none" stroke="var(--accent)" stroke-width="2" />` : ''}
                    ${months.length > 1 ? `<path d="${lineRemPath}" fill="none" stroke="var(--success)" stroke-width="2" stroke-dasharray="4,2" />` : ''}

                    <!-- Points -->
                    ${pointsTotal.map(p => `
                        <circle cx="${p.x}" cy="${p.y}" r="4" fill="var(--bg-surface)" stroke="var(--accent)" stroke-width="2" />
                    `).join('')}

                    ${pointsRemediated.map(p => `
                        <circle cx="${p.x}" cy="${p.y}" r="4" fill="var(--bg-surface)" stroke="var(--success)" stroke-width="2" />
                    `).join('')}

                    <!-- X-Axis Labels -->
                    ${months.map((m, i) => `
                        <text x="${xAt(i)}" y="${height - 6}" font-size="10" fill="var(--text-muted)" text-anchor="middle" font-family="var(--font-sans)">${escapeHtml(m)}</text>
                    `).join('')}
                </svg>

                <div class="chart-legend chart-legend-centered">
                    <div class="legend-item">
                        <span class="legend-color legend-bg-accent"></span>
                        <span>Total Identified</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-color legend-bg-success"></span>
                        <span>Remediated &amp; Validated</span>
                    </div>
                </div>
            </div>
        `;
    }

    function renderSeverityDonutChart(data) {
        if (!chartSeverityContainer) return;

        if (!data || data.length === 0) {
            const size = 150;
            const strokeWidth = 18;
            const radius = (size - strokeWidth) / 2;
            chartSeverityContainer.innerHTML = `
                <div class="u-flex-around">
                    <div class="donut-wrap">
                        <svg viewBox="0 0 ${size} ${size}" class="svg-chart">
                            <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="var(--bg-surface-hover)" stroke-width="${strokeWidth}" />
                        </svg>
                        <div class="donut-center-overlay">
                            <span class="donut-total-val">0</span>
                            <span class="donut-total-sub">Total</span>
                        </div>
                    </div>
                    <div class="chart-legend chart-legend-col">
                        <div class="legend-item"><span class="legend-color legend-bg-danger"></span><span>Critical:</span><strong class="u-text-primary u-ml-4">0</strong></div>
                        <div class="legend-item"><span class="legend-color legend-bg-warning"></span><span>High:</span><strong class="u-text-primary u-ml-4">0</strong></div>
                        <div class="legend-item"><span class="legend-color legend-bg-medium"></span><span>Medium:</span><strong class="u-text-primary u-ml-4">0</strong></div>
                        <div class="legend-item"><span class="legend-color legend-bg-accent"></span><span>Low:</span><strong class="u-text-primary u-ml-4">0</strong></div>
                    </div>
                </div>
            `;
            return;
        }

        const critical = data.filter(v => (v.Severity || '').toUpperCase() === 'CRITICAL').length;
        const high = data.filter(v => (v.Severity || '').toUpperCase() === 'HIGH').length;
        const medium = data.filter(v => (v.Severity || '').toUpperCase() === 'MEDIUM').length;
        const low = data.filter(v => (v.Severity || '').toUpperCase() === 'LOW').length;
        const total = critical + high + medium + low || 1;

        const size = 150;
        const strokeWidth = 18;
        const radius = (size - strokeWidth) / 2;
        const circumference = 2 * Math.PI * radius;

        const segments = [
            { label: 'Critical', count: critical, color: 'var(--danger)', colorClass: 'legend-bg-danger', pct: critical / total },
            { label: 'High', count: high, color: 'var(--warning)', colorClass: 'legend-bg-warning', pct: high / total },
            { label: 'Medium', count: medium, color: 'var(--sev-medium-text)', colorClass: 'legend-bg-medium', pct: medium / total },
            { label: 'Low', count: low, color: 'var(--accent)', colorClass: 'legend-bg-accent', pct: low / total }
        ];

        let accumulatedOffset = 0;
        const circleSvgSegments = segments.map(seg => {
            const strokeDasharray = `${seg.pct * circumference} ${circumference}`;
            const strokeDashoffset = -accumulatedOffset;
            accumulatedOffset += seg.pct * circumference;
            return `
                <circle class="donut-segment" cx="${size / 2}" cy="${size / 2}" r="${radius}"
                    fill="none" stroke="${seg.color}" stroke-width="${strokeWidth}"
                    stroke-dasharray="${strokeDasharray}" stroke-dashoffset="${strokeDashoffset}" />
            `;
        }).join('');

        chartSeverityContainer.innerHTML = `
            <div class="u-flex-around">
                <div class="donut-wrap">
                    <svg viewBox="0 0 ${size} ${size}" class="svg-chart">
                        <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="var(--bg-surface-hover)" stroke-width="${strokeWidth}" />
                        ${circleSvgSegments}
                    </svg>
                    <div class="donut-center-overlay">
                        <span class="donut-total-val">${data.length}</span>
                        <span class="donut-total-sub">Total</span>
                    </div>
                </div>
                <div class="chart-legend chart-legend-col">
                    ${segments.map(s => `
                        <div class="legend-item">
                            <span class="legend-color ${s.colorClass}"></span>
                            <span>${s.label}:</span>
                            <strong class="u-text-primary u-ml-4">${s.count}</strong>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    function renderStatusBarChart(data) {
        if (!chartStatusContainer) return;

        const breakdown = computeStatusBreakdown(data);
        const maxVal = Math.max(breakdown.remediated, breakdown.approved, breakdown.review, breakdown.inProgress, breakdown.pending, 1);

        const items = [
            { label: 'Remediated', count: breakdown.remediated, colorClass: 'legend-bg-success' },
            { label: 'Approved', count: breakdown.approved, colorClass: 'legend-bg-accent' },
            { label: 'Needs Review', count: breakdown.review, colorClass: 'legend-bg-warning' },
            { label: 'In Progress', count: breakdown.inProgress, colorClass: 'legend-bg-info' },
            { label: 'Pending', count: breakdown.pending, colorClass: 'legend-bg-muted' }
        ];

        chartStatusContainer.innerHTML = `
            <div class="u-flex-col-center">
                ${items.map(it => `
                    <div class="chart-bar-row">
                        <span class="chart-bar-label">${it.label}</span>
                        <div class="chart-bar-track">
                            <div class="chart-bar-fill ${it.colorClass}" data-bar-width="${(it.count / maxVal) * 100}%"></div>
                        </div>
                        <span class="chart-bar-val">${it.count}</span>
                    </div>
                `).join('')}
            </div>
        `;
        applyDynamicStyles(chartStatusContainer);
    }

    function renderStageDurationChart() {
        if (!chartStageDurationContainer) return;

        const { hasData, stages } = aggregateStageDurations(Array.from(detailsCache.values()));

        if (!hasData) {
            chartStageDurationContainer.innerHTML = `
                <div class="empty-state u-p-24 u-text-center u-w-full">
                    <p class="u-fw-500 u-text-muted">No stage duration telemetry available yet.</p>
                    <p class="u-font-11 u-text-muted u-mt-4">Durations are captured strictly during live execution.</p>
                </div>
            `;
            return;
        }

        const numericDurations = stages.map(s => s.duration).filter(d => d !== null);
        const maxDur = Math.max(...numericDurations, 1);

        chartStageDurationContainer.innerHTML = `
            <div class="u-flex-col-center">
                ${stages.map(s => {
                    const widthPct = s.duration !== null ? (s.duration / maxDur) * 100 : 0;
                    const displayVal = s.duration !== null ? `${s.duration}s` : 'N/A';
                    return `
                    <div class="chart-bar-row">
                        <span class="chart-bar-label">${s.label}</span>
                        <div class="chart-bar-track">
                            <div class="chart-bar-fill ${s.colorClass}" data-bar-width="${widthPct}%"></div>
                        </div>
                        <span class="chart-bar-val">${displayVal}</span>
                    </div>
                `;
                }).join('')}
            </div>
        `;
        applyDynamicStyles(chartStageDurationContainer);
    }

    // --------------------------------------------------------------------------
    // Vulnerability Table & Repository Filtering
    // --------------------------------------------------------------------------
    function updateFilterDropdowns() {
        if (!dashFilterApp || !tableRepoFilter) return;

        const apps = Array.from(new Set(allVulnerabilities.map(v => v.Application_Name).filter(Boolean)));
        const repos = Array.from(new Set(allVulnerabilities.map(v => v.Repository).filter(Boolean)));

        const currentDashApp = dashFilterApp.value;
        dashFilterApp.innerHTML = '<option value="ALL">All Applications</option>';
        apps.forEach(app => {
            const opt = document.createElement('option');
            opt.value = app;
            opt.textContent = app;
            dashFilterApp.appendChild(opt);
        });
        if (apps.includes(currentDashApp)) dashFilterApp.value = currentDashApp;

        const currentRepo = tableRepoFilter.value;
        tableRepoFilter.innerHTML = '<option value="ALL">All Repositories</option>';
        repos.forEach(repo => {
            const opt = document.createElement('option');
            opt.value = repo;
            opt.textContent = repo.replace('sample-repos/', '');
            tableRepoFilter.appendChild(opt);
        });
        if (repos.includes(currentRepo)) tableRepoFilter.value = currentRepo;
    }

    function applyQuickFilter(filterType) {
        activeQuickFilter = filterType;

        filterChips.forEach(chip => {
            chip.classList.toggle('active', chip.getAttribute('data-chip') === filterType);
        });

        if (tableSeverityFilter) {
            if (filterType === 'CRITICAL') tableSeverityFilter.value = 'CRITICAL';
            else if (filterType === 'HIGH') tableSeverityFilter.value = 'HIGH';
            else if (filterType === 'ALL') tableSeverityFilter.value = 'ALL';
        }

        if (tableStatusFilter) {
            if (filterType === 'REVIEW') tableStatusFilter.value = 'REVIEW';
            else if (filterType === 'REMEDIATED') tableStatusFilter.value = 'REMEDIATED';
            else if (filterType === 'ALL') tableStatusFilter.value = 'ALL';
        }

        renderTable();
    }

    function getTableFilteredData() {
        const query = (tableSearchInput?.value || '').toLowerCase().trim();
        const sev = tableSeverityFilter?.value || 'ALL';
        const st = tableStatusFilter?.value || 'ALL';
        const rep = tableRepoFilter?.value || 'ALL';
        const src = tableSourceFilter?.value || 'ALL';

        return allVulnerabilities.filter(v => {
            if (sev !== 'ALL' && (v.Severity || '').toUpperCase() !== sev) return false;
            if (rep !== 'ALL' && v.Repository !== rep) return false;

            if (src !== 'ALL') {
                const isScanner = (v.Source_Type === 'SCANNER' || v.Source_Type === 'scanner');
                if (src === 'LocalScanner' && !isScanner) return false;
                if (src === 'CSV' && isScanner) return false;
            }

            if (st !== 'ALL') {
                const status = (v.Remediation_Status || 'Pending').toUpperCase();
                if (st === 'REMEDIATED' && status !== 'REMEDIATED') return false;
                if (st === 'APPROVED' && status !== 'APPROVED') return false;
                if (st === 'INPROGRESS' && !status.includes('PROGRESS')) return false;
                if (st === 'REVIEW' && (v.Requires_Human_Review || '').toLowerCase() !== 'true' && !status.includes('REVIEW')) return false;
                if (st === 'PENDING' && status !== 'PENDING') return false;
            }

            if (query) {
                const matchStr = `${v.Vulnerability_ID} ${v.CVE_ID} ${v.Title} ${v.Detailed_Name} ${v.Application_Name} ${v.Location_Path}`.toLowerCase();
                return matchStr.includes(query);
            }

            return true;
        });
    }

    function renderTable() {
        if (!vulnTableBody) return;

        let list = getTableFilteredData();
        if (tableVulnCounter) tableVulnCounter.textContent = `${list.length} item${list.length === 1 ? '' : 's'}`;

        // Sorting
        list.sort((a, b) => {
            let valA = a[tableSortColumn] || '';
            let valB = b[tableSortColumn] || '';

            if (tableSortColumn === 'id') {
                valA = a.Vulnerability_ID || '';
                valB = b.Vulnerability_ID || '';
            } else if (tableSortColumn === 'title') {
                valA = a.Title || '';
                valB = b.Title || '';
            } else if (tableSortColumn === 'severity') {
                const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
                valA = sevRank[(a.Severity || '').toUpperCase()] || 0;
                valB = sevRank[(b.Severity || '').toUpperCase()] || 0;
            } else if (tableSortColumn === 'status') {
                valA = a.Remediation_Status || '';
                valB = b.Remediation_Status || '';
            } else if (tableSortColumn === 'source') {
                valA = a.Source_Type || 'CSV';
                valB = b.Source_Type || 'CSV';
            }

            if (valA < valB) return tableSortAsc ? -1 : 1;
            if (valA > valB) return tableSortAsc ? 1 : -1;
            return 0;
        });

        vulnTableBody.innerHTML = '';

        if (list.length === 0) {
            const hasAny = allVulnerabilities.length > 0;
            vulnTableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="empty-state u-empty-table-cell">
                        <p class="u-fw-600 u-font-13 u-text-primary">${hasAny ? 'No vulnerabilities match your filter criteria.' : 'No vulnerabilities scanned yet.'}</p>
                        <p class="u-font-11 u-text-muted u-mt-4">${hasAny ? 'Try clearing filters or search query.' : 'Select files or a repository in Local Scanners and click Run Vulnerability Scan.'}</p>
                        ${!hasAny ? '<button class="btn btn-primary btn-sm u-mt-12" id="btnTableGoToScans">Go to Local Scanners ➔</button>' : ''}
                    </td>
                </tr>
            `;
            const btnScans = vulnTableBody.querySelector('#btnTableGoToScans');
            if (btnScans) {
                btnScans.addEventListener('click', () => switchView('scans'));
            }
            return;
        }

        list.forEach(v => {
            const tr = document.createElement('tr');
            tr.className = 'vuln-row';
            if (selectedVulnerability && selectedVulnerability.Vulnerability_ID === v.Vulnerability_ID) {
                tr.classList.add('active');
            }

            const sevClass = getSeverityBadgeClass(v.Severity);
            const statusClass = getStatusBadgeClass(v.Remediation_Status, v.Requires_Human_Review);
            const isScanner = (v.Source_Type === 'SCANNER' || v.Source_Type === 'scanner');
            const sourceBadgeClass = isScanner ? 'badge-source-scanner' : 'badge-source-csv';
            const sourceLabel = isScanner ? (v.Scanner_ID ? `Scanner: ${v.Scanner_ID}` : 'Local Scanner') : 'CSV Import';

            tr.innerHTML = `
                <td>
                    <span class="id-badge">${escapeHtml(v.Vulnerability_ID)}</span>
                    <span class="cve-text">${escapeHtml(v.CVE_ID || 'No CVE')}</span>
                </td>
                <td>
                    <div class="u-fw-600 u-text-primary">${escapeHtml(v.Title)}</div>
                    <div class="u-font-11 u-text-muted u-mt-1">${escapeHtml(v.Detailed_Name || '')}</div>
                </td>
                <td>
                    <span class="badge ${sevClass}">${escapeHtml(v.Severity || 'Unknown')}</span>
                </td>
                <td>
                    <span class="badge ${sourceBadgeClass}">${escapeHtml(sourceLabel)}</span>
                </td>
                <td>
                    <div class="u-fw-500">${escapeHtml(v.Application_Name || '')}</div>
                    <div class="u-font-11 u-text-muted u-mono">${escapeHtml(v.Repository ? v.Repository.replace('sample-repos/', '') : '')}</div>
                </td>
                <td>
                    <div class="font-mono u-font-11 u-text-secondary">${escapeHtml(v.Location_Path || '')}${v.Line_Number ? `:${v.Line_Number}` : ''}</div>
                </td>
                <td>
                    <span class="badge ${statusClass}">${escapeHtml(v.Remediation_Status || 'Pending')}</span>
                </td>
                <td>
                    <span class="u-font-11 u-text-muted">${escapeHtml(v.Finding_Date || 'Recent')}</span>
                </td>
                <td class="u-text-right">
                    <button class="btn btn-secondary btn-sm btn-inspect-row" data-id="${escapeHtml(v.Vulnerability_ID)}">
                        Inspect
                    </button>
                </td>
            `;

            tr.addEventListener('click', (e) => {
                if (e.target.closest('button')) return;
                selectVulnerability(v, true);
            });

            const inspectBtn = tr.querySelector('.btn-inspect-row');
            if (inspectBtn) {
                inspectBtn.addEventListener('click', () => selectVulnerability(v, true));
            }

            vulnTableBody.appendChild(tr);
        });
    }

    function selectVulnerability(v, requestDetails = true) {
        selectedVulnerability = v;

        // Highlight active row in table
        document.querySelectorAll('.vuln-row').forEach(r => r.classList.remove('active'));
        const matchingRow = Array.from(document.querySelectorAll('.vuln-row')).find(r => r.innerHTML.includes(v.Vulnerability_ID));
        if (matchingRow) matchingRow.classList.add('active');

        // Populate Inspector Header
        if (detailId) detailId.textContent = v.Vulnerability_ID;
        if (detailTitle) detailTitle.textContent = v.Title;
        if (detailCve) detailCve.textContent = v.CVE_ID ? `${v.CVE_ID} • ${v.Detailed_Name || ''}` : (v.Detailed_Name || '');
        if (detailSeverity) {
            detailSeverity.textContent = v.Severity;
            detailSeverity.className = `badge ${getSeverityBadgeClass(v.Severity)}`;
        }
        const isScannerFinding = (v.Source_Type === 'SCANNER' || v.Source_Type === 'scanner');
        if (detailApp) detailApp.textContent = `${v.Application_Name || ''} (${v.Application_Number || ''})`;
        if (detailRepo) detailRepo.textContent = v.Repository || 'workspace';
        if (detailTech) detailTech.textContent = isScannerFinding && v.Scanner_ID ? `${v.Technology || 'dotnet'} (${v.Scanner_ID})` : (v.Technology || 'dotnet');
        if (detailSla) detailSla.textContent = v.SLA_Status || 'In SLA';
        if (detailLocation) detailLocation.textContent = `${v.Location_Path || ''} ${v.Line_Number ? `(Line ${v.Line_Number})` : ''}`;
        if (detailGuidance) {
            if (v.Remediation_Guidance) {
                detailGuidance.textContent = v.Remediation_Guidance;
            } else if (v.Rule_ID) {
                detailGuidance.textContent = `Security Rule ${v.Rule_ID}: Review identified location and implement defensive verification.`;
            } else {
                detailGuidance.textContent = 'Apply secure coding best practices.';
            }
        }

        // Update Live Remediation button state
        const isRemediated = (v.Remediation_Status || '').toLowerCase() === 'remediated';
        if (btnRunRemediationText) {
            btnRunRemediationText.textContent = isRemediated ? 'Re-run Engine' : 'Execute Engine';
        }

        // Open Inspector Panel
        detailPanel.classList.add('visible');
        vulnWorkspaceLayout.classList.add('with-detail');

        // Update Active Runs View with this finding
        updateActiveRunView(v);

        // Request detailed artifacts from extension host
        if (requestDetails) {
            postToHost({ command: 'loadDetails', vulnerabilityId: v.Vulnerability_ID });
        }
    }

    function updateActiveRunView(v) {
        if (!v) return;
        if (activeRunVulnTitle) activeRunVulnTitle.textContent = `${v.Vulnerability_ID} — ${v.Title}`;
        if (activeRunVulnSubtitle) activeRunVulnSubtitle.textContent = `${v.Severity} Severity • ${v.Application_Name || ''} • ${v.Repository || ''}`;
        if (activeRunSummaryId) activeRunSummaryId.textContent = v.Vulnerability_ID;
        if (activeRunSummaryStage) activeRunSummaryStage.textContent = isRemediating ? 'Executing 7-Stage Pipeline' : (v.Remediation_Status || 'Ready');
        if (activeRunSummaryFiles) activeRunSummaryFiles.textContent = v.Files_Changed ? v.Files_Changed.split(';').length + ' File(s)' : (v.Location_Path ? '1 File' : '--');
        if (activeRunSummaryTests) activeRunSummaryTests.textContent = v.Test_Status || (v.Final_Validation_Status === 'PASS' ? 'PASS (1/1)' : 'Pending');
        if (activeRunSummaryRetries) activeRunSummaryRetries.textContent = '0 of 3';
        if (activeRunSummaryStatus) activeRunSummaryStatus.textContent = v.Remediation_Status || 'Ready';
        if (activeRunStatusPill) activeRunStatusPill.textContent = isRemediating ? 'In Progress' : (v.Remediation_Status || 'Idle');
    }

    // --------------------------------------------------------------------------
    // Inspector Details & Stepper Rendering
    // --------------------------------------------------------------------------
    function renderInspectorDetails(details) {
        if (!details) return;

        // 1. Render Stepper
        if (pipelineStepper) {
            pipelineStepper.innerHTML = '';
            const stages = details.stages || [];

            let showGate4 = false;
            let showGate6 = false;
            let hasFailure = false;
            let allDone = true;

            stages.forEach((stage, idx) => {
                const li = document.createElement('li');
                const status = stage.status || 'pending';
                li.className = `step-item ${status}`;

                let icon = stage.number || (idx + 1);
                if (status === 'completed') icon = '✓';
                if (status === 'failed') { icon = '✕'; hasFailure = true; allDone = false; }
                if (status === 'awaiting_review') {
                    icon = '!';
                    allDone = false;
                    if (stage.id === 'human-gate') showGate4 = true;
                    if (stage.id === 'final-human-gate') showGate6 = true;
                }
                if (status === 'in_progress' || status === 'pending') allDone = false;

                li.innerHTML = `
                    <div class="step-number">${icon}</div>
                    <div class="step-content">
                        <div>
                            <div class="step-name">${stage.number ? `Stage ${stage.number}: ` : ''}${escapeHtml(stage.name)}</div>
                            <div class="step-summary">${escapeHtml(stage.summary || 'Pending')}</div>
                        </div>
                        <span class="badge badge-status-${status}">${status.replace('_', ' ').toUpperCase()}</span>
                    </div>
                `;
                pipelineStepper.appendChild(li);
            });

            // Overall status badge
            if (pipelineOverallStatus) {
                if (allDone) {
                    pipelineOverallStatus.textContent = 'Remediated';
                    pipelineOverallStatus.className = 'badge badge-status-remediated';
                } else if (showGate4 || showGate6) {
                    pipelineOverallStatus.textContent = 'Awaiting Gate';
                    pipelineOverallStatus.className = 'badge badge-status-review';
                } else if (hasFailure) {
                    pipelineOverallStatus.textContent = 'Failed';
                    pipelineOverallStatus.className = 'badge badge-status-failed';
                } else {
                    pipelineOverallStatus.textContent = 'Ready';
                    pipelineOverallStatus.className = 'badge badge-status-pending';
                }
            }

            // Gate Banners & Failure panel
            if (humanGateCard) {
                humanGateCard.style.display = showGate4 ? 'flex' : 'none';
                if (showGate4 && gate4PatchSummary) {
                    gate4PatchSummary.innerHTML = `
                        <div class="gate4-patch-box">
                            <div><strong>Root Cause:</strong> ${escapeHtml(selectedVulnerability?.Agent_Code_Analysis_Output || 'Untrusted input parameter concatenated directly into raw query.')}</div>
                            <div class="u-mt-4"><strong>Proposed Fix:</strong> ${escapeHtml(selectedVulnerability?.Remediation_Guidance || 'Use parameterized query placeholder.')}</div>
                            <div class="u-mt-4"><strong>Target File:</strong> <code>${escapeHtml(selectedVulnerability?.Location_Path || 'Source.cs')}</code> (Line ${escapeHtml(selectedVulnerability?.Line_Number || '1')})</div>
                        </div>
                    `;
                }
            }

            if (finalGateCard) finalGateCard.style.display = showGate6 ? 'flex' : 'none';
            if (failureRecoveryCard) {
                failureRecoveryCard.style.display = hasFailure ? 'flex' : 'none';
                if (hasFailure && failureStageTitle) {
                    failureStageTitle.textContent = 'Validation Failed at Stage 5 (Bench Testing)';
                }
            }
        }

        // 2. Render Evidence Tabs
        if (reportContent) {
            reportContent.innerHTML = details.reportMarkdown
                ? `<div class="markdown-body">${renderMarkdown(details.reportMarkdown)}</div>`
                : '<div class="empty-state"><p>No audit report generated yet. Run remediation to produce Shared Markdown evidence.</p></div>';
        }

        renderDiffView(details.patchDiff);
        renderTestEvidenceView(details);
        renderTraceLogView(details.traceLog);

        if (activeRunsStepper) {
            activeRunsStepper.innerHTML = pipelineStepper.innerHTML;
        }
    }

    function renderDiffView(patch) {
        if (!diffContent) return;

        if (patch && patch.trim().length > 0) {
            if (diffSummaryBar) diffSummaryBar.style.display = 'flex';

            const lines = patch.split('\n');
            const adds = lines.filter(l => l.startsWith('+') && !l.startsWith('+++')).length;
            const dels = lines.filter(l => l.startsWith('-') && !l.startsWith('---')).length;

            if (diffStatAdd) diffStatAdd.textContent = `+${adds}`;
            if (diffStatDel) diffStatDel.textContent = `-${dels}`;
            if (diffStatFile) diffStatFile.textContent = selectedVulnerability?.Location_Path || 'TargetPatch.cs';

            diffContent.innerHTML = renderColorizedDiff(patch);
        } else {
            if (diffSummaryBar) diffSummaryBar.style.display = 'none';
            diffContent.innerHTML = '<div class="empty-state"><p>No patch diff available yet.</p></div>';
        }
    }

    function renderTestEvidenceView(details) {
        if (!valContent) return;
        const val = details.validation;
        const sec = details.securityReview;

        if (!val && !sec) {
            valContent.innerHTML = '<div class="empty-state"><p>Validation evidence pending Stage 5 Bench Testing execution.</p></div>';
            return;
        }

        const isNotExecuted = val?.status === 'NOT EXECUTED' || val?.executed === false;
        const testStatus = isNotExecuted ? 'NOT EXECUTED' : (val?.status || (val?.buildResult === 'PASS' ? 'PASS' : 'FAIL'));
        const buildPass = testStatus === 'PASS';
        const testsPassed = val?.testsPassed ?? 0;
        const testsFailed = val?.testsFailed ?? 0;
        const duration = val?.durationMs ? `${(val.durationMs / 1000).toFixed(2)}s` : 'N/A';
        const score = sec?.score ?? val?.confidenceScore ?? 0;
        const statusColorClass = buildPass ? 'u-text-success' : (isNotExecuted ? 'u-text-warning' : 'u-text-danger');
        const scoreTextClass = score >= 90 ? 'u-text-success' : (score >= 70 ? 'u-text-warning' : 'u-text-danger');
        const scoreBgClass = score >= 90 ? 'legend-bg-success' : (score >= 70 ? 'legend-bg-warning' : 'legend-bg-danger');

        valContent.innerHTML = `
            <div class="evidence-dashboard">
                <div class="test-metric-row">
                    <div class="test-metric-card">
                        <div class="test-metric-label">Execution Status</div>
                        <div class="test-metric-val u-font-13 ${statusColorClass}">${escapeHtml(testStatus)}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Tests Passed</div>
                        <div class="test-metric-val u-text-success">${isNotExecuted ? 'N/A' : testsPassed}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Tests Failed</div>
                        <div class="test-metric-val ${testsFailed > 0 ? 'u-text-danger' : 'u-text-muted'}">${isNotExecuted ? 'N/A' : testsFailed}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Duration</div>
                        <div class="test-metric-val">${duration}</div>
                    </div>
                </div>

                <div class="score-meter-wrap">
                    <div class="score-meter-label">
                        <span class="u-fw-600">Autonomous Validation Confidence Score</span>
                        <span class="u-fw-700 ${scoreTextClass}">${score} / 100</span>
                    </div>
                    <div class="score-bar-bg">
                        <div class="score-bar-fill ${scoreBgClass}" data-bar-width="${score}%"></div>
                    </div>
                </div>

                ${val?.consoleOutput ? `
                    <div class="u-mt-8">
                        <div class="evidence-label-sm">Runner Console Output</div>
                        <pre class="console-output-pre">${escapeHtml(val.consoleOutput)}</pre>
                    </div>
                ` : ''}
            </div>
        `;
        applyDynamicStyles(valContent);
    }

    function renderTraceLogView(trace) {
        if (!traceContent) return;
        if (!trace || trace.trim().length === 0) {
            traceContent.innerHTML = '<div class="empty-state"><p>No agent execution trace logs recorded.</p></div>';
            return;
        }

        const lines = trace.split('\n').filter(Boolean);
        let html = '<div class="log-terminal">';
        lines.forEach(line => {
            const match = line.match(/^(\[[^\]]+\])\s*(\[[A-Z_]+\])?\s*(.*)$/);
            if (match) {
                const ts = match[1];
                const tag = match[2] ? match[2].replace(/[\[\]]/g, '') : '';
                const msg = match[3];
                html += `
                    <div class="log-entry">
                        <span class="log-ts">${escapeHtml(ts)}</span>
                        ${tag ? `<span class="log-tag ${tag}">${escapeHtml(tag)}</span>` : ''}
                        <span class="log-msg">${escapeHtml(msg)}</span>
                    </div>
                `;
            } else {
                html += `<div class="log-entry"><span class="log-msg">${escapeHtml(line)}</span></div>`;
            }
        });
        html += '</div>';
        traceContent.innerHTML = html;
    }

    function switchEvidenceTab(tabId) {
        evidenceTabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
        });
        evidenceTabPanes.forEach(pane => {
            pane.classList.toggle('active', pane.id === `tab-${tabId}`);
        });
    }

    // --------------------------------------------------------------------------
    // Review Queue View Renderer
    // --------------------------------------------------------------------------
    function renderReviewQueueView() {
        if (!reviewQueueCardsList) return;

        const queueItems = allVulnerabilities.filter(v => (v.Requires_Human_Review || '').toLowerCase() === 'true' || (v.Remediation_Status || '').toLowerCase().includes('review'));
        if (queueTotalBadge) queueTotalBadge.textContent = `${queueItems.length} Finding${queueItems.length === 1 ? '' : 's'} Requiring Authorization`;

        if (queueItems.length === 0) {
            reviewQueueCardsList.innerHTML = `
                <div class="empty-state u-p-40">
                    <p class="u-font-15 u-fw-600 u-text-primary">All Governance Gates Cleared ✓</p>
                    <p class="u-font-12 u-text-muted u-mt-4">No human review approvals or sign-offs are currently pending.</p>
                </div>
            `;
            return;
        }

        reviewQueueCardsList.innerHTML = queueItems.map(item => `
            <div class="review-card" id="review-card-${escapeHtml(item.Vulnerability_ID)}">
                <div class="review-card-top">
                    <div>
                        <div class="review-card-title">${escapeHtml(item.Vulnerability_ID)}: ${escapeHtml(item.Title)}</div>
                        <div class="review-card-meta">${escapeHtml(item.Application_Name)} • ${escapeHtml(item.Repository)} • ${escapeHtml(item.Location_Path || '')}</div>
                    </div>
                    <span class="badge ${getSeverityBadgeClass(item.Severity)}">${escapeHtml(item.Severity)}</span>
                </div>

                <div class="review-card-body">
                    <p><strong>Root Cause:</strong> ${escapeHtml(item.Agent_Code_Analysis_Output || 'Identified untrusted data flow at ' + (item.Location_Path || 'target file') + ' (Line ' + (item.Line_Number || 1) + ').')}</p>
                    <p class="u-mt-6"><strong>Proposed Fix:</strong> ${escapeHtml(item.Remediation_Guidance || 'Apply secure parameterized modification.')}</p>
                </div>

                <div class="review-card-actions">
                    <button class="btn btn-success btn-sm btn-queue-approve" data-id="${escapeHtml(item.Vulnerability_ID)}">
                        ✓ Authorize &amp; Proceed to Testing
                    </button>
                    <button class="btn btn-secondary btn-sm btn-queue-reject" data-id="${escapeHtml(item.Vulnerability_ID)}">
                        Request Changes / Reject
                    </button>
                    <button class="btn btn-secondary btn-sm btn-queue-inspect" data-id="${escapeHtml(item.Vulnerability_ID)}">
                        Inspect in Workspace
                    </button>
                </div>
            </div>
        `).join('');

        reviewQueueCardsList.querySelectorAll('.btn-queue-approve').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                postToHost({ command: 'approveRemediation', vulnerabilityId: id });
            });
        });

        reviewQueueCardsList.querySelectorAll('.btn-queue-reject').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                postToHost({ command: 'rejectRemediation', vulnerabilityId: id });
            });
        });

        reviewQueueCardsList.querySelectorAll('.btn-queue-inspect').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                const target = allVulnerabilities.find(v => v.Vulnerability_ID === id);
                if (target) {
                    switchView('vulnerabilities');
                    selectVulnerability(target, true);
                }
            });
        });
    }

    function updateSelectedTargetDisplay(targetPath, isFolder) {
        if (!selectedTargetBadge) return;
        if (!targetPath || targetPath === '.') {
            selectedTargetBadge.textContent = targetPath === '.' ? 'Entire Workspace' : 'No Target Selected';
            selectedTargetBadge.className = 'badge ' + (targetPath === '.' ? 'badge-primary' : 'badge-secondary');
        } else {
            const cleanPath = targetPath.replace(/\\/g, '/');
            const fileName = cleanPath.split('/').filter(Boolean).pop() || cleanPath;
            const typeLabel = isFolder ? 'Folder' : (cleanPath.includes('.') ? 'File' : 'Target');
            selectedTargetBadge.textContent = `${typeLabel}: ${fileName}`;
            selectedTargetBadge.className = 'badge badge-success';
            selectedTargetBadge.title = targetPath;
        }
        if (displayRepoName && targetPath) {
            displayRepoName.textContent = targetPath.split(/[/\\]/).filter(Boolean).pop() || targetPath;
            displayRepoName.title = targetPath;
        }
    }

    function openTargetPickerModal(targets, mode) {
        if (!targetPickerModal) return;
        targetPickerModal.style.display = 'flex';
        const titleEl = document.getElementById('targetPickerTitle');
        if (titleEl) titleEl.textContent = mode === 'file' ? 'Select File to Scan' : 'Select Folder / Repository to Scan';
        renderTargetPickerList(targets || [], mode);
    }

    function closeTargetPickerModal() {
        if (targetPickerModal) targetPickerModal.style.display = 'none';
    }

    function renderTargetPickerList(targets, mode) {
        if (!targetPickerList) return;
        targetPickerList.innerHTML = '';
        if (!targets || targets.length === 0) {
            targetPickerList.innerHTML = '<div class="empty-state u-p-16">No targets discovered in workspace.</div>';
            return;
        }

        const filtered = targets.filter(t => mode === 'file' ? !t.isFolder : t.isFolder);
        const listToRender = filtered.length > 0 ? filtered : targets;

        listToRender.forEach(t => {
            const item = document.createElement('div');
            item.className = 'dash-list-item target-picker-item';
            item.innerHTML = `
                <div>
                    <div class="u-fw-600 u-text-primary u-font-13">${t.isFolder ? '📁' : '📄'} ${escapeHtml(t.name || t.path)}</div>
                    <div class="u-font-11 u-text-muted u-mono">${escapeHtml(t.path)}</div>
                </div>
                <button class="btn btn-secondary btn-sm">Select</button>
            `;
            item.addEventListener('click', () => {
                if (inputScanTargetPath) inputScanTargetPath.value = t.path;
                updateSelectedTargetDisplay(t.path, t.isFolder);
                postToHost({ command: 'selectScanTarget', targetPath: t.path });
                closeTargetPickerModal();
                showToast(`Target selected: ${t.path}`, 'info');
            });
            targetPickerList.appendChild(item);
        });
    }

    // --------------------------------------------------------------------------
    // Vulnerability Scanning & Adapter Management
    // --------------------------------------------------------------------------
    function triggerScanExecution() {
        const scannerIds = [];
        if (chkScanSecrets && chkScanSecrets.checked) scannerIds.push('secrets-config-scanner');
        if (chkScanDotnet && chkScanDotnet.checked) scannerIds.push('dotnet-security-scanner');
        if (chkScanNuget && chkScanNuget.checked) scannerIds.push('nuget-audit-scanner');
        if (chkScanCodeql && chkScanCodeql.checked) scannerIds.push('codeql-scanner');

        if (scannerIds.length === 0) {
            showToast('Please select at least one scanner adapter', 'warning');
            return;
        }

        const chosenTarget = (inputScanTargetPath ? inputScanTargetPath.value.trim() : '') || currentConfig.activeRepo;

        if (btnStartScan) btnStartScan.disabled = true;
        if (btnCancelScan) btnCancelScan.style.display = 'inline-flex';
        if (scanProgressCard) scanProgressCard.style.display = 'block';
        if (scanProgressBarFill) scanProgressBarFill.style.width = '5%';
        if (scanProgressText) scanProgressText.textContent = `Starting scan on ${chosenTarget || 'workspace'}...`;

        scanStartTime = Date.now();
        if (scanTimerInterval) clearInterval(scanTimerInterval);
        scanTimerInterval = setInterval(() => {
            const elapsed = Math.round((Date.now() - scanStartTime) / 1000);
            if (scanProgressTimer) scanProgressTimer.textContent = `${elapsed}s`;
        }, 1000);

        postToHost({
            command: 'scanRepository',
            scannerIds: scannerIds,
            targetRepo: chosenTarget
        });
    }

    function handleScanProgress(data) {
        const normalized = normalizeScanProgressEvent(data);
        if (!normalized) return;
        if (scanProgressCard) scanProgressCard.style.display = 'block';
        if (normalized.percent !== undefined && scanProgressBarFill) {
            scanProgressBarFill.style.width = `${normalized.percent}%`;
        }
        if (normalized.message && scanProgressText) {
            scanProgressText.textContent = normalized.message;
        }
    }

    function handleScanCompleted(data) {
        if (scanTimerInterval) {
            clearInterval(scanTimerInterval);
            scanTimerInterval = null;
        }
        if (btnStartScan) btnStartScan.disabled = false;
        if (btnCancelScan) btnCancelScan.style.display = 'none';
        if (scanProgressBarFill) scanProgressBarFill.style.width = '100%';
        const count = data.findingsCount !== undefined ? data.findingsCount : (data.result?.findingsSummary?.total || 0);
        if (scanProgressText) scanProgressText.textContent = `Scan complete: ${count} finding(s) discovered`;

        setTimeout(() => {
            if (scanProgressCard) scanProgressCard.style.display = 'none';
        }, 3000);

        showToast(`Scan completed: ${count} findings discovered`, 'success');
        postToHost({ command: 'getScanHistory' });
        postToHost({ command: 'requestData' });
    }

    function handleScanError(data) {
        if (scanTimerInterval) {
            clearInterval(scanTimerInterval);
            scanTimerInterval = null;
        }
        if (btnStartScan) btnStartScan.disabled = false;
        if (btnCancelScan) btnCancelScan.style.display = 'none';
        if (scanProgressCard) scanProgressCard.style.display = 'none';
        showToast(data.error || 'Vulnerability scan failed', 'error');
    }

    function renderScannersCards(scanners) {
        if (!scannersCardsGrid) return;
        if (!scanners || scanners.length === 0) {
            scannersCardsGrid.innerHTML = '<div class="empty-state">No scanner adapters discovered.</div>';
            return;
        }

        scannersCardsGrid.innerHTML = '';
        scanners.forEach(s => {
            const card = document.createElement('div');
            card.className = 'scanner-card';
            // CodeQL gets special treatment: show NOT_INSTALLED distinctly vs. Ready
            const isCodeql = s.id === 'codeql';
            const isReady  = s.available !== false && (s.status === 'Ready' || s.status === 'Completed');
            const isNotInstalled = s.available === false || s.status === 'Not Installed';
            const statusClass = isReady ? 'badge-success'
                : (s.status === 'Running' ? 'badge-info'
                : (isNotInstalled ? 'badge-warning' : 'badge-secondary'));
            const statusLabel = isNotInstalled ? 'Not Installed' : (s.status || 'Ready');

            const metaRow = `<div class="scanner-meta-row">
                <span class="scanner-meta-label">Rules:</span>
                <span class="scanner-meta-val">${s.rulesCount || (s.rules ? s.rules.length : 'Configured')}</span>
                <span class="scanner-meta-label u-ml-12">Targets:</span>
                <span class="scanner-meta-val font-mono">${escapeHtml((s.languages || ['csharp']).join(', '))}</span>
            </div>`;
            const codeqlWarning = isCodeql && isNotInstalled
                ? `<div class="u-mt-6 u-font-11 u-text-warning">⚠ Run <code>node scripts/setup-codeql.js</code> to enable semantic analysis.</div>`
                : '';

            card.innerHTML = `
                <div class="scanner-card-header">
                    <div>
                        <div class="scanner-card-title">${escapeHtml(s.name)}</div>
                        <div class="scanner-card-id">${escapeHtml(s.id)} v${escapeHtml(s.version || '1.0')}</div>
                    </div>
                    <span class="badge ${statusClass}">${escapeHtml(statusLabel)}</span>
                </div>
                <div class="scanner-card-body">
                    <p class="scanner-card-desc">${escapeHtml(s.description || 'Static analysis and security verification module.')}</p>
                    ${codeqlWarning}
                    ${isCodeql && isNotInstalled ? '' : metaRow}
                </div>
            `;
            scannersCardsGrid.appendChild(card);
        });
    }

    /**
     * Handles the CODEQL_STATUS message from the extension host.
     * Updates the CodeQL status panel in the Local Scanners view.
     */
    function handleCodeqlStatus(data) {
        if (!codeqlStatusBadge) return;

        if (data.available) {
            codeqlStatusBadge.className = 'badge badge-success';
            codeqlStatusBadge.textContent = 'Installed';
            if (codeqlStatusText) codeqlStatusText.textContent = `GitHub CodeQL CLI v${data.version || 'unknown'} detected and ready.`;
            if (codeqlInstallGuide)  codeqlInstallGuide.style.display  = 'none';
            if (codeqlInstalledInfo) codeqlInstalledInfo.style.display = 'block';
            if (codeqlVersionDisplay) codeqlVersionDisplay.textContent = data.version || 'unknown';
            if (codeqlBinaryDisplay)  codeqlBinaryDisplay.textContent  = data.binaryPath || 'system PATH';
        } else {
            codeqlStatusBadge.className = 'badge badge-warning';
            codeqlStatusBadge.textContent = 'Not Installed';
            if (codeqlStatusText) codeqlStatusText.textContent = 'CodeQL CLI is not installed. Semantic data-flow analysis is unavailable.';
            if (codeqlInstallGuide)  codeqlInstallGuide.style.display  = 'block';
            if (codeqlInstalledInfo) codeqlInstalledInfo.style.display = 'none';
            if (codeqlInstallCmd) {
                const localPath = data.localBinPath || '';
                const installNote = localPath
                    ? `node scripts/setup-codeql.js  # installs to tools/codeql/`
                    : 'node scripts/setup-codeql.js';
                codeqlInstallCmd.textContent = installNote;
            }
        }
    }

    function renderScanHistory(history) {
        if (!scanHistoryTableBody) return;
        if (!history || history.length === 0) {
            scanHistoryTableBody.innerHTML = '<tr><td colspan="6" class="empty-cell u-empty-history-cell">No scan history recorded yet. Run a scan to discover local vulnerabilities.</td></tr>';
            return;
        }

        scanHistoryTableBody.innerHTML = '';
        history.forEach(item => {
            const tr = document.createElement('tr');
            const entry = formatScanHistoryEntry(item);
            const statusClass = entry.status === 'Completed' ? 'badge-success' : (entry.status === 'Failed' ? 'badge-danger' : 'badge-warning');

            tr.innerHTML = `
                <td><span class="font-mono u-fw-600 u-font-11">${escapeHtml(entry.scanId)}</span></td>
                <td><span class="u-font-11 u-text-muted">${escapeHtml(entry.dateStr)}</span></td>
                <td><span class="font-mono u-font-11">${escapeHtml(entry.targetBase)}</span></td>
                <td><span class="u-font-11">${entry.durationSec}</span></td>
                <td><span class="badge ${statusClass}">${escapeHtml(entry.status)}</span></td>
                <td>
                    <span class="u-fw-600">${entry.counts.total || 0}</span>
                    <span class="u-font-11 u-text-muted u-ml-4">
                        (${entry.counts.critical || 0} crit / ${entry.counts.high || 0} high / ${entry.counts.medium || 0} med)
                    </span>
                </td>
            `;
            scanHistoryTableBody.appendChild(tr);
        });
    }

    // --------------------------------------------------------------------------
    // Reports View Renderer
    // --------------------------------------------------------------------------
    function renderReportsList() {
        if (!reportsItemsList) return;

        const query = (reportsSearchInput?.value || '').toLowerCase().trim();
        const filtered = currentReports.filter(r => {
            if (!query) return true;
            return r.fileName.toLowerCase().includes(query) || (r.title || '').toLowerCase().includes(query) || (r.vulnerabilityId || '').toLowerCase().includes(query);
        });

        if (filtered.length === 0) {
            reportsItemsList.innerHTML = '<div class="empty-state"><p>No generated reports found.</p></div>';
            return;
        }

        reportsItemsList.innerHTML = filtered.map(r => `
            <div class="report-item ${selectedReport && selectedReport.filePath === r.filePath ? 'active' : ''}" data-path="${escapeHtml(r.filePath)}">
                <div class="report-item-title">${escapeHtml(r.title || r.fileName)}</div>
                <div class="report-item-sub">${escapeHtml(r.vulnerabilityId || '')} • ${(r.sizeBytes / 1024).toFixed(1)} KB</div>
            </div>
        `).join('');

        reportsItemsList.querySelectorAll('.report-item').forEach(item => {
            item.addEventListener('click', () => {
                const p = item.getAttribute('data-path');
                postToHost({ command: 'loadReportContent', filePath: p });
            });
        });

        if (!selectedReport && filtered.length > 0) {
            postToHost({ command: 'loadReportContent', filePath: filtered[0].filePath });
        }
    }

    // --------------------------------------------------------------------------
    // Modals & Utilities
    // --------------------------------------------------------------------------
    function renderSourceCodeModal(data) {
        if (!codeModal || !modalCodeContainer) return;

        if (modalFileName) modalFileName.textContent = data.relativePath || 'source-file.cs';
        if (modalFileLine) modalFileLine.textContent = `Line ${data.targetLine || 1}`;

        const lines = (data.code || '').split('\n');
        let html = '';

        lines.forEach((line, idx) => {
            const lineNo = idx + 1;
            const isTarget = lineNo === data.targetLine;
            html += `
                <div class="code-line ${isTarget ? 'target-line' : ''}" id="codeline-${lineNo}">
                    <span class="code-line-no">${lineNo}</span>
                    <span class="code-line-text">${escapeHtml(line)}</span>
                </div>
            `;
        });

        modalCodeContainer.innerHTML = html;
        codeModal.style.display = 'flex';

        setTimeout(() => {
            const targetEl = document.getElementById(`codeline-${data.targetLine}`);
            if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 100);
    }

    function openCopilotModal(prompt, manualSubmission = true) {
        if (!copilotModal) return;
        if (copilotCommandText) copilotCommandText.textContent = prompt;
        const modalSub = document.querySelector('#copilotModal .modal-subtitle');
        if (modalSub) {
            modalSub.textContent = manualSubmission
                ? 'Manual submission required: Press Enter in Copilot Chat to begin remediation.'
                : 'Copy and execute in Copilot Chat';
        }
        copilotModal.style.display = 'flex';
    }

    function showToast(text, status = 'info') {
        if (!toastContainer) return;

        const toast = document.createElement('div');
        toast.className = `toast ${status}`;

        let icon = 'ℹ️';
        if (status === 'success') icon = '✓';
        if (status === 'warning') icon = '⚠️';
        if (status === 'error') icon = '✕';

        toast.innerHTML = `
            <span class="u-fw-700">${icon}</span>
            <span class="u-flex-1">${escapeHtml(text)}</span>
        `;

        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(8px)';
            toast.style.transition = 'all 0.2s ease-out';
            setTimeout(() => toast.remove(), 200);
        }, 3200);
    }

    function getSeverityBadgeClass(sev) {
        const s = (sev || '').toLowerCase();
        if (s === 'critical') return 'badge-critical';
        if (s === 'high') return 'badge-high';
        if (s === 'medium') return 'badge-medium';
        return 'badge-low';
    }

    function getStatusBadgeClass(status, reviewRequired) {
        const s = (status || '').toLowerCase();
        if ((reviewRequired || '').toLowerCase() === 'true' || s.includes('review')) return 'badge-status-review';
        if (s === 'remediated' || s === 'completed' || s === 'pass') return 'badge-status-remediated';
        if (s === 'approved') return 'badge-status-approved';
        if (s.includes('progress')) return 'badge-status-inprogress';
        if (s.includes('fail')) return 'badge-status-failed';
        return 'badge-status-pending';
    }

    function renderColorizedDiff(patch) {
        if (!patch) return '';
        const lines = patch.split('\n');
        let html = '<div class="diff-container">';

        lines.forEach((line, idx) => {
            let lineClass = '';
            if (line.startsWith('+++') || line.startsWith('---')) lineClass = 'file';
            else if (line.startsWith('@@')) lineClass = 'chunk';
            else if (line.startsWith('+')) lineClass = 'add';
            else if (line.startsWith('-')) lineClass = 'del';

            html += `
                <div class="diff-line ${lineClass}">
                    <span class="diff-line-no">${idx + 1}</span>
                    <span class="diff-line-text">${escapeHtml(line)}</span>
                </div>
            `;
        });

        html += '</div>';
        return html;
    }

    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function renderMarkdown(rawMd) {
        if (!rawMd) return '';
        // 1. Strictly escape all raw text first to neutralize any injected HTML or scripts
        const escaped = escapeHtml(rawMd);

        // 2. Process code fences ```lang\ncode\n``` safely
        const codeBlocks = [];
        let textWithoutBlocks = escaped.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
            const placeholder = `__CODE_BLOCK_${codeBlocks.length}__`;
            codeBlocks.push(`<pre><code class="language-${lang || 'text'}">${code.trim()}</code></pre>`);
            return placeholder;
        });

        // 3. Process tables | col1 | col2 |
        const tableBlocks = [];
        textWithoutBlocks = textWithoutBlocks.replace(/(?:^|\n)(\|(?:[^\n]+\|)+)(?:\n\|(?:[ :\-]+(?:\|[ :\-]+)+))((?:\n\|(?:[^\n]+\|)+)+)/g, (match, headerRow, bodyRows) => {
            const placeholder = `__TABLE_BLOCK_${tableBlocks.length}__`;
            const parseRow = (r, isHeader) => {
                const cells = r.split('|').slice(1, -1).map(c => c.trim());
                const tag = isHeader ? 'th' : 'td';
                return `<tr>${cells.map(c => `<${tag}>${c}</${tag}>`).join('')}</tr>`;
            };
            const headerHtml = `<thead>${parseRow(headerRow, true)}</thead>`;
            const bodyHtml = `<tbody>${bodyRows.trim().split('\n').map(r => parseRow(r, false)).join('')}</tbody>`;
            tableBlocks.push(`<div class="table-responsive"><table class="markdown-table">${headerHtml}${bodyHtml}</table></div>`);
            return placeholder;
        });

        // 4. Line-by-line transformations
        const lines = textWithoutBlocks.split('\n');
        const formatted = [];
        let inList = false;

        for (let i = 0; i < lines.length; i++) {
            let line = lines[i];

            // Headers
            if (/^### (.*$)/.test(line)) {
                if (inList) { formatted.push('</ul>'); inList = false; }
                formatted.push(line.replace(/^### (.*$)/, '<h4>$1</h4>'));
                continue;
            }
            if (/^## (.*$)/.test(line)) {
                if (inList) { formatted.push('</ul>'); inList = false; }
                formatted.push(line.replace(/^## (.*$)/, '<h3>$1</h3>'));
                continue;
            }
            if (/^# (.*$)/.test(line)) {
                if (inList) { formatted.push('</ul>'); inList = false; }
                formatted.push(line.replace(/^# (.*$)/, '<h2>$1</h2>'));
                continue;
            }

            // Checkbox lists
            if (/^\s*[-*]\s*\[([ xX])\]\s*(.*$)/.test(line)) {
                if (!inList) { formatted.push('<ul class="markdown-checklist">'); inList = true; }
                formatted.push(line.replace(/^\s*[-*]\s*\[([ xX])\]\s*(.*$)/, (m, mark, item) => {
                    const checked = mark.toLowerCase() === 'x';
                    return `<li class="checklist-item"><input type="checkbox" disabled ${checked ? 'checked' : ''}> <span>${item}</span></li>`;
                }));
                continue;
            }

            // Unordered list items
            if (/^\s*[-*]\s+(.*$)/.test(line)) {
                if (!inList) { formatted.push('<ul>'); inList = true; }
                formatted.push(line.replace(/^\s*[-*]\s+(.*$)/, '<li>$1</li>'));
                continue;
            }

            // Blockquotes
            if (/^&gt;\s*(.*$)/.test(line)) {
                if (inList) { formatted.push('</ul>'); inList = false; }
                formatted.push(line.replace(/^&gt;\s*(.*$)/, '<blockquote>$1</blockquote>'));
                continue;
            }

            // End list if non-list line
            if (inList && line.trim() === '') {
                formatted.push('</ul>');
                inList = false;
            }

            // Empty line
            if (line.trim() === '') {
                formatted.push('');
                continue;
            }

            // Normal line
            formatted.push(`<p>${line}</p>`);
        }

        if (inList) {
            formatted.push('</ul>');
        }

        let outputHtml = formatted.join('\n');

        // Inline formatting (bold, italic, code)
        outputHtml = outputHtml
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\*([^*]+)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code>$1</code>');

        // Restore code blocks
        codeBlocks.forEach((block, idx) => {
            outputHtml = outputHtml.replace(`__CODE_BLOCK_${idx}__`, block);
        });

        // Restore tables
        tableBlocks.forEach((tbl, idx) => {
            outputHtml = outputHtml.replace(`__TABLE_BLOCK_${idx}__`, tbl);
        });

        return outputHtml;
    }

    // Auto-initialize on load when running in a browser/webview context
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
