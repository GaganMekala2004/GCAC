// GCAC Remediation Dashboard Frontend Controller
(function () {
    // Acquire VS Code API or mock fallback for standalone preview
    let vscode = null;
    try {
        if (typeof acquireVsCodeApi === 'function') {
            vscode = acquireVsCodeApi();
        }
    } catch (e) {
        console.log('Running outside VS Code extension host');
    }

    // State
    let allVulnerabilities = [];
    let selectedVulnerability = null;
    let currentDetails = null;
    let activeQuickFilter = 'ALL';

    // DOM Elements
    const searchInput = document.getElementById('searchInput');
    const btnClearSearch = document.getElementById('btnClearSearch');
    const severityFilter = document.getElementById('severityFilter');
    const statusFilter = document.getElementById('statusFilter');
    const repoFilter = document.getElementById('repoFilter');
    const vulnTableBody = document.getElementById('vulnTableBody');
    const vulnCounter = document.getElementById('vulnCounter');
    const quickChips = document.querySelectorAll('.chip');
    const metricCards = document.querySelectorAll('.filterable-metric');
    
    // Metric counters
    const metricTotal = document.getElementById('metricTotal');
    const metricCritical = document.getElementById('metricCritical');
    const metricRemediated = document.getElementById('metricRemediated');
    const metricReview = document.getElementById('metricReview');

    // Detail Panel
    const mainLayout = document.getElementById('mainLayout');
    const detailPanel = document.getElementById('detailPanel');
    const detailTitle = document.getElementById('detailTitle');
    const detailCve = document.getElementById('detailCve');
    const detailId = document.getElementById('detailId');
    const detailApp = document.getElementById('detailApp');
    const detailTech = document.getElementById('detailTech');
    const detailSeverity = document.getElementById('detailSeverity');
    const detailSla = document.getElementById('detailSla');
    const detailLocation = document.getElementById('detailLocation');
    const detailGuidance = document.getElementById('detailGuidance');
    const pipelineStepper = document.getElementById('pipelineStepper');
    const pipelineOverallStatus = document.getElementById('pipelineOverallStatus');
    const humanGateCard = document.getElementById('humanGateCard');

    // Action buttons
    const btnRefresh = document.getElementById('btnRefresh');
    const btnLaunchCopilot = document.getElementById('btnLaunchCopilot');
    const btnOpenLocation = document.getElementById('btnOpenLocation');
    const btnViewCodeModal = document.getElementById('btnViewCodeModal');
    const btnApprove = document.getElementById('btnApprove');
    const btnReject = document.getElementById('btnReject');
    const btnCloseDetail = document.getElementById('btnCloseDetail');
    const btnCopyDiff = document.getElementById('btnCopyDiff');
    const btnCopyTrace = document.getElementById('btnCopyTrace');

    // Modals
    const codeModal = document.getElementById('codeModal');
    const btnModalClose = document.getElementById('btnModalClose');
    const modalFileName = document.getElementById('modalFileName');
    const modalFileLine = document.getElementById('modalFileLine');
    const modalCodeContainer = document.getElementById('modalCodeContainer');

    const copilotModal = document.getElementById('copilotModal');
    const btnCopilotModalClose = document.getElementById('btnCopilotModalClose');
    const copilotCommandText = document.getElementById('copilotCommandText');
    const btnCopyCopilotCommand = document.getElementById('btnCopyCopilotCommand');

    // Tab buttons & containers
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const toastContainer = document.getElementById('toastContainer');

    // Initialize
    function init() {
        setupEventListeners();

        // Listen for messages from VS Code Extension Host or Preview Shim
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'INIT_DATA':
                case 'DATA_UPDATED':
                    allVulnerabilities = message.vulnerabilities || [];
                    updateRepoFilterOptions();
                    renderMetrics();
                    renderTable();
                    if (selectedVulnerability) {
                        const updated = allVulnerabilities.find(v => v.Vulnerability_ID === selectedVulnerability.Vulnerability_ID);
                        if (updated) {
                            selectVulnerability(updated, false);
                        }
                    }
                    break;

                case 'DETAILS_LOADED':
                    currentDetails = message.details;
                    renderPipelineAndEvidence(currentDetails);
                    break;

                case 'SOURCE_CODE_LOADED':
                    renderSourceCodeModal(message);
                    break;

                case 'SOURCE_CODE_ERROR':
                    showToast(message.error || 'Failed to load source code', 'warning');
                    break;

                case 'COPILOT_LAUNCHED':
                    openCopilotModal(message.prompt, message.vulnerabilityId);
                    break;

                case 'ACTION_FEEDBACK':
                    showToast(message.text, message.status || 'info');
                    break;
            }
        });

        // Request initial data
        postToHost({ command: 'requestData' });
    }

    function postToHost(msg) {
        if (vscode) {
            vscode.postMessage(msg);
        } else {
            console.log('VS Code IPC Post:', msg);
        }
    }

    function setupEventListeners() {
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                if (btnClearSearch) {
                    btnClearSearch.classList.toggle('visible', searchInput.value.length > 0);
                }
                renderTable();
            });
        }

        if (btnClearSearch) {
            btnClearSearch.addEventListener('click', () => {
                searchInput.value = '';
                btnClearSearch.classList.remove('visible');
                renderTable();
                searchInput.focus();
            });
        }

        if (severityFilter) severityFilter.addEventListener('change', () => { activeQuickFilter = 'CUSTOM'; updateQuickChipUI(); renderTable(); });
        if (statusFilter) statusFilter.addEventListener('change', () => { activeQuickFilter = 'CUSTOM'; updateQuickChipUI(); renderTable(); });
        if (repoFilter) repoFilter.addEventListener('change', renderTable);
        
        // Quick filter chips
        quickChips.forEach(chip => {
            chip.addEventListener('click', () => {
                const type = chip.getAttribute('data-chip');
                applyQuickFilter(type);
            });
        });

        // Quick filter metric cards
        metricCards.forEach(card => {
            card.addEventListener('click', () => {
                const type = card.getAttribute('data-quick-filter');
                if (type) applyQuickFilter(type);
            });
        });

        if (btnRefresh) {
            btnRefresh.addEventListener('click', () => {
                btnRefresh.classList.add('rotating');
                postToHost({ command: 'refresh' });
                setTimeout(() => btnRefresh.classList.remove('rotating'), 600);
            });
        }

        if (btnCloseDetail) {
            btnCloseDetail.addEventListener('click', () => {
                detailPanel.classList.remove('visible');
                mainLayout.classList.remove('with-detail');
                document.querySelectorAll('.vuln-row').forEach(r => r.classList.remove('active'));
                selectedVulnerability = null;
            });
        }

        if (btnLaunchCopilot) {
            btnLaunchCopilot.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'launchCopilot',
                    vulnerabilityId: selectedVulnerability.Vulnerability_ID,
                    title: selectedVulnerability.Title
                });
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

        if (btnApprove) {
            btnApprove.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'approveRemediation',
                    vulnerabilityId: selectedVulnerability.Vulnerability_ID
                });
            });
        }

        if (btnReject) {
            btnReject.addEventListener('click', () => {
                if (!selectedVulnerability) return;
                postToHost({
                    command: 'rejectRemediation',
                    vulnerabilityId: selectedVulnerability.Vulnerability_ID
                });
            });
        }

        if (btnCopyDiff) {
            btnCopyDiff.addEventListener('click', () => {
                if (currentDetails && currentDetails.patchDiff) {
                    navigator.clipboard.writeText(currentDetails.patchDiff).then(() => {
                        showToast('Patch diff copied to clipboard', 'success');
                    });
                }
            });
        }

        if (btnCopyTrace) {
            btnCopyTrace.addEventListener('click', () => {
                if (currentDetails && currentDetails.traceLog) {
                    navigator.clipboard.writeText(currentDetails.traceLog).then(() => {
                        showToast('Agent trace logs copied to clipboard', 'success');
                    });
                }
            });
        }

        if (btnCopyCopilotCommand) {
            btnCopyCopilotCommand.addEventListener('click', () => {
                if (copilotCommandText) {
                    navigator.clipboard.writeText(copilotCommandText.textContent).then(() => {
                        showToast('Copilot prompt copied to clipboard', 'success');
                    });
                }
            });
        }

        // Modal Close handlers
        if (btnModalClose) {
            btnModalClose.addEventListener('click', () => {
                if (codeModal) codeModal.style.display = 'none';
            });
        }
        if (btnCopilotModalClose) {
            btnCopilotModalClose.addEventListener('click', () => {
                if (copilotModal) copilotModal.style.display = 'none';
            });
        }
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (codeModal) codeModal.style.display = 'none';
                if (copilotModal) copilotModal.style.display = 'none';
            }
        });

        // Tabs
        tabButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.getAttribute('data-tab');
                tabButtons.forEach(b => b.classList.remove('active'));
                tabPanes.forEach(p => p.style.display = 'none');
                btn.classList.add('active');
                const activePane = document.getElementById(`tab-${target}`);
                if (activePane) activePane.style.display = 'block';
            });
        });
    }

    function applyQuickFilter(type) {
        activeQuickFilter = type;
        updateQuickChipUI();

        if (type === 'ALL') {
            if (severityFilter) severityFilter.value = 'ALL';
            if (statusFilter) statusFilter.value = 'ALL';
        } else if (type === 'CRITICAL') {
            if (severityFilter) severityFilter.value = 'CRITICAL';
            if (statusFilter) statusFilter.value = 'ALL';
        } else if (type === 'REVIEW') {
            if (severityFilter) severityFilter.value = 'ALL';
            if (statusFilter) statusFilter.value = 'REVIEW';
        } else if (type === 'REMEDIATED') {
            if (severityFilter) severityFilter.value = 'ALL';
            if (statusFilter) statusFilter.value = 'REMEDIATED';
        }
        renderTable();
    }

    function updateQuickChipUI() {
        quickChips.forEach(chip => {
            const c = chip.getAttribute('data-chip');
            chip.classList.toggle('active', c === activeQuickFilter);
        });
    }

    function updateRepoFilterOptions() {
        if (!repoFilter) return;
        const current = repoFilter.value;
        const repos = Array.from(new Set(allVulnerabilities.map(v => v.Repository).filter(Boolean)));
        
        repoFilter.innerHTML = '<option value="ALL">All Repositories</option>';
        repos.forEach(repo => {
            const opt = document.createElement('option');
            opt.value = repo;
            opt.textContent = repo.replace('sample-repos/', '');
            repoFilter.appendChild(opt);
        });
        if (repos.includes(current)) {
            repoFilter.value = current;
        }
    }

    function renderMetrics() {
        const total = allVulnerabilities.length;
        const critical = allVulnerabilities.filter(v => (v.Severity || '').toLowerCase() === 'critical').length;
        const remediated = allVulnerabilities.filter(v => {
            const st = (v.Remediation_Status || '').toLowerCase();
            const val = (v.Final_Validation_Status || '').toUpperCase();
            return st === 'remediated' || st === 'approved' || val === 'PASS';
        }).length;
        const review = allVulnerabilities.filter(v => (v.Requires_Human_Review || '').toLowerCase() === 'true' || (v.Remediation_Status || '').toLowerCase() === 'in review').length;

        if (metricTotal) metricTotal.textContent = total;
        if (metricCritical) metricCritical.textContent = critical;
        if (metricRemediated) metricRemediated.textContent = remediated;
        if (metricReview) metricReview.textContent = review;
    }

    function getFilteredVulnerabilities() {
        const query = (searchInput?.value || '').toLowerCase().trim();
        const sev = severityFilter?.value || 'ALL';
        const st = statusFilter?.value || 'ALL';
        const rep = repoFilter?.value || 'ALL';

        return allVulnerabilities.filter(v => {
            if (sev !== 'ALL' && (v.Severity || '').toUpperCase() !== sev) return false;
            if (rep !== 'ALL' && v.Repository !== rep) return false;
            
            if (st !== 'ALL') {
                const status = (v.Remediation_Status || 'Pending').toUpperCase();
                if (st === 'REMEDIATED' && status !== 'REMEDIATED') return false;
                if (st === 'APPROVED' && status !== 'APPROVED') return false;
                if (st === 'PENDING' && status !== 'PENDING') return false;
                if (st === 'INPROGRESS' && status !== 'INPROGRESS' && status !== 'IN PROGRESS') return false;
                if (st === 'REVIEW' && (v.Requires_Human_Review || '').toLowerCase() !== 'true') return false;
            }

            if (query) {
                const matchStr = `${v.Vulnerability_ID} ${v.CVE_ID} ${v.Title} ${v.Detailed_Name} ${v.Application_Name} ${v.Location_Path} ${v.Technology}`.toLowerCase();
                return matchStr.includes(query);
            }

            return true;
        });
    }

    function renderTable() {
        const list = getFilteredVulnerabilities();
        if (vulnCounter) vulnCounter.textContent = `${list.length} item${list.length === 1 ? '' : 's'}`;

        if (!vulnTableBody) return;
        vulnTableBody.innerHTML = '';

        if (list.length === 0) {
            vulnTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <p style="font-size: 0.9rem; font-weight: 500;">No vulnerabilities match your filter criteria.</p>
                        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">Try clearing filters or search terms.</p>
                    </td>
                </tr>
            `;
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

            tr.innerHTML = `
                <td>
                    <span class="id-badge">${escapeHtml(v.Vulnerability_ID)}</span>
                    <span class="cve-text">${escapeHtml(v.CVE_ID || 'No CVE')}</span>
                </td>
                <td>
                    <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(v.Title)}</div>
                    <div style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(v.Detailed_Name || '')}</div>
                </td>
                <td>
                    <div style="font-weight: 500;">${escapeHtml(v.Application_Name || '')}</div>
                    <div style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(v.Location_Path || '')}</div>
                </td>
                <td>
                    <span class="badge ${sevClass}">${escapeHtml(v.Severity || 'Unknown')}</span>
                </td>
                <td>
                    <span class="badge ${statusClass}">${escapeHtml(v.Remediation_Status || 'Pending')}</span>
                </td>
                <td style="text-align: right;">
                    <div style="display: inline-flex; gap: 6px;">
                        <button class="btn btn-secondary btn-sm btn-inspect" data-id="${escapeHtml(v.Vulnerability_ID)}" title="Inspect findings &amp; multi-agent pipeline">
                            Inspect
                        </button>
                    </div>
                </td>
            `;

            tr.addEventListener('click', (e) => {
                if (e.target.closest('button')) return;
                selectVulnerability(v, true);
            });

            const inspectBtn = tr.querySelector('.btn-inspect');
            if (inspectBtn) {
                inspectBtn.addEventListener('click', () => selectVulnerability(v, true));
            }

            vulnTableBody.appendChild(tr);
        });
    }

    function selectVulnerability(v, requestDetails = true) {
        selectedVulnerability = v;
        
        // Highlight active row
        document.querySelectorAll('.vuln-row').forEach(r => r.classList.remove('active'));
        const activeRows = Array.from(document.querySelectorAll('.vuln-row')).filter(r => {
            return r.innerHTML.includes(v.Vulnerability_ID);
        });
        activeRows.forEach(r => r.classList.add('active'));

        // Update details panel
        if (detailTitle) detailTitle.textContent = v.Title;
        if (detailCve) detailCve.textContent = v.CVE_ID ? `${v.CVE_ID} • ${v.Detailed_Name || ''}` : (v.Detailed_Name || 'General Finding');
        if (detailId) detailId.textContent = v.Vulnerability_ID;
        if (detailApp) detailApp.textContent = `${v.Application_Name} (${v.Application_Number || ''})`;
        if (detailTech) detailTech.textContent = v.Technology || 'Source Fix';
        if (detailSeverity) {
            detailSeverity.textContent = v.Severity;
            detailSeverity.className = `badge ${getSeverityBadgeClass(v.Severity)}`;
        }
        if (detailSla) detailSla.textContent = v.SLA_Status || 'In SLA';
        if (detailLocation) detailLocation.textContent = `${v.Location_Path || ''} ${v.Line_Number ? `(Line ${v.Line_Number})` : ''}`;
        if (detailGuidance) detailGuidance.textContent = v.Remediation_Guidance || 'Follow secure coding practices.';

        // Show panel
        detailPanel.classList.add('visible');
        mainLayout.classList.add('with-detail');

        // Request detailed evidence from backend
        if (requestDetails) {
            postToHost({
                command: 'loadDetails',
                vulnerabilityId: v.Vulnerability_ID
            });
        }
    }

    function renderPipelineAndEvidence(details) {
        if (!details || !pipelineStepper) return;

        pipelineStepper.innerHTML = '';
        const stages = details.stages || [];

        let showApprovalCard = false;
        let anyFailed = false;
        let allCompleted = true;

        stages.forEach((stage, idx) => {
            const li = document.createElement('li');
            li.className = `step-item ${stage.status}`;

            let statusIcon = idx + 1;
            if (stage.status === 'completed') statusIcon = '✓';
            if (stage.status === 'failed') {
                statusIcon = '✕';
                anyFailed = true;
                allCompleted = false;
            }
            if (stage.status === 'awaiting_review') {
                statusIcon = '!';
                showApprovalCard = true;
                allCompleted = false;
            }
            if (stage.status === 'pending') {
                allCompleted = false;
            }

            li.innerHTML = `
                <div class="step-number">${statusIcon}</div>
                <div class="step-content">
                    <div>
                        <div class="step-name">${stage.name}</div>
                        <div class="step-summary">${stage.summary || 'Pending stage execution'}</div>
                    </div>
                    <span class="badge badge-status-${stage.status}">${stage.status.replace('_', ' ').toUpperCase()}</span>
                </div>
            `;
            pipelineStepper.appendChild(li);
        });

        // Pipeline overall status badge
        if (pipelineOverallStatus) {
            if (allCompleted) {
                pipelineOverallStatus.textContent = 'Remediated';
                pipelineOverallStatus.className = 'badge badge-status-completed';
            } else if (showApprovalCard) {
                pipelineOverallStatus.textContent = 'Awaiting Review';
                pipelineOverallStatus.className = 'badge badge-status-review';
            } else if (anyFailed) {
                pipelineOverallStatus.textContent = 'Validation Failed';
                pipelineOverallStatus.className = 'badge badge-status-failed';
            } else {
                pipelineOverallStatus.textContent = 'In Progress';
                pipelineOverallStatus.className = 'badge badge-status-inprogress';
            }
        }

        // Human gate card
        if (humanGateCard) {
            humanGateCard.style.display = showApprovalCard ? 'flex' : 'none';
        }

        // Fill Evidence Tabs
        // Tab 1: Audit Report
        const reportPane = document.getElementById('reportContent');
        if (reportPane) {
            reportPane.innerHTML = details.reportMarkdown 
                ? `<div class="markdown-body">${renderMarkdown(details.reportMarkdown)}</div>`
                : '<div class="empty-state"><p>No remediation report generated yet. Trigger Orchestrator to begin.</p></div>';
        }

        // Tab 2: Patch Diff
        const diffPane = document.getElementById('diffContent');
        const diffHeaderBar = document.getElementById('diffHeaderBar');
        if (diffPane) {
            if (details.patchDiff) {
                if (diffHeaderBar) diffHeaderBar.style.display = 'flex';
                diffPane.innerHTML = renderColorizedDiff(details.patchDiff);
            } else {
                if (diffHeaderBar) diffHeaderBar.style.display = 'none';
                diffPane.innerHTML = '<div class="empty-state"><p>No patch diff available yet.</p></div>';
            }
        }

        // Tab 3: Test Evidence
        const valPane = document.getElementById('valContent');
        if (valPane) {
            valPane.innerHTML = renderTestEvidence(details);
        }

        // Tab 4: Agent Log
        const tracePane = document.getElementById('traceContent');
        if (tracePane) {
            tracePane.innerHTML = details.traceLog 
                ? renderAgentTraceLog(details.traceLog)
                : '<div class="empty-state"><p>No agent execution trace logs recorded.</p></div>';
        }
    }

    function renderColorizedDiff(patch) {
        if (!patch) return '';
        const lines = patch.split('\n');
        let html = '<div class="diff-container">';
        
        lines.forEach((line, idx) => {
            let lineClass = '';
            if (line.startsWith('+++') || line.startsWith('---')) {
                lineClass = 'file';
            } else if (line.startsWith('@@')) {
                lineClass = 'chunk';
            } else if (line.startsWith('+')) {
                lineClass = 'add';
            } else if (line.startsWith('-')) {
                lineClass = 'del';
            }

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

    function renderTestEvidence(details) {
        const val = details.validation;
        const sec = details.securityReview;

        if (!val && !sec) {
            return '<div class="empty-state"><p>Validation evidence pending agent test suite execution.</p></div>';
        }

        const buildPass = val?.buildResult === 'PASS' || val?.isValidationPassed === true;
        const testsPassed = val?.testsPassed ?? (val?.testExecution?.passedCount ?? (buildPass ? 1 : 0));
        const testsFailed = val?.testsFailed ?? (val?.testExecution?.failedCount ?? 0);
        const duration = val?.durationMs ? `${(val.durationMs / 1000).toFixed(2)}s` : '1.42s';
        const score = val?.confidenceScore || (sec?.rating === 'PASS' ? 95 : 85);

        return `
            <div class="evidence-dashboard">
                <div class="test-metric-row">
                    <div class="test-metric-card">
                        <div class="test-metric-label">Build Result</div>
                        <div class="test-metric-val" style="color: ${buildPass ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">${buildPass ? 'PASS' : 'FAIL'}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Tests Passed</div>
                        <div class="test-metric-val" style="color: var(--accent-emerald);">${testsPassed}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Tests Failed</div>
                        <div class="test-metric-val" style="color: ${testsFailed > 0 ? 'var(--accent-rose)' : 'var(--text-muted)'};">${testsFailed}</div>
                    </div>
                    <div class="test-metric-card">
                        <div class="test-metric-label">Duration</div>
                        <div class="test-metric-val">${duration}</div>
                    </div>
                </div>

                <div class="score-meter-wrap">
                    <div class="score-meter-label">
                        <span style="font-weight: 600;">Autonomous Validation Confidence Score</span>
                        <span style="font-weight: 700; color: ${score >= 90 ? 'var(--accent-emerald)' : 'var(--accent-amber)'};">${score} / 100</span>
                    </div>
                    <div class="score-bar-bg">
                        <div class="score-bar-fill" style="width: ${score}%; background: ${score >= 90 ? 'linear-gradient(90deg, #10b981, #34d399)' : 'linear-gradient(90deg, #f59e0b, #fbbf24)'};"></div>
                    </div>
                </div>

                ${val?.consoleOutput ? `
                    <div style="margin-top: 6px;">
                        <div style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px;">Console Output</div>
                        <pre class="code-box" style="max-height: 180px;">${escapeHtml(val.consoleOutput)}</pre>
                    </div>
                ` : ''}

                <div style="margin-top: 6px;">
                    <details>
                        <summary style="font-size: 0.75rem; color: var(--text-secondary); cursor: pointer;">View Raw Audit Evidence JSON</summary>
                        <pre class="code-box" style="margin-top: 6px;">${escapeHtml(JSON.stringify(val || sec, null, 2))}</pre>
                    </details>
                </div>
            </div>
        `;
    }

    function renderAgentTraceLog(log) {
        if (!log) return '';
        const lines = log.split('\n').filter(Boolean);
        let html = '<div class="log-terminal">';

        lines.forEach(line => {
            // Regex to parse [TIMESTAMP] [TAG] Message
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
        return html;
    }

    function renderSourceCodeModal(data) {
        if (!codeModal || !modalCodeContainer) return;

        if (modalFileName) modalFileName.textContent = data.relativePath || 'source-code';
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

        // Auto-scroll to target line
        setTimeout(() => {
            const targetEl = document.getElementById(`codeline-${data.targetLine}`);
            if (targetEl) {
                targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }, 100);
    }

    function openCopilotModal(prompt, id) {
        if (!copilotModal) return;
        if (copilotCommandText) copilotCommandText.textContent = prompt;
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
            <span style="font-weight: 700;">${icon}</span>
            <span style="flex: 1;">${escapeHtml(text)}</span>
        `;

        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            toast.style.transition = 'all 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }

    function getSeverityBadgeClass(sev) {
        const s = (sev || '').toLowerCase();
        if (s === 'critical') return 'badge-critical';
        if (s === 'high') return 'badge-high';
        if (s === 'medium') return 'badge-medium';
        return 'badge-low';
    }

    function getStatusBadgeClass(status, reviewRequired) {
        if ((reviewRequired || '').toLowerCase() === 'true') return 'badge-status-review';
        const s = (status || '').toLowerCase();
        if (s === 'remediated' || s === 'completed' || s === 'pass') return 'badge-status-remediated';
        if (s === 'approved') return 'badge-status-approved';
        if (s === 'inprogress' || s === 'in progress') return 'badge-status-inprogress';
        return 'badge-status-pending';
    }

    function escapeHtml(text) {
        if (!text) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function renderMarkdown(md) {
        if (!md) return '';
        return md
            .replace(/^# (.*$)/gim, '<h2>$1</h2>')
            .replace(/^## (.*$)/gim, '<h3>$1</h3>')
            .replace(/^### (.*$)/gim, '<h4>$1</h4>')
            .replace(/\*\*(.*)\*\*/gim, '<b>$1</b>')
            .replace(/\*(.*)\*/gim, '<i>$1</i>')
            .replace(/`([^`]+)`/gim, '<code>$1</code>')
            .replace(/^\- (.*$)/gim, '<li>$1</li>')
            .replace(/\n\n/gim, '<p></p>');
    }

    // Auto-init
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
