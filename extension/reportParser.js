const fs = require('fs');
const path = require('path');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('./contentInjectionScreen');
const { verifyEvidencePackage } = require('./evidenceLedger');
const {
    RUN_STATE_SCHEMA_VERSION,
    WORKFLOW_LIFECYCLE,
    VALIDATION_OUTCOME,
    APPROVAL_DECISION,
    FORMAL_CLOSURE,
    FINDING_STATE,
    normalizeCanonicalRunState,
    deriveTerminalBanner
} = require('./runStateContract');
const { buildEvidenceChecklist } = require('./evidenceChecklist');

/**
 * Normalizes a vulnerability ID or filename token for safe, deterministic matching.
 * Handles hyphen-to-underscore conversions (e.g. VUL-POC-001 vs vul_poc_001)
 * and guards against substring collisions (e.g. VUL-POC-001 vs VUL-POC-0010).
 */
function isReportMatchForVulnerability(fileName, vulnerabilityId) {
    if (!fileName || !vulnerabilityId || !fileName.endsWith('.md')) return false;

    // Direct match check
    const cleanId = vulnerabilityId.trim();
    const escapedPattern = cleanId.replace(/[-_]/g, '[-_]');
    const boundaryRegex = new RegExp(`(?:^|[_-])${escapedPattern}(?:[_-]|\\.)`, 'i');
    if (boundaryRegex.test(fileName)) {
        return true;
    }

    // Normalized alphanumeric check as secondary guarantee
    const normId = cleanId.toLowerCase().replace(/[^a-z0-9]/g, '');
    const normFile = fileName.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (normFile.endsWith(normId + 'md') || normFile.includes(normId)) {
        // Ensure no trailing digit collision (e.g. vulpoc001 vs vulpoc0010)
        const idx = normFile.indexOf(normId);
        const nextChar = normFile.charAt(idx + normId.length);
        if (!nextChar || nextChar === 'm' || isNaN(parseInt(nextChar, 10))) {
            return true;
        }
    }

    return false;
}

/**
 * Reads remediation artifacts and reports for a given vulnerability ID from all possible sources:
 * 1. remediation-output/<id>/
 * 2. evidence/<id>/
 * 3. output/<title>_<id>.md (Shared Markdown Report)
 * Also extracts patch diff, trace logs, and test evidence directly from markdown if files are omitted.
 */
function loadVulnerabilityDetails(workspaceRoot, vulnerabilityId) {
    const details = {
        vulnerabilityId,
        hasEvidence: false,
        reportMarkdown: '',
        patchDiff: '',
        finding: null,
        classification: null,
        validation: null,
        securityReview: null,
        traceLog: '',
        evidenceRecord: null,
        integrityVerification: null,
        approvalRecord: null,
        remediationDecision: null,
        sourceToSinkEvidence: null,
        injectionScreening: null,
        runState: null,
        baselineValidation: null,
        reScanVerification: null,
        findingContext: null,
        runId: null,
        attemptId: null,
        attemptNumber: 0,
        retryCount: 0,
        attemptHistory: [],
        failedStage: null,
        failedStageId: null,
        failureCategory: null,
        failureReason: null,
        retryEligibility: null,
        schemaVersion: RUN_STATE_SCHEMA_VERSION,
        workflowLifecycle: WORKFLOW_LIFECYCLE.NOT_STARTED,
        securityValidationOutcome: VALIDATION_OUTCOME.NOT_EXECUTED,
        approvalDecision: APPROVAL_DECISION.NOT_REQUESTED,
        formalClosure: FORMAL_CLOSURE.OPEN,
        findingState: FINDING_STATE.OPEN,
        terminalBanner: '',
        handoff: null,
        lastAppliedSeq: 0,
        stages: [
            {
                id: 'intake',
                name: 'Stage 1: Intake & Mapping',
                number: 1,
                stageNumber: 1,
                type: 'agent',
                status: 'pending',
                summary: 'Resolve single finding identity, canonical repository path, and file context.',
                bullets: [
                    'Validate single-finding metadata',
                    'Resolve canonical repository root',
                    'Build isolated workspace context'
                ]
            },
            {
                id: 'classification',
                name: 'Stage 2: Classification Agent',
                number: 2,
                stageNumber: 2,
                type: 'agent',
                status: 'pending',
                summary: 'Classify vulnerability severity, CWE, remediation route & priority.',
                bullets: [
                    'Classify by severity, CWE, type',
                    'Enforce immutable scanner severity',
                    'Assess exploitability & prioritize strategy'
                ]
            },
            {
                id: 'analysis',
                name: 'Stage 3: Source Analysis & Baseline',
                number: 3,
                stageNumber: 3,
                type: 'agent',
                status: 'pending',
                summary: 'Locate vulnerable code, analyze data flow, baseline build/test & prepare proposal.',
                bullets: [
                    'Locate vulnerable code (file, line)',
                    'Trace source-to-sink data flow',
                    'Run baseline tests & prepare minimal patch proposal'
                ]
            },
            {
                id: 'human-gate',
                name: 'Stage 4: Human Approval Gate',
                number: 4,
                stageNumber: 4,
                type: 'gate',
                status: 'pending',
                summary: 'Review root-cause analysis and proposed code diff before workspace mutation.',
                bullets: [
                    'Review vulnerability analysis and diff-bound proposal',
                    'Authorize isolated code modification or request rework'
                ]
            },
            {
                id: 'remediation',
                name: 'Stage 5: Isolated Code Remediation',
                number: 5,
                stageNumber: 5,
                type: 'agent',
                status: 'pending',
                summary: 'Apply approved code changes strictly within file-scope inside isolated worktree.',
                bullets: [
                    'Verify diff-bound Stage 4 authorization',
                    'Apply approved patch inside isolated git worktree',
                    'Enforce post-apply scope and test protection rules'
                ]
            },
            {
                id: 'bench-test',
                name: 'Stage 6: Bench Test & Re-Scan',
                number: 6,
                stageNumber: 6,
                type: 'agent',
                status: 'pending',
                summary: 'Execute real build/unit tests and run targeted post-fix scanner verification.',
                bullets: [
                    'Execute targeted unit tests in approved runner',
                    'Re-scan modified file with originating scanner',
                    'Fail closed on build errors, zero tests, or regression'
                ]
            },
            {
                id: 'security-review',
                name: 'Stage 7: Security Review & Evidence',
                number: 7,
                stageNumber: 7,
                type: 'agent',
                status: 'pending',
                summary: 'Evaluate deterministic security evidence checklist across patch, tests, and re-scan.',
                bullets: [
                    'Inspect test execution & originating scanner results',
                    'Audit secret rotation / externalization requirements',
                    'Verify SHA-256 evidence manifest completeness'
                ]
            },
            {
                id: 'final-human-gate',
                name: 'Stage 8: Final Human Sign-Off',
                number: 8,
                stageNumber: 8,
                type: 'gate',
                status: 'pending',
                summary: 'Final human review gate prior to formal closure (blocked unless validation passed).',
                bullets: [
                    'Confirm verified validation & evidence checklist',
                    'Sign off or request revision/rework'
                ]
            },
            {
                id: 'manual-validations',
                name: 'Stage 9: Workflow Closure',
                number: 9,
                stageNumber: 9,
                type: 'non-agentic',
                status: 'pending',
                summary: 'Conclude workflow, persist immutable ledger, and record operational handoff state.',
                bullets: [
                    'Record final canonical workflow & validation status',
                    'Persist tamper-detectable evidence manifest & trace'
                ]
            }
        ]
    };

    // Candidate directories to search for artifacts
    const candidateDirs = [
        path.join(workspaceRoot, 'remediation-output', vulnerabilityId),
        path.join(workspaceRoot, 'evidence', vulnerabilityId)
    ];

    for (const dir of candidateDirs) {
        if (fs.existsSync(dir)) {
            details.hasEvidence = true;

            const reportPath = path.join(dir, 'remediation-report.md');
            if (fs.existsSync(reportPath) && !details.reportMarkdown) {
                try { details.reportMarkdown = fs.readFileSync(reportPath, 'utf-8'); } catch (e) { }
            }

            const patchPath = path.join(dir, 'changes.patch');
            if (fs.existsSync(patchPath) && !details.patchDiff) {
                try { details.patchDiff = fs.readFileSync(patchPath, 'utf-8'); } catch (e) { }
            }

            const findingPath = path.join(dir, 'finding.json');
            if (fs.existsSync(findingPath) && !details.finding) {
                try { details.finding = JSON.parse(fs.readFileSync(findingPath, 'utf-8')); } catch (e) { }
            }

            const classPath = path.join(dir, 'classification.json');
            if (fs.existsSync(classPath) && !details.classification) {
                try { details.classification = JSON.parse(fs.readFileSync(classPath, 'utf-8')); } catch (e) { }
            }

            const valPath = path.join(dir, 'validation.json');
            if (fs.existsSync(valPath) && !details.validation) {
                try { details.validation = JSON.parse(fs.readFileSync(valPath, 'utf-8')); } catch (e) { }
            }

            const sbxPath = path.join(dir, 'sandbox-execution.json');
            if (fs.existsSync(sbxPath) && !details.sandboxExecution) {
                try { details.sandboxExecution = JSON.parse(fs.readFileSync(sbxPath, 'utf-8')); } catch (e) { }
            }

            const sbomPath = path.join(dir, 'sbom.cdx.json');
            if (fs.existsSync(sbomPath) && !details.sbomEvidence) {
                try {
                    const rawSbom = JSON.parse(fs.readFileSync(sbomPath, 'utf-8'));
                    const props = rawSbom?.metadata?.properties || [];
                    const getProp = (k) => props.find(p => p.name === k)?.value || null;
                    details.sbomEvidence = {
                        format: `${rawSbom.bomFormat || 'CycloneDX'}/${rawSbom.specVersion || '1.5'}`,
                        componentCount: Array.isArray(rawSbom.components) ? rawSbom.components.length : 0,
                        externalSbomCliStatus: getProp('gcac:externalSbomCliStatus') || 'NOT_AVAILABLE',
                        sbomStatus: getProp('gcac:sbomStatus') || (Array.isArray(rawSbom.components) && rawSbom.components.length > 0 ? 'MANIFEST_INVENTORY_ONLY' : 'NOT_AVAILABLE')
                    };
                } catch (e) { }
            }

            const secPath = path.join(dir, 'security-review.json');
            if (fs.existsSync(secPath) && !details.securityReview) {
                try { details.securityReview = JSON.parse(fs.readFileSync(secPath, 'utf-8')); } catch (e) { }
            }

            const tracePath = path.join(dir, 'agent-execution-trace.log');
            if (fs.existsSync(tracePath) && !details.traceLog) {
                try { details.traceLog = fs.readFileSync(tracePath, 'utf-8'); } catch (e) { }
            }

            const evidenceRecPath = path.join(dir, 'evidence-record.json');
            if (fs.existsSync(evidenceRecPath) && !details.evidenceRecord) {
                try { details.evidenceRecord = JSON.parse(fs.readFileSync(evidenceRecPath, 'utf-8')); } catch (e) { }
            }

            const approvalRecPath = path.join(dir, 'approval-record.json');
            if (fs.existsSync(approvalRecPath) && !details.approvalRecord) {
                try { details.approvalRecord = JSON.parse(fs.readFileSync(approvalRecPath, 'utf-8')); } catch (e) { }
            }

            const decisionPath = path.join(dir, 'remediation-decision.json');
            if (fs.existsSync(decisionPath) && !details.remediationDecision) {
                try { details.remediationDecision = JSON.parse(fs.readFileSync(decisionPath, 'utf-8')); } catch (e) { }
            }

            const s2sPath = path.join(dir, 'source-to-sink.json');
            if (fs.existsSync(s2sPath) && !details.sourceToSinkEvidence) {
                try { details.sourceToSinkEvidence = JSON.parse(fs.readFileSync(s2sPath, 'utf-8')); } catch (e) { }
            }

            const runStatePath = path.join(dir, 'run-state.json');
            if (fs.existsSync(runStatePath) && !details.runState) {
                try {
                    const rawRs = JSON.parse(fs.readFileSync(runStatePath, 'utf-8'));
                    const rs = normalizeCanonicalRunState(rawRs, vulnerabilityId);
                    details.runState = rs;
                    details.executionMode = rs.executionMode || 'ENTERPRISE';
                    details.localOutcome = rs.localOutcome || null;
                    details.verifiedRemediation = rs.verifiedRemediation === true;
                    details.runId = rs.runId || null;
                    details.attemptId = rs.attemptId || null;
                    details.attemptNumber = Number(rs.attemptNumber || 1);
                    details.retryCount = Number(rs.retryCount || 0);
                    details.attemptHistory = Array.isArray(rs.attemptHistory) ? rs.attemptHistory : [];
                    details.failedStage = rs.failedStage ?? null;
                    details.failedStageId = rs.failedStageId || null;
                    details.failureCategory = rs.failureCategory || null;
                    details.failureReason = rs.failureReason || null;
                    details.status = rs.status || (rs.workflowLifecycle === 'BLOCKED' ? 'BLOCKED' : details.status);
                    details.retryEligibility = rs.retryEligibility || null;
                    details.workflowLifecycle = rs.workflowLifecycle;
                    details.securityValidationOutcome = rs.securityValidationOutcome;
                    details.approvalDecision = rs.approvalDecision;
                    details.formalClosure = rs.formalClosure;
                    details.findingState = rs.findingState;
                    details.terminalBanner = rs.terminalBanner;
                    if (rs.failureCategory === 'TOOLCHAIN_IMAGE_UNAVAILABLE' || (details.failureReason && /is not present in local runtime cache|template placeholder|UNPROVISIONED_TOOLCHAIN_PROFILE/i.test(details.failureReason))) {
                        details.failureCategory = 'TOOLCHAIN_IMAGE_UNAVAILABLE';
                        details.workflowLifecycle = 'BLOCKED';
                        details.findingState = 'COULD_NOT_RUN';
                        details.formalClosure = 'COULD_NOT_RUN';
                        details.status = 'BLOCKED';
                        details.terminalBanner = 'Workflow Blocked — Toolchain Image Unavailable';
                    }
                    details.handoff = rs.handoff || null;
                    details.lastAppliedSeq = Number(rs.lastAppliedSeq || 0);
                    details.findingContext = rs.findingContext || details.findingContext;
                    if (!details.validation && rs.postFixValidation) details.validation = rs.postFixValidation;
                    if (!details.baselineValidation && rs.baselineValidation) details.baselineValidation = rs.baselineValidation;
                    if (!details.reScanVerification && rs.reScanVerification) details.reScanVerification = rs.reScanVerification;
                    if (!details.classification && rs.classification) details.classification = rs.classification;
                    if (!details.securityReview && rs.securityReview) details.securityReview = rs.securityReview;

                    // Hydrate canonical 9 stages from persisted trusted run-state if available
                    if (Array.isArray(rs.stages) && rs.stages.length === details.stages.length) {
                        for (let si = 0; si < details.stages.length; si++) {
                            if (rs.stages[si] && rs.stages[si].status && rs.stages[si].status !== 'pending') {
                                details.stages[si] = {
                                    ...details.stages[si],
                                    status: rs.stages[si].status,
                                    summary: rs.stages[si].summary || details.stages[si].summary,
                                    durationSec: rs.stages[si].durationSec ?? details.stages[si].durationSec ?? null,
                                    failureCategory: rs.stages[si].failureCategory || null,
                                    evidenceRef: rs.stages[si].evidenceRef || null,
                                    attemptId: rs.stages[si].attemptId || null
                                };
                            }
                        }
                    }
                } catch (e) { }
            }

            const baseValPath = path.join(dir, 'baseline-validation.json');
            if (fs.existsSync(baseValPath) && !details.baselineValidation) {
                try { details.baselineValidation = JSON.parse(fs.readFileSync(baseValPath, 'utf-8')); } catch (e) { }
            }

            const rescanPath = path.join(dir, 're-scan-verification.json');
            if (fs.existsSync(rescanPath) && !details.reScanVerification) {
                try { details.reScanVerification = JSON.parse(fs.readFileSync(rescanPath, 'utf-8')); } catch (e) { }
            }

            const ctxPath = path.join(dir, 'finding-context.json');
            if (fs.existsSync(ctxPath) && !details.findingContext) {
                try { details.findingContext = JSON.parse(fs.readFileSync(ctxPath, 'utf-8')); } catch (e) { }
            }

            const manifestPath = path.join(dir, 'integrity-manifest.json');
            if (fs.existsSync(manifestPath) || !details.integrityVerification) {
                const verification = verifyEvidencePackage(dir, details.evidenceRecord?.runId || null);
                if (!details.integrityVerification || verification.hasManifest) {
                    details.integrityVerification = verification;
                }
            }
        }
    }

    if (!details.integrityVerification && details.hasEvidence) {
        details.integrityVerification = {
            hasManifest: false,
            verified: false,
            status: 'LEGACY_NO_MANIFEST',
            mismatches: [],
            chainErrors: [],
            warning: 'Historical/legacy evidence package has no SHA-256 integrity manifest.'
        };
    }

    // Check output/ directory for shared markdown report (e.g. output/VUL-POC-007_....md or output/<title>_<id>.md)
    const sharedOutputDir = path.join(workspaceRoot, 'output');
    if (fs.existsSync(sharedOutputDir)) {
        const files = fs.readdirSync(sharedOutputDir);
        const match = files.find(f => isReportMatchForVulnerability(f, vulnerabilityId));
        if (match) {
            const sharedReportPath = path.join(sharedOutputDir, match);
            try {
                const sharedContent = fs.readFileSync(sharedReportPath, 'utf-8');
                if ((!details.runState?.runId || sharedContent.includes(details.runState.runId)) &&
                    (!details.reportMarkdown || details.reportMarkdown.length < sharedContent.length)) {
                    details.reportMarkdown = sharedContent;
                }
                details.hasEvidence = true;
            } catch (e) { }
        }
    }

    // Screen untrusted Markdown & trace log before machine parsing
    const screen = new ContentInjectionScreen();
    if (details.reportMarkdown) {
        details.injectionScreening = screen.screen({
            text: details.reportMarkdown,
            contentSource: `report:${vulnerabilityId}`,
            trustClass: TRUST_CLASSES.UNTRUSTED_MARKDOWN_REPORT,
            runId: vulnerabilityId,
            filePath: `remediation-report:${vulnerabilityId}`
        });
    }

    // Fallback parser: extract patch diff, trace log, and test evidence directly from Markdown if not found on disk
    if (details.reportMarkdown) {
        extractEvidenceFromMarkdown(details);
    }

    // Infer stages status from evidence and report content
    const canonical = details.runState;
    details.proposedDiffSha256 = canonical?.vulnerabilityId === vulnerabilityId &&
        details.integrityVerification?.status !== 'TAMPERING_DETECTED' &&
        require('./baselineEligibility').isStage4ConsentEligible(canonical) ? canonical.proposedDiffSha256 : null;
    if (canonical?.schemaVersion === RUN_STATE_SCHEMA_VERSION && canonical.stages?.length === 9) {
        // Explicit current-run nulls must not be filled from an older report.
        for (const [stateKey, detailKey] of [['patchDiff', 'patchDiff'], ['postFixValidation', 'validation'],
            ['baselineValidation', 'baselineValidation'], ['reScanVerification', 'reScanVerification'], ['securityReview', 'securityReview']]) {
            if (Object.prototype.hasOwnProperty.call(canonical, stateKey)) details[detailKey] = canonical[stateKey] || null;
        }
        details.stages = canonical.stages.map((stage, index) => ({ ...details.stages[index], ...stage }));
        if (canonical.status === 'HANDED_OFF_TO_COPILOT' || canonical.status === 'AWAITING_VERIFIED_RESULT') {
            details.validation = canonical.postFixValidation || null;
            details.failureCategory = canonical.failureCategory || null;
            details.failureReason = canonical.failureReason || null;
            details.diagnostics = canonical.diagnostics || {
                failureCategory: 'VERIFIED_EXECUTION_PENDING',
                rootError: 'Copilot handoff is recorded; no verified build, test, or re-scan result has been received for this run.'
            };
        }
    } else {
        inferStageStatuses(details);
    }

    // Fail-closed: tampered evidence packages cannot present trusted PASS indicators
    if (details.integrityVerification && details.integrityVerification.status === 'TAMPERING_DETECTED') {
        if (details.validation) {
            details.validation = {
                ...details.validation,
                isValidationPassed: false,
                status: 'TAMPERING_DETECTED',
                buildResult: 'TAMPERING_DETECTED',
                integrityWarning: details.integrityVerification.warning
            };
        }
        if (details.securityReview) {
            details.securityReview = {
                ...details.securityReview,
                rating: 'TAMPERING_DETECTED',
                status: 'TAMPERING_DETECTED',
                summary: details.integrityVerification.warning
            };
        }
    }

    // Extract detailed timing metrics from trace logs
    details.timings = extractTimingsFromTrace(details.traceLog);

    // Deterministic evidence verification checklist (eliminates arbitrary confidence score)
    if (details.hasEvidence || details.reportMarkdown || details.runState) {
        details.evidenceChecklist = buildEvidenceChecklist({
            finding: details.finding || { Vulnerability_ID: vulnerabilityId },
            classification: details.classification,
            rca: details.classification || null,
            sourceToSinkEvidence: details.sourceToSinkEvidence,
            baselineValidation: details.baselineValidation,
            patchDiff: details.patchDiff,
            proposedDiffSha256: details.runState?.proposedDiffSha256 || details.approvalRecord?.proposedDiffSha256 || null,
            approvalRecord: details.approvalRecord,
            scopeVerification: details.runState?.scopeVerification || null,
            validation: details.validation || details.diagnostics || null,
            reScanVerification: details.reScanVerification,
            requiresScannerReScan: Boolean(details.finding?.scannerId || details.reScanVerification),
            securityReview: details.securityReview,
            outcomeEvaluation: details.runState?.outcomeEvaluation || null,
            integrityVerification: details.integrityVerification,
            secretRemediation: details.runState?.secretRemediation || null
        });
    }

    return details;
}

/**
 * Extracts patch diff, trace log, test validation, and metadata from Shared Markdown report
 */
function extractEvidenceFromMarkdown(details) {
    const md = details.reportMarkdown;
    if (!md) return;

    // 1. Extract Patch Diff from Markdown
    if (!details.patchDiff) {
        // Look for ```diff or ```patch blocks
        const diffMatch = md.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/i);
        if (diffMatch && diffMatch[1].trim()) {
            details.patchDiff = diffMatch[1].trim();
        } else {
            // Look under ### Git Diff section
            const gitDiffSection = md.match(/### Git Diff[\s\S]*?```[a-z]*\s*\n([\s\S]*?)```/i);
            if (gitDiffSection && gitDiffSection[1].trim() && !gitDiffSection[1].includes('# No git diff')) {
                details.patchDiff = gitDiffSection[1].trim();
            }
        }
    }

    // 2. Extract Execution Trace Log from Markdown
    if (!details.traceLog) {
        const traceSection = md.match(/### Execution Trace\s*\n([\s\S]*?)(?:\n##|\n$)/i);
        if (traceSection && traceSection[1].trim()) {
            const lines = traceSection[1]
                .split('\n')
                .map(l => l.replace(/^\s*[-*]\s*/, '').trim())
                .filter(l => l.length > 0 && (l.startsWith('[') || l.includes('[')));
            if (lines.length > 0) {
                details.traceLog = lines.join('\n');
            }
        }

        if (!details.traceLog) {
            // Check for general timestamped logs in markdown
            const timestampLines = md.split('\n')
                .map(l => l.replace(/^\s*[-*]\s*/, '').trim())
                .filter(l => /^\[\d{4}-\d{2}-\d{2}[^\]]*\]/.test(l));
            if (timestampLines.length > 0) {
                details.traceLog = timestampLines.join('\n');
            }
        }

        // Check for ## Agent Execution Summary (table or list)
        if (!details.traceLog) {
            const summaryMatch = md.match(/## Agent Execution Summary\s*\n([\s\S]*?)(?:\n##|\n$)/i);
            if (summaryMatch && summaryMatch[1].trim()) {
                const lines = summaryMatch[1]
                    .split('\n')
                    .map(l => l.trim())
                    .filter(l => l.length > 0 && !l.startsWith('| :---') && !l.startsWith('| Stage'));

                const formatted = lines.map((l, i) => {
                    if (l.startsWith('|')) {
                        const parts = l.split('|').map(p => p.trim()).filter(Boolean);
                        return `[AGENT_SUMMARY] [${parts[0] || 'STAGE'}] ${parts[1] || ''}: ${parts[2] || ''} (${parts[3] || 'Done'})`;
                    }
                    return `[AGENT_SUMMARY] ${l.replace(/^[-*]\s*/, '')}`;
                });

                if (formatted.length > 0) {
                    details.traceLog = formatted.join('\n');
                }
            }
        }
    }

    // 3. Extract Test Evidence / Validation from Markdown (strictly non-authoritative, never fabricate missing counts)
    const markdownBlocked = details.injectionScreening && details.injectionScreening.outcome !== SCREEN_OUTCOME.ALLOW_UNTRUSTED_DATA;
    if (!details.validation) {
        const hasPassedPostFix = !markdownBlocked && (
            /Post-Fix Result\*\*: \*\*PASS\*\*/i.test(md) ||
            /Baseline Result\*\*: \*\*PASS/i.test(md) ||
            /Security Review Rating\s*:\s*\*\*PASS\*\*/i.test(md)
        );
        const exitCodeMatch = md.match(/Exit Code\*\*:\s*(\d+)/i);
        const exitCode = exitCodeMatch ? parseInt(exitCodeMatch[1], 10) : null;

        const countsMatch = md.match(/Total:\s*(\d+),\s*Passed:\s*(\d+),\s*Failed:\s*(\d+)/i);
        const totalTests = countsMatch ? parseInt(countsMatch[1], 10) : 0;
        const passedTests = countsMatch ? parseInt(countsMatch[2], 10) : 0;
        const failedTests = countsMatch ? parseInt(countsMatch[3], 10) : 0;

        // Extract console output block
        let consoleOutput = '';
        const consoleMatch = md.match(/### Baseline Test Execution[\s\S]*?```(?:text)?\s*\n([\s\S]*?)```/i) ||
            md.match(/### Post-Fix Verification Tests[\s\S]*?```(?:text)?\s*\n([\s\S]*?)```/i);
        if (consoleMatch) {
            consoleOutput = consoleMatch[1].trim();
        }

        if (markdownBlocked) {
            details.validation = {
                isValidationPassed: false,
                buildResult: 'BLOCKED',
                status: 'BLOCKED',
                buildSuccessful: false,
                exitCode: exitCode ?? -1,
                testsPassed: 0,
                testsFailed: 0,
                totalTests: 0,
                consoleOutput: 'BLOCKED — Untrusted Markdown report contained suspicious injection/forged markers.'
            };
        } else if (hasPassedPostFix || exitCodeMatch || countsMatch || consoleOutput) {
            const genuinePass = hasPassedPostFix && totalTests > 0 && failedTests === 0 && (exitCode === null || exitCode === 0);
            details.validation = {
                isValidationPassed: genuinePass,
                buildResult: genuinePass ? 'PASS' : (totalTests === 0 ? 'UNTESTED' : 'FAIL'),
                status: genuinePass ? 'PASS' : (totalTests === 0 ? 'NOT EXECUTED' : 'FAIL'),
                buildSuccessful: genuinePass,
                exitCode: exitCode,
                testsPassed: passedTests,
                testsFailed: failedTests,
                totalTests: totalTests,
                consoleOutput: consoleOutput || (totalTests > 0 ? `Validation completed. Test suite passed ${passedTests}/${totalTests} tests.` : 'No real test execution counts found in report.')
            };
        }
    }

    // 4. Extract Security Review from Markdown
    if (!details.securityReview) {
        if (markdownBlocked) {
            details.securityReview = {
                rating: 'BLOCKED',
                status: 'BLOCKED',
                summary: `Markdown report failed untrusted content screening (${details.injectionScreening.ruleId}).`
            };
        } else {
            const ratingMatch = md.match(/Security Audit Rating\*\*:\s*\*\*([^\*]+)\*\*/i) || md.match(/Security Review Rating\s*:\s*\*\*([^\*]+)\*\*/i);
            const reviewStatusMatch = md.match(/Final Review Status\*\*:\s*\*\*([^\*]+)\*\*/i);
            if (ratingMatch || reviewStatusMatch) {
                const rawRating = ratingMatch ? ratingMatch[1].trim() : 'NOT_VERIFIED';
                const hasRealTests = details.validation && details.validation.totalTests > 0 && details.validation.isValidationPassed;
                const safeRating = (rawRating.toUpperCase() === 'PASS' && !hasRealTests) ? 'NOT_VERIFIED' : rawRating;
                details.securityReview = {
                    rating: safeRating,
                    status: reviewStatusMatch ? reviewStatusMatch[1].trim() : safeRating,
                    summary: 'Extracted from Markdown report.'
                };
            }
        }
    }

    // 5. Extract Finding Information from Markdown header if missing
    if (!details.finding) {
        const cveMatch = md.match(/CVE ID\*\*?:\s*`?([^\n`]+)`?/i);
        const appMatch = md.match(/Application Name\*\*?:\s*`?([^\n`]+)`?/i);
        const sevMatch = md.match(/Severity\*\*?:\s*`?([^\n`]+)`?/i);
        const locMatch = md.match(/Location(?: Path)?\*\*?:\s*`?([^\n`]+)`?/i);
        const routeMatch = md.match(/Source Classification\*\*?:\s*`?([^\n`]+)`?/i);
        const techMatch = md.match(/Technology\*\*?:\s*`?([^\n`]+)`?/i);

        if (cveMatch || appMatch || sevMatch || locMatch) {
            details.finding = {
                vulnerabilityId: details.vulnerabilityId,
                cveId: cveMatch ? cveMatch[1].trim() : '',
                applicationName: appMatch ? appMatch[1].trim() : '',
                severity: sevMatch ? sevMatch[1].trim() : '',
                locationPath: locMatch ? locMatch[1].trim() : '',
                derivedRemediationRoute: routeMatch ? routeMatch[1].trim() : 'SpecializedAction',
                technology: techMatch ? techMatch[1].trim() : 'unknown'
            };
        }
    }
}

/**
 * Infers completion/failure states for the canonical 9-stage model
 * (and remains compatible with legacy 7-slot caller mocks in tests).
 *
 * Canonical 9 Stages:
 * 1: intake (idx 0)
 * 2: classification (idx 1)
 * 3: analysis (idx 2)
 * 4: human-gate (idx 3)
 * 5: remediation (idx 4)
 * 6: bench-test (idx 5)
 * 7: security-review (idx 6)
 * 8: final-human-gate (idx 7)
 * 9: manual-validations / closure (idx 8)
 */
function inferStageStatuses(details) {
    const { reportMarkdown, validation, securityReview, patchDiff, traceLog, stages } = details;
    if (!Array.isArray(stages) || stages.length === 0) return;

    const isLegacy7 = stages.length === 7;
    const idx = isLegacy7
        ? { intake: 0, classify: 0, analysis: 1, humanGate: 3, remediation: 2, benchTest: 4, secReview: 4, finalGate: 5, closure: 6 }
        : { intake: 0, classify: 1, analysis: 2, humanGate: 3, remediation: 4, benchTest: 5, secReview: 6, finalGate: 7, closure: 8 };

    if (!details.hasEvidence && !reportMarkdown && !details.runState) {
        return;
    }

    const report = reportMarkdown || '';
    const trace = traceLog || '';

    // Copilot Handoff without engine execution: keep Stages 2-9 honest pending unless already advanced
    const isCopilotHandoffPending = details.runState &&
        (details.runState.workflowLifecycle === WORKFLOW_LIFECYCLE.HANDED_OFF_TO_COPILOT ||
         details.runState.findingState === FINDING_STATE.AWAITING_VERIFIED_RESULT);
    if (isCopilotHandoffPending && !report && !validation && !trace) {
        if (stages[idx.intake]) {
            stages[idx.intake].status = 'completed';
            stages[idx.intake].summary = 'Finding handed off to Copilot Chat; awaiting verified execution.';
        }
        details.terminalBanner = deriveTerminalBanner(details);
        return;
    }

    // Stage 1: Intake
    if (!isLegacy7 && (details.finding || details.findingContext || details.runState || report)) {
        stages[idx.intake].status = 'completed';
        stages[idx.intake].summary = `Target mapped: ${details.finding?.applicationName || details.vulnerabilityId}`;
    }

    // Stage 2: Classification
    if (details.finding || details.classification || report.includes('Vulnerability Information') || trace.includes('[DISCOVERY]') || trace.includes('[CLASSIFY]')) {
        stages[idx.classify].status = 'completed';
        const sev = details.finding?.severity || 'Assessed';
        const cwe = details.classification?.cwe || details.finding?.detailedName || 'Vulnerability';
        stages[idx.classify].summary = `Classified as ${sev} (${cwe}). Remediation route prioritized.`;
    }

    // Stage 3: Analysis / RCA & Baseline
    const runStateStages = Array.isArray(details.runState?.stages) ? details.runState.stages : null;
    const isStage3BlockedOrFailed = details.runState?.failedStage === 3 ||
        runStateStages?.[2]?.status === 'blocked' ||
        runStateStages?.[2]?.status === 'failed' ||
        details.runState?.baselineValidation?.status === 'BLOCKED' ||
        details.runState?.baselineValidation?.status === 'COULD NOT RUN' ||
        details.runState?.baselineValidation?.machineStatus === 'BLOCKED' ||
        details.runState?.baselineValidation?.machineStatus === 'COULD_NOT_RUN';

    if (isStage3BlockedOrFailed) {
        stages[idx.analysis].status = runStateStages?.[2]?.status === 'failed' ? 'failed' : 'blocked';
        stages[idx.analysis].summary = runStateStages?.[2]?.summary || details.runState?.failureReason || 'Baseline testing could not run (toolchain unavailable).';
    } else if (details.classification || report.includes('Code Analysis / RCA Agent') || report.includes('Root Cause') || trace.includes('code-analysis-rca') || trace.includes('[RCA]') || trace.includes('[ANALYZE]')) {
        stages[idx.analysis].status = 'completed';
        stages[idx.analysis].summary = details.classification?.strategy || 'RCA identified vulnerable data flow and call stack context.';
    }

    // Stage 4: Human Approval Gate (Pre-test fix authorization)
    const isHumanApproved = (report.includes('APPROVED') || report.includes('Human Review: Approved') || report.includes('STATUS: APPROVED') ||
        trace.includes('Human Approval granted') || trace.includes('[GOVERNANCE_GATE] Human Approval') ||
        details.runState?.isApproved === true || details.runState?.approvalDecision === APPROVAL_DECISION.APPROVED_STAGE4) && !isStage3BlockedOrFailed;
    const isAwaitingFirstApproval = (report.includes('AWAITING_HUMAN_APPROVAL') || report.includes('Awaiting Human Review') ||
        trace.includes('AWAITING_HUMAN_REVIEW') || details.runState?.status === 'AWAITING_HUMAN_APPROVAL') && !isStage3BlockedOrFailed;

    let fixApplied = Boolean(patchDiff || trace.includes('[REMEDIATE]') || details.runState?.patchAppliedAtStage5 || report.includes('Isolated worktree updated')) && !isStage3BlockedOrFailed;
    if (isLegacy7) {
        fixApplied = Boolean(patchDiff || report.includes('## Remediation Agent') || report.includes('Remediation Strategy') || trace.includes('remediation') || trace.includes('[REMEDIATE]')) && !isStage3BlockedOrFailed;
    }

    if (isStage3BlockedOrFailed) {
        stages[idx.humanGate].status = 'blocked_by_prerequisite';
        stages[idx.humanGate].summary = 'BLOCKED — Stage 3 source analysis and baseline testing prerequisites not satisfied.';
    } else if (isHumanApproved || (fixApplied && (validation || report.includes('## Unit Test Agent') || report.includes('## Final Validation Agent')))) {
        stages[idx.humanGate].status = 'completed';
        stages[idx.humanGate].summary = 'Secure fix authorized by developer / security lead.';
    } else if (isAwaitingFirstApproval || (stages[idx.classify].status === 'completed' && stages[idx.analysis].status === 'completed' && !isStage3BlockedOrFailed)) {
        stages[idx.humanGate].status = 'awaiting_review';
        stages[idx.humanGate].summary = 'Awaiting human review and authorization of proposed fix.';
    } else {
        stages[idx.humanGate].status = 'pending';
        stages[idx.humanGate].summary = 'Pending prerequisite completion.';
    }

    // Stage 5: Code Remediation (Patch application)
    if (isStage3BlockedOrFailed) {
        stages[idx.remediation].status = 'not_started';
        stages[idx.remediation].summary = 'Not started (prerequisites blocked).';
    } else if (fixApplied && (!isAwaitingFirstApproval || isHumanApproved)) {
        stages[idx.remediation].status = 'completed';
        stages[idx.remediation].summary = 'Minimal secure code patch applied within approved file scope.';
    }

    // Stage 6: Bench Test & Re-Scan
    let benchPassed = false;
    if (isStage3BlockedOrFailed) {
        stages[idx.benchTest].status = 'not_started';
        stages[idx.benchTest].summary = 'Not started (prerequisites blocked).';
        benchPassed = false;
    } else if (validation || report.includes('## Unit Test Agent') || report.includes('Post-Fix Verification Tests') || report.includes('## Post-Fix Test Validation') || trace.includes('unit-test') || trace.includes('[TEST]') || trace.includes('[BENCH_TEST]')) {
        const valStatus = String(validation?.status || '').toUpperCase();
        const machine = String(validation?.machineStatus || '').toUpperCase();
        const cat = String(validation?.failureCategory || '').toUpperCase();
        const countsKnown = validation?.countsKnown !== false;
        const testsPassed = validation?.testsPassed ?? (validation?.testExecution?.passedCount ?? 0);
        const testsFailed = validation?.testsFailed ?? (validation?.testExecution?.failedCount ?? 0);
        const testsTotal = validation?.testsTotal ?? (testsPassed + testsFailed);

        const isHardFailure = machine === 'FAILED' || machine === 'TIMED_OUT' || machine === 'CANCELLED' || machine === 'BLOCKED'
            || cat === 'TESTS_FAILED' || cat === 'BUILD_FAILED' || cat === 'RESTORE_FAILED'
            || cat === 'NO_TESTS_DISCOVERED' || cat === 'PARSE_FAILED' || cat === 'EXECUTION_BLOCKED'
            || cat === 'TIMED_OUT' || cat === 'CANCELLED';
        const isNotExecuted = validation?.executed === false || valStatus === 'NOT EXECUTED'
            || valStatus === 'SANDBOX UNAVAILABLE' || valStatus === 'COULD NOT RUN'
            || machine === 'UNTESTED' || machine === 'COULD_NOT_RUN';

        if (isHardFailure) {
            benchPassed = false;
            stages[idx.benchTest].status = 'failed';
            const rootMsg = validation?.rootError || validation?.summary || `Stage failed (${cat || valStatus || 'FAILED'})`;
            stages[idx.benchTest].summary = (cat === 'TESTS_FAILED' && countsKnown && testsTotal > 0)
                ? `Post-fix tests failed (${testsPassed} passed, ${testsFailed} failed). ${validation?.rootError ? validation.rootError : ''}`.trim()
                : rootMsg;
        } else if (isNotExecuted) {
            stages[idx.benchTest].status = 'pending';
            stages[idx.benchTest].summary = validation?.rootError || validation?.summary || 'NOT EXECUTED — Required sandbox or test runtime unavailable.';
            benchPassed = false;
        } else {
            const exitZero = validation?.exitCode === 0 || validation?.buildResult === 'PASS' || valStatus === 'PASS';
            benchPassed = exitZero && testsFailed === 0 && testsTotal > 0;

            stages[idx.benchTest].status = benchPassed ? 'completed' : 'failed';
            stages[idx.benchTest].summary = benchPassed
                ? `Targeted unit tests passed (${testsPassed} passed, ${testsFailed} failed).`
                : (validation?.rootError || validation?.summary || (countsKnown ? `Targeted unit tests failed (${testsPassed} passed, ${testsFailed} failed).` : 'Post-fix verification did not pass.'));
        }
    }

    // Propagate explicit failed/interrupted runState stage cleanly
    if (details.runState && (details.runState.status === 'FAILED' || details.runState.status === 'INTERRUPTED' || details.runState.findingState === FINDING_STATE.VALIDATION_FAILED)) {
        const engineFailStage = Number(details.runState.failedStage || 0);
        const reasonText = details.runState.failureReason || details.runState.failureCategory || details.runState.status;
        if (engineFailStage >= 1 && engineFailStage <= 9) {
            const targetIdx = isLegacy7
                ? Math.min(idx.closure, Math.max(0, engineFailStage - 1))
                : engineFailStage - 1;
            if (stages[targetIdx]) {
                stages[targetIdx].status = isStage3BlockedOrFailed && targetIdx === idx.analysis ? 'blocked' : 'failed';
                if (!stages[targetIdx].summary || stages[targetIdx].summary.includes('Execute')) {
                    stages[targetIdx].summary = reasonText;
                }
            }
        }
    }

    // Stage 7: Security Review & Evidence (9-stage model)
    if (!isLegacy7 && stages[idx.secReview]) {
        if (isStage3BlockedOrFailed) {
            stages[idx.secReview].status = 'not_started';
            stages[idx.secReview].summary = 'Not started (prerequisites blocked).';
        } else if (securityReview) {
            const revRating = String(securityReview.rating || securityReview.status || '').toUpperCase();
            stages[idx.secReview].status = revRating === 'PASS' ? 'completed' : (revRating === 'FAIL' || revRating === 'BLOCKED' ? 'failed' : 'completed');
            stages[idx.secReview].summary = securityReview.summary || `Security review outcome: ${revRating || 'Evaluated'}`;
        } else if (stages[idx.benchTest].status === 'failed' || stages[idx.benchTest].status === 'completed') {
            stages[idx.secReview].status = 'completed';
            stages[idx.secReview].summary = benchPassed ? 'Security evidence review completed.' : 'Security review documented validation failure.';
        }
    }

    // Stage 8: Final Human Approval Gate
    const hasFinalDoc = report.includes('## Documentation Agent') || report.includes('Final Status') || trace.includes('[DOCUMENTATION]') || trace.includes('[FINAL_GATE]');
    const isFinalPass = (securityReview?.rating === 'PASS' || validation?.isValidationPassed === true) && benchPassed;
    const hasIntegrityTampering = details.integrityVerification?.status === 'TAMPERING_DETECTED';
    const hasBlockedInjection = details.injectionScreening?.outcome === SCREEN_OUTCOME.BLOCK ||
        details.injectionScreening?.outcome === SCREEN_OUTCOME.QUARANTINE;

    if (isStage3BlockedOrFailed) {
        stages[idx.finalGate].status = 'not_started';
        stages[idx.finalGate].summary = 'Not started (prerequisites blocked).';
    } else if (hasIntegrityTampering || hasBlockedInjection) {
        if (stages[idx.benchTest]) {
            stages[idx.benchTest].status = 'failed';
            stages[idx.benchTest].summary = hasIntegrityTampering
                ? 'Evidence Integrity Mismatch Detected — validation results cannot be trusted.'
                : 'Blocked untrusted content injection detected in evidence.';
        }
        stages[idx.finalGate].status = 'failed';
        stages[idx.finalGate].summary = hasIntegrityTampering
            ? 'Evidence Integrity Mismatch Detected — manual audit required before exit.'
            : 'Blocked untrusted content injection detected in evidence report.';
        details.securityValidationOutcome = VALIDATION_OUTCOME.FAILED;
        details.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
        details.formalClosure = FORMAL_CLOSURE.VALIDATION_FAILED;
        details.findingState = FINDING_STATE.VALIDATION_FAILED;
    } else if (stages[idx.benchTest].status === 'failed' || details.runState?.approvalDecision === APPROVAL_DECISION.BLOCKED_STAGE8) {
        // B5: Failed validation BLOCKS final human sign-off (never awaiting approval/resolved)
        stages[idx.finalGate].status = 'blocked';
        stages[idx.finalGate].summary = 'BLOCKED — Post-fix validation failed. Final sign-off is prohibited until validation passes.';
        details.securityValidationOutcome = VALIDATION_OUTCOME.FAILED;
        details.approvalDecision = APPROVAL_DECISION.BLOCKED_STAGE8;
        details.formalClosure = FORMAL_CLOSURE.VALIDATION_FAILED;
        details.findingState = FINDING_STATE.VALIDATION_FAILED;
        details.workflowLifecycle = WORKFLOW_LIFECYCLE.COMPLETED;
    } else if (hasFinalDoc && isFinalPass && details.runState?.status !== 'AWAITING_FINAL_APPROVAL') {
        stages[idx.finalGate].status = 'completed';
        stages[idx.finalGate].summary = 'Final governance approval granted. Ready for workflow exit.';
        details.securityValidationOutcome = VALIDATION_OUTCOME.PASSED;
        details.approvalDecision = APPROVAL_DECISION.APPROVED_STAGE8;
        details.formalClosure = FORMAL_CLOSURE.RESOLVED_CLOSED;
        details.findingState = FINDING_STATE.RESOLVED;
        details.workflowLifecycle = WORKFLOW_LIFECYCLE.COMPLETED;
    } else if (stages[idx.benchTest].status === 'completed' && benchPassed) {
        stages[idx.finalGate].status = 'awaiting_review';
        stages[idx.finalGate].summary = 'Ready for final human sign-off before application team hand-off.';
        details.securityValidationOutcome = VALIDATION_OUTCOME.PASSED;
        details.approvalDecision = APPROVAL_DECISION.PENDING_STAGE8;
        details.formalClosure = FORMAL_CLOSURE.AWAITING_FINAL_SIGN_OFF;
        details.findingState = FINDING_STATE.AWAITING_FINAL_SIGN_OFF;
    }

    // Stage 9: Workflow Closure
    if (isStage3BlockedOrFailed) {
        stages[idx.closure].status = 'not_started';
        stages[idx.closure].summary = 'Not started (prerequisites blocked).';
    } else if (stages[idx.finalGate].status === 'completed') {
        stages[idx.closure].status = 'completed';
        stages[idx.closure].summary = 'Workflow concluded with verified remediation and formal sign-off.';
    } else if (stages[idx.finalGate].status === 'blocked' || stages[idx.benchTest].status === 'failed') {
        stages[idx.closure].status = 'failed';
        stages[idx.closure].summary = 'Workflow Ended — Validation Failed (remediation incomplete; rework or retry required).';
        details.workflowLifecycle = WORKFLOW_LIFECYCLE.COMPLETED;
    } else if (stages[idx.benchTest].status === 'completed') {
        stages[idx.closure].status = 'pending';
        stages[idx.closure].summary = 'Pending final human sign-off before workflow closure.';
    }

    details.terminalBanner = deriveTerminalBanner(details);
}

/**
 * Extracts structured stage timestamps and calculates stage durations from execution trace
 */
function extractTimingsFromTrace(traceLog) {
    if (!traceLog) return null;
    const lines = traceLog.split('\n');
    const events = [];

    for (const line of lines) {
        const match = line.match(/\[(\d{4}-\d{2}-\d{2}[^\]]+)\]\s*(?:\[([A-Z_]+)\])?/);
        if (match) {
            const dateStr = match[1].trim();
            let dt = new Date(dateStr);
            if (isNaN(dt.getTime())) {
                dt = new Date(dateStr.replace(' UTC', 'Z').replace(' ', 'T'));
            }
            if (!isNaN(dt.getTime())) {
                events.push({
                    timestamp: dt,
                    tag: (match[2] || '').trim(),
                    line: line
                });
            }
        }
    }

    if (events.length === 0) return null;

    const startTime = events[0].timestamp;
    const endTime = events[events.length - 1].timestamp;
    const totalDurationSec = Math.max(0, (endTime.getTime() - startTime.getTime()) / 1000);

    const findEvent = (tag) => events.find(e => e.tag === tag);
    const discoveryEvt = findEvent('DISCOVERY') || events[0];
    const classifyEvt = findEvent('CLASSIFY') || discoveryEvt;
    const rcaEvt = findEvent('RCA');
    const remediateEvt = findEvent('REMEDIATE');
    const govGateEvt = findEvent('GOVERNANCE_GATE');
    const benchTestEvt = findEvent('BENCH_TEST');
    const finalGateEvt = findEvent('FINAL_GATE');
    const handoffEvt = findEvent('HANDOFF') || events[events.length - 1];

    const analysisDurationSec = (rcaEvt && classifyEvt && rcaEvt.timestamp >= classifyEvt.timestamp)
        ? Math.max(0, (rcaEvt.timestamp.getTime() - classifyEvt.timestamp.getTime()) / 1000)
        : null;
    const remediationDurationSec = (remediateEvt && rcaEvt && remediateEvt.timestamp >= rcaEvt.timestamp)
        ? Math.max(0, (remediateEvt.timestamp.getTime() - rcaEvt.timestamp.getTime()) / 1000)
        : null;
    const approvalWaitDurationSec = (govGateEvt && remediateEvt && govGateEvt.timestamp >= remediateEvt.timestamp)
        ? Math.max(0, (govGateEvt.timestamp.getTime() - remediateEvt.timestamp.getTime()) / 1000)
        : null;
    const testDurationSec = (benchTestEvt && govGateEvt && benchTestEvt.timestamp >= govGateEvt.timestamp)
        ? Math.max(0, (benchTestEvt.timestamp.getTime() - govGateEvt.timestamp.getTime()) / 1000)
        : null;
    const validationDurationSec = (finalGateEvt && benchTestEvt && finalGateEvt.timestamp >= benchTestEvt.timestamp)
        ? Math.max(0, (finalGateEvt.timestamp.getTime() - benchTestEvt.timestamp.getTime()) / 1000)
        : null;

    return {
        runStartTime: startTime.toISOString(),
        runEndTime: endTime.toISOString(),
        totalDurationSec: totalDurationSec > 0 ? totalDurationSec : null,
        analysisDurationSec,
        remediationDurationSec,
        approvalWaitDurationSec,
        testDurationSec,
        validationDurationSec
    };
}

/**
 * Lists all generated reports in output/ and remediation-output/
 */
function loadAllReports(workspaceRoot) {
    const reports = [];
    const seenIds = new Set();
    const sharedOutputDir = path.join(workspaceRoot, 'output');
    const remOutputDir = path.join(workspaceRoot, 'remediation-output');

    // 1. Scan output/ directory for shared markdown reports
    if (fs.existsSync(sharedOutputDir)) {
        const files = fs.readdirSync(sharedOutputDir);
        for (const file of files) {
            if (file.endsWith('.md') && !file.startsWith('.')) {
                const fullPath = path.join(sharedOutputDir, file);
                try {
                    const content = fs.readFileSync(fullPath, 'utf-8');
                    const stats = fs.statSync(fullPath);
                    const titleMatch = content.match(/^#\s+(.*)$/m);
                    const idMatch = file.match(/([a-zA-Z0-9]+-[a-zA-Z0-9]+-[0-9]+)/i) || file.match(/(vul_poc_\d+|gcas_e2e_\d+)/i);
                    const vulnId = idMatch ? idMatch[1].toUpperCase().replace(/_/g, '-') : file.replace('.md', '');
                    seenIds.add(vulnId);

                    reports.push({
                        fileName: file,
                        filePath: fullPath,
                        title: titleMatch ? titleMatch[1] : file,
                        vulnerabilityId: vulnId,
                        sizeBytes: stats.size,
                        modifiedAt: stats.mtime.toISOString(),
                        preview: content.substring(0, 300)
                    });
                } catch (e) { }
            }
        }
    }

    // 2. Also scan remediation-output/<id>/remediation-report.md
    if (fs.existsSync(remOutputDir)) {
        try {
            const subdirs = fs.readdirSync(remOutputDir, { withFileTypes: true });
            for (const sub of subdirs) {
                if (sub.isDirectory() && !sub.name.startsWith('.')) {
                    const vulnId = sub.name.toUpperCase();
                    const reportPath = path.join(remOutputDir, sub.name, 'remediation-report.md');
                    if (fs.existsSync(reportPath)) {
                        try {
                            const content = fs.readFileSync(reportPath, 'utf-8');
                            const stats = fs.statSync(reportPath);
                            const titleMatch = content.match(/^#\s+(.*)$/m);

                            if (!seenIds.has(vulnId)) {
                                seenIds.add(vulnId);
                                reports.push({
                                    fileName: `${sub.name}_remediation_report.md`,
                                    filePath: reportPath,
                                    title: titleMatch ? titleMatch[1] : `${vulnId} Remediation Report`,
                                    vulnerabilityId: vulnId,
                                    sizeBytes: stats.size,
                                    modifiedAt: stats.mtime.toISOString(),
                                    preview: content.substring(0, 300)
                                });
                            }
                        } catch (e) { }
                    }
                }
            }
        } catch (e) { }
    }

    return reports;
}

module.exports = {
    loadVulnerabilityDetails,
    inferStageStatuses,
    extractTimingsFromTrace,
    loadAllReports,
    isReportMatchForVulnerability
};
