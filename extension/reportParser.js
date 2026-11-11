const fs = require('fs');
const path = require('path');
const {
    ContentInjectionScreen,
    TRUST_CLASSES,
    SCREEN_OUTCOME
} = require('./contentInjectionScreen');
const { verifyEvidencePackage } = require('./evidenceLedger');

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
        stages: [
            {
                id: 'classification',
                name: 'Classification Agent',
                number: 1,
                type: 'agent',
                status: 'pending',
                summary: 'Read vulnerabilities, classify by severity, CWE, type, assess complexity & prioritize.',
                bullets: [
                    'Read vulnerabilities from repository',
                    'Classify by severity, CWE, type',
                    'Assess complexity & exploitability',
                    'Prioritize remediation strategy'
                ]
            },
            {
                id: 'code-analysis',
                name: 'Code Analysis Agent',
                number: 2,
                type: 'agent',
                status: 'pending',
                summary: 'Locate vulnerable code, analyze data flow, call flow & identify root cause.',
                bullets: [
                    'Locate vulnerable code (file, line)',
                    'Analyze data flow & call flow',
                    'Understand context & dependencies',
                    'Identify root cause'
                ]
            },
            {
                id: 'remediation',
                name: 'Remediation Agent',
                number: 3,
                type: 'agent',
                status: 'pending',
                summary: 'Determine secure fix strategy, generate code patch & change summary.',
                bullets: [
                    'Determine secure fix strategy',
                    'Generate .NET code changes (patch)',
                    'Follow best practices & secure coding',
                    'Prepare change summary',
                    'Only uses existing remediation & knowledge if not stale'
                ]
            },
            {
                id: 'human-gate',
                name: 'Human Approval Gate',
                number: 4,
                type: 'gate',
                status: 'pending',
                summary: 'Review vulnerability analysis and proposed secure fix before bench testing.',
                bullets: [
                    'Review vulnerability analysis and proposed fix',
                    'Authorize code modification or request rework'
                ]
            },
            {
                id: 'bench-test',
                name: 'Bench Test',
                number: 5,
                type: 'agent',
                status: 'pending',
                summary: 'Create/update unit tests, cover vulnerable scenarios & validate fix.',
                bullets: [
                    'Create / update unit tests',
                    'Cover vulnerable scenario',
                    'Validate fix with targeted tests',
                    'Retry on test failure loop'
                ]
            },
            {
                id: 'final-human-gate',
                name: 'Final Human Approval Gate',
                number: 6,
                type: 'gate',
                status: 'pending',
                summary: 'Final human sign-off before workflow exit and team hand-off.',
                bullets: [
                    'Final Human Approval before workflow exit',
                    'Verify test evidence & audit compliance'
                ]
            },
            {
                id: 'manual-validations',
                name: 'Final Manual Validations',
                number: 7,
                type: 'non-agentic',
                status: 'pending',
                summary: 'Non-agentic workflow for Regression Testing & CI/CD Deployment by App Owners.',
                bullets: [
                    'Regression Testing - To be performed by App Owners',
                    'Deployment - Through existing CI/CD Pipeline performed by App Owners'
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
                try { details.reportMarkdown = fs.readFileSync(reportPath, 'utf-8'); } catch (e) {}
            }

            const patchPath = path.join(dir, 'changes.patch');
            if (fs.existsSync(patchPath) && !details.patchDiff) {
                try { details.patchDiff = fs.readFileSync(patchPath, 'utf-8'); } catch (e) {}
            }

            const findingPath = path.join(dir, 'finding.json');
            if (fs.existsSync(findingPath) && !details.finding) {
                try { details.finding = JSON.parse(fs.readFileSync(findingPath, 'utf-8')); } catch (e) {}
            }

            const classPath = path.join(dir, 'classification.json');
            if (fs.existsSync(classPath) && !details.classification) {
                try { details.classification = JSON.parse(fs.readFileSync(classPath, 'utf-8')); } catch (e) {}
            }

            const valPath = path.join(dir, 'validation.json');
            if (fs.existsSync(valPath) && !details.validation) {
                try { details.validation = JSON.parse(fs.readFileSync(valPath, 'utf-8')); } catch (e) {}
            }

            const sbxPath = path.join(dir, 'sandbox-execution.json');
            if (fs.existsSync(sbxPath) && !details.sandboxExecution) {
                try { details.sandboxExecution = JSON.parse(fs.readFileSync(sbxPath, 'utf-8')); } catch (e) {}
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
                } catch (e) {}
            }

            const secPath = path.join(dir, 'security-review.json');
            if (fs.existsSync(secPath) && !details.securityReview) {
                try { details.securityReview = JSON.parse(fs.readFileSync(secPath, 'utf-8')); } catch (e) {}
            }

            const tracePath = path.join(dir, 'agent-execution-trace.log');
            if (fs.existsSync(tracePath) && !details.traceLog) {
                try { details.traceLog = fs.readFileSync(tracePath, 'utf-8'); } catch (e) {}
            }

            const evidenceRecPath = path.join(dir, 'evidence-record.json');
            if (fs.existsSync(evidenceRecPath) && !details.evidenceRecord) {
                try { details.evidenceRecord = JSON.parse(fs.readFileSync(evidenceRecPath, 'utf-8')); } catch (e) {}
            }

            const approvalRecPath = path.join(dir, 'approval-record.json');
            if (fs.existsSync(approvalRecPath) && !details.approvalRecord) {
                try { details.approvalRecord = JSON.parse(fs.readFileSync(approvalRecPath, 'utf-8')); } catch (e) {}
            }

            const decisionPath = path.join(dir, 'remediation-decision.json');
            if (fs.existsSync(decisionPath) && !details.remediationDecision) {
                try { details.remediationDecision = JSON.parse(fs.readFileSync(decisionPath, 'utf-8')); } catch (e) {}
            }

            const s2sPath = path.join(dir, 'source-to-sink.json');
            if (fs.existsSync(s2sPath) && !details.sourceToSinkEvidence) {
                try { details.sourceToSinkEvidence = JSON.parse(fs.readFileSync(s2sPath, 'utf-8')); } catch (e) {}
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
            warning: 'Historical/legacy evidence package has no Phase 2 SHA-256 integrity manifest.'
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
                if (!details.reportMarkdown || details.reportMarkdown.length < sharedContent.length) {
                    details.reportMarkdown = sharedContent;
                }
                details.hasEvidence = true;
            } catch (e) {}
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
    inferStageStatuses(details);

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

        const scoreMatch = md.match(/Confidence Score\*\*:\s*\*\*?(\d+)(?:\/100)?/i) || md.match(/Score:\s*(\d+)\/100/i);
        const score = scoreMatch ? parseInt(scoreMatch[1], 10) : 0;

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
                confidenceScore: 0,
                consoleOutput: 'BLOCKED — Untrusted Markdown report contained suspicious injection/forged markers.'
            };
        } else if (hasPassedPostFix || exitCodeMatch || countsMatch || scoreMatch || consoleOutput) {
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
                confidenceScore: genuinePass ? score : Math.min(score, 40),
                consoleOutput: consoleOutput || (totalTests > 0 ? `Validation completed. Test suite passed ${passedTests}/${totalTests} tests.` : 'No real test execution counts found in report.')
            };
        }
    }

    // 4. Extract Security Review from Markdown
    if (!details.securityReview) {
        if (markdownBlocked) {
            details.securityReview = {
                rating: 'BLOCKED',
                score: 0,
                status: 'BLOCKED',
                summary: `Markdown report failed untrusted content screening (${details.injectionScreening.ruleId}).`
            };
        } else {
            const ratingMatch = md.match(/Security Audit Rating\*\*:\s*\*\*([^\*]+)\*\*/i) || md.match(/Security Review Rating\s*:\s*\*\*([^\*]+)\*\*/i);
            const scoreMatch = md.match(/Final Confidence Score\*\*:\s*\*\*?(\d+)/i);
            if (ratingMatch || scoreMatch) {
                const rawRating = ratingMatch ? ratingMatch[1].trim() : 'NOT_VERIFIED';
                const hasRealTests = details.validation && details.validation.totalTests > 0 && details.validation.isValidationPassed;
                const safeRating = (rawRating.toUpperCase() === 'PASS' && !hasRealTests) ? 'NOT_VERIFIED' : rawRating;
                details.securityReview = {
                    rating: safeRating,
                    score: scoreMatch ? parseInt(scoreMatch[1], 10) : 0,
                    status: safeRating,
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
                technology: techMatch ? techMatch[1].trim() : 'dotnet'
            };
        }
    }
}

/**
 * Infers the completion state of the 7 pipeline stages
 * Stage 1: Classification Agent
 * Stage 2: Code Analysis Agent
 * Stage 3: Remediation Agent
 * Stage 4: Human Approval Gate (Pre-Test Fix Authorization)
 * Stage 5: Bench Test
 * Stage 6: Final Human Approval Gate (Workflow Exit Sign-off)
 * Stage 7: Final Manual Validations (Non-Agentic Application Team Hand-off)
 */
function inferStageStatuses(details) {
    const { reportMarkdown, validation, securityReview, patchDiff, traceLog, stages } = details;

    if (!details.hasEvidence && !reportMarkdown) {
        return;
    }

    const report = reportMarkdown || '';
    const trace = traceLog || '';

    // Stage 1: Classification Agent
    if (details.finding || details.classification || report.includes('Vulnerability Information') || trace.includes('[DISCOVERY]') || trace.includes('[CLASSIFY]')) {
        stages[0].status = 'completed';
        const sev = details.finding?.severity || 'Assessed';
        const cwe = details.classification?.cwe || details.finding?.detailedName || 'Vulnerability';
        stages[0].summary = `Classified as ${sev} (${cwe}). Remediation route prioritized.`;
    }

    // Stage 2: Code Analysis Agent
    if (details.classification || report.includes('Code Analysis / RCA Agent') || report.includes('Root Cause') || trace.includes('code-analysis-rca') || trace.includes('[RCA]') || trace.includes('[ANALYZE]')) {
        stages[1].status = 'completed';
        stages[1].summary = details.classification?.strategy || 'RCA identified vulnerable data flow and call stack context.';
    }

    // Stage 3: Remediation Agent
    let fixCompleted = false;
    if (patchDiff || report.includes('## Remediation Agent') || report.includes('Remediation Strategy') || trace.includes('remediation') || trace.includes('[REMEDIATE]')) {
        fixCompleted = true;
        stages[2].status = 'completed';
        stages[2].summary = 'Minimal secure code patch created and verified against AST.';
    }

    // Stage 4: Human Approval Gate (Pre-test fix authorization)
    const isHumanApproved = report.includes('APPROVED') || report.includes('Human Review: Approved') || report.includes('STATUS: APPROVED') || trace.includes('Human Approval granted') || trace.includes('[GOVERNANCE_GATE] Human Approval');
    const isAwaitingFirstApproval = report.includes('AWAITING_HUMAN_APPROVAL') || report.includes('Awaiting Human Review') || trace.includes('AWAITING_HUMAN_REVIEW');

    if (isHumanApproved || (fixCompleted && (validation || report.includes('## Unit Test Agent') || report.includes('## Final Validation Agent')))) {
        stages[3].status = 'completed';
        stages[3].summary = 'Secure fix authorized by developer / security lead.';
    } else if (isAwaitingFirstApproval || fixCompleted || (stages[0].status === 'completed' && stages[1].status === 'completed')) {
        stages[3].status = 'awaiting_review';
        stages[3].summary = 'Awaiting human review and authorization of proposed fix.';
    }

    // Stage 5: Bench Test
    let benchPassed = false;
    if (validation || report.includes('## Unit Test Agent') || report.includes('Post-Fix Verification Tests') || report.includes('## Post-Fix Test Validation') || trace.includes('unit-test') || trace.includes('[TEST]') || trace.includes('[BENCH_TEST]')) {
        if (validation?.status === 'NOT EXECUTED') {
            stages[4].status = 'pending';
            stages[4].summary = validation.summary || 'NOT EXECUTED — Required runtime unavailable.';
            benchPassed = false;
        } else {
            const testsPassed = validation?.testsPassed ?? (validation?.testExecution?.passedCount ?? 0);
            const testsFailed = validation?.testsFailed ?? (validation?.testExecution?.failedCount ?? 0);
            const exitZero = validation?.exitCode === 0 || validation?.buildResult === 'PASS' || validation?.status === 'PASS';
            benchPassed = exitZero && testsFailed === 0;

            stages[4].status = benchPassed ? 'completed' : 'failed';
            stages[4].summary = `Targeted unit tests ${benchPassed ? 'passed' : 'failed'} (${testsPassed} passed, ${testsFailed} failed).`;
        }
    }

    // Stage 6: Final Human Approval Gate
    const hasFinalDoc = report.includes('## Documentation Agent') || report.includes('Final Status') || trace.includes('[DOCUMENTATION]') || trace.includes('[FINAL_GATE]');
    const isFinalPass = securityReview?.rating === 'PASS' || (validation?.isValidationPassed === true && benchPassed);
    const hasIntegrityTampering = details.integrityVerification?.status === 'TAMPERING_DETECTED';
    const hasBlockedInjection = details.injectionScreening?.outcome === SCREEN_OUTCOME.BLOCK ||
        details.injectionScreening?.outcome === SCREEN_OUTCOME.QUARANTINE;

    if (hasIntegrityTampering || hasBlockedInjection) {
        stages[5].status = 'failed';
        stages[5].summary = hasIntegrityTampering
            ? 'Evidence Integrity Mismatch Detected — manual audit required before exit.'
            : 'Blocked untrusted content injection detected in evidence report.';
    } else if (hasFinalDoc && isFinalPass) {
        stages[5].status = 'completed';
        stages[5].summary = 'Final governance approval granted. Ready for workflow exit.';
    } else if (stages[4].status === 'completed') {
        stages[5].status = 'awaiting_review';
        stages[5].summary = 'Ready for final human sign-off before application team hand-off.';
    }

    // Stage 7: Final Manual Validations (Non-Agentic App Team Hand-off)
    if (stages[5].status === 'completed') {
        stages[6].status = 'completed';
        stages[6].summary = 'Handed off to Application Team for Regression Testing & CI/CD Deployment.';
    } else if (stages[4].status === 'completed') {
        stages[6].status = 'pending';
        stages[6].summary = 'Pending final human gate approval before App Owner validation.';
    }
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
                } catch (e) {}
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
                        } catch (e) {}
                    }
                }
            }
        } catch (e) {}
    }

    return reports;
}

module.exports = {
    loadVulnerabilityDetails,
    extractTimingsFromTrace,
    loadAllReports,
    isReportMatchForVulnerability
};
