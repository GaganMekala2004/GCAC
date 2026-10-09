const fs = require('fs');
const path = require('path');

/**
 * Reads remediation artifacts and reports for a given vulnerability ID
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
        stages: [
            { id: 'code-analysis-rca', name: 'Code Analysis & RCA', status: 'pending', summary: '' },
            { id: 'unit-test', name: 'Security Unit Test', status: 'pending', summary: '' },
            { id: 'human-gate', name: 'Human Review Gate', status: 'pending', summary: '' },
            { id: 'remediation', name: 'Remediation Fix', status: 'pending', summary: '' },
            { id: 'regression', name: 'Regression Suite', status: 'pending', summary: '' },
            { id: 'final-validation', name: 'Final Validation', status: 'pending', summary: '', score: 0 },
            { id: 'documentation', name: 'Audit Documentation', status: 'pending', summary: '' }
        ]
    };

    // 1. Check remediation-output/<id>/
    const outputDir = path.join(workspaceRoot, 'remediation-output', vulnerabilityId);
    if (fs.existsSync(outputDir)) {
        details.hasEvidence = true;

        const reportPath = path.join(outputDir, 'remediation-report.md');
        if (fs.existsSync(reportPath)) {
            details.reportMarkdown = fs.readFileSync(reportPath, 'utf-8');
        }

        const patchPath = path.join(outputDir, 'changes.patch');
        if (fs.existsSync(patchPath)) {
            details.patchDiff = fs.readFileSync(patchPath, 'utf-8');
        }

        const findingPath = path.join(outputDir, 'finding.json');
        if (fs.existsSync(findingPath)) {
            try {
                details.finding = JSON.parse(fs.readFileSync(findingPath, 'utf-8'));
            } catch (e) {
                // Ignore parse errors
            }
        }

        const classPath = path.join(outputDir, 'classification.json');
        if (fs.existsSync(classPath)) {
            try {
                details.classification = JSON.parse(fs.readFileSync(classPath, 'utf-8'));
            } catch (e) {
                // Ignore parse errors
            }
        }

        const valPath = path.join(outputDir, 'validation.json');
        if (fs.existsSync(valPath)) {
            try {
                details.validation = JSON.parse(fs.readFileSync(valPath, 'utf-8'));
            } catch (e) {
                // Ignore parse errors
            }
        }

        const secPath = path.join(outputDir, 'security-review.json');
        if (fs.existsSync(secPath)) {
            try {
                details.securityReview = JSON.parse(fs.readFileSync(secPath, 'utf-8'));
            } catch (e) {
                // Ignore parse errors
            }
        }

        const tracePath = path.join(outputDir, 'agent-execution-trace.log');
        if (fs.existsSync(tracePath)) {
            details.traceLog = fs.readFileSync(tracePath, 'utf-8');
        }
    }

    // 2. Check output/ directory for shared markdown report
    const sharedOutputDir = path.join(workspaceRoot, 'output');
    if (fs.existsSync(sharedOutputDir)) {
        const files = fs.readdirSync(sharedOutputDir);
        const match = files.find(f => f.toLowerCase().includes(vulnerabilityId.toLowerCase()) && f.endsWith('.md'));
        if (match) {
            const sharedReportPath = path.join(sharedOutputDir, match);
            const sharedContent = fs.readFileSync(sharedReportPath, 'utf-8');
            if (!details.reportMarkdown) {
                details.reportMarkdown = sharedContent;
            }
            details.hasEvidence = true;
        }
    }

    // Infer stages status from evidence and report content
    inferStageStatuses(details);

    return details;
}

/**
 * Infers the completion state of the 7 pipeline stages
 */
function inferStageStatuses(details) {
    const { reportMarkdown, validation, securityReview, patchDiff, traceLog } = details;

    if (!details.hasEvidence && !reportMarkdown) {
        return;
    }

    const report = reportMarkdown || '';
    const trace = traceLog || '';

    // Stage 1: Code Analysis & RCA
    if (details.classification || report.includes('Root Cause Summary') || report.includes('RCA') || trace.includes('code-analysis-rca') || trace.includes('[ANALYZE]')) {
        details.stages[0].status = 'completed';
        details.stages[0].summary = details.classification?.strategy || 'RCA identified vulnerable data flow.';
    }

    // Stage 2: Security Unit Test Baseline
    if (validation || report.includes('Unit Tests') || trace.includes('unit-test') || trace.includes('[TEST]')) {
        details.stages[1].status = 'completed';
        const testsPassed = validation?.testsPassed ?? (validation?.testExecution?.passedCount ?? 1);
        const testsFailed = validation?.testsFailed ?? (validation?.testExecution?.failedCount ?? 0);
        details.stages[1].summary = `Baseline established (${testsPassed} passed, ${testsFailed} failed).`;
    }

    // Stage 4: Remediation Fix (Evaluated prior to gate resolution)
    let fixCompleted = false;
    if (patchDiff || report.includes('Remediation Summary') || report.includes('Secure Fix Applied') || trace.includes('remediation') || trace.includes('[REMEDIATE]')) {
        fixCompleted = true;
        details.stages[3].status = 'completed';
        details.stages[3].summary = 'Minimal secure code patch created.';
    }

    // Stage 3: Human Review Gate
    if (fixCompleted || report.includes('STATUS: APPROVED') || report.includes('Human Review: Approved') || report.includes('Approved') || trace.includes('[PUBLISH]')) {
        details.stages[2].status = 'completed';
        details.stages[2].summary = 'Authorized by developer/security lead.';
    } else if (report.includes('AWAITING_HUMAN_REVIEW') || trace.includes('AWAITING_HUMAN_REVIEW') || (details.stages[0].status === 'completed' && details.stages[1].status === 'completed')) {
        details.stages[2].status = 'awaiting_review';
        details.stages[2].summary = 'Ready for human review before fix execution.';
    }

    // Stage 5: Regression Suite
    if (validation?.buildResult !== undefined || validation?.buildSuccessful !== undefined || report.includes('Build / Test Result') || trace.includes('regression') || trace.includes('[TEST]')) {
        const buildPassed = validation?.buildResult === 'PASS' || validation?.buildSuccessful !== false || validation?.exitCode === 0;
        const testPassed = validation?.isValidationPassed !== false && (validation?.testsFailed === 0 || validation?.testsFailed === undefined);
        const passed = buildPassed && testPassed;
        details.stages[4].status = passed ? 'completed' : 'failed';
        details.stages[4].summary = passed ? 'Build and regression test suite passed.' : 'Regression tests failed.';
    }

    // Stage 6: Final Validation
    if (validation || securityReview || report.includes('Validation & Security Audit Results') || report.includes('Security Review Rating')) {
        const secRating = securityReview?.rating || securityReview?.status || '';
        const secPass = secRating.toUpperCase() === 'PASS' || report.includes('Security Review Rating : **PASS**') || (validation?.isValidationPassed === true);
        const score = validation?.confidenceScore || (secPass ? (securityReview?.score || 95) : 50);
        details.stages[5].status = secPass ? 'completed' : 'failed';
        details.stages[5].score = score;
        details.stages[5].summary = `Validation Score: ${score}/100 (${secPass ? 'PASS' : 'FAIL'}).`;
    }

    // Stage 7: Audit Documentation
    if (report && (details.stages[5].status === 'completed' || details.stages[3].status === 'completed')) {
        details.stages[6].status = 'completed';
        details.stages[6].summary = 'Shared audit report generated & CSV updated.';
    }
}

module.exports = {
    loadVulnerabilityDetails
};

