const path = require('path');
const fs = require('fs');
const { VERIFICATION_STATUS, SCANNER_STATUS } = require('./findingModel');
const {
    OUTCOME_STATUS,
    resolveOriginatingScannerId,
    classifyTestOutcome,
    toLegacyVerificationDisplay
} = require('../outcomeContract');

/**
 * Post-Remediation Re-Scan Verification Engine
 * Performs genuine before-and-after finding comparison to determine whether
 * a vulnerability has been verified as RESOLVED, STILL PRESENT, INCONCLUSIVE,
 * NOT VERIFIED, or REGRESSION DETECTED.
 */
class ReScanVerifier {
    /**
     * @param {import('./scanController').ScanController|string} scanControllerOrWorkspaceRoot 
     * @param {import('./scanController').ScanController} [maybeScanController]
     */
    constructor(scanControllerOrWorkspaceRoot, maybeScanController) {
        if (maybeScanController) {
            this.workspaceRoot = scanControllerOrWorkspaceRoot;
            this.scanController = maybeScanController;
        } else {
            this.scanController = scanControllerOrWorkspaceRoot;
            this.workspaceRoot = scanControllerOrWorkspaceRoot ? scanControllerOrWorkspaceRoot.workspaceRoot : process.cwd();
        }
    }

    /**
     * Executes targeted re-scan and computes definitive post-remediation verification status.
     * 
     * @param {object} params
     * @param {object} params.originalFinding - The original baseline finding record
     * @param {object} [params.postFixTestResult] - The result from Stage 6 post-fix test runner
     * @param {string} [params.targetFilePath] - The source file that was remediated
     * @returns {Promise<{
     *   status: string, // RESOLVED | STILL PRESENT | INCONCLUSIVE | NOT VERIFIED | REGRESSION DETECTED
     *   reason: string,
     *   summary: string,
     *   isResolved: boolean,
     *   beforeFingerprint: string,
     *   reScanDurationMs: number,
     *   stillPresent: boolean,
     *   newFindingsCount: number,
     *   evidence: string[],
     *   evidenceMarkdown: string,
     *   scannerDetails: { id: string, name: string, version: string }
     * }>}
     */
    async verifyRemediation(params = {}) {
        const originalFinding = params.originalFinding;
        const postFixTestResult = params.postFixTestResult || params.postFixValidation || params.testResult;
        const targetFilePath = params.targetFilePath || params.targetPath;

        if (!originalFinding) {
            const reason = 'Missing original finding context.';
            const md = '### ⚠️ Re-Scan Verification\n- Status: `NOT VERIFIED` (No original finding supplied)\n';
            return {
                status: VERIFICATION_STATUS.NOT_VERIFIED,
                machineStatus: OUTCOME_STATUS.NOT_VERIFIED,
                isResolved: false,
                reason,
                summary: reason,
                beforeFingerprint: '',
                reScanDurationMs: 0,
                stillPresent: false,
                newFindingsCount: 0,
                evidence: [md],
                evidenceMarkdown: md,
                scannerDetails: { id: 'unknown', name: 'Unknown', version: '' }
            };
        }

        // Resolve originating scanner explicitly (never default silently to another scanner)
        const origin = resolveOriginatingScannerId(originalFinding);
        if (!origin.resolved || !origin.scannerId) {
            const rawDisplay = origin.rawScannerId || 'unspecified';
            const reason = `Cannot verify remediation: originating scanner '${rawDisplay}' is missing or unrecognized. Silent scanner fallback is disabled.`;
            const md = `### ⚠️ Re-Scan Verification\n- Scanner: \`${rawDisplay}\`\n- Status: \`NOT VERIFIED\` (${reason})\n`;
            return {
                status: VERIFICATION_STATUS.NOT_VERIFIED,
                machineStatus: OUTCOME_STATUS.NOT_VERIFIED,
                isResolved: false,
                reason,
                summary: reason,
                beforeFingerprint: originalFinding.findingFingerprint || originalFinding.Finding_Fingerprint || '',
                reScanDurationMs: 0,
                stillPresent: false,
                newFindingsCount: 0,
                evidence: [md],
                evidenceMarkdown: md,
                scannerDetails: { id: origin.rawScannerId || 'unknown', name: origin.rawScannerId || 'Unknown', version: '' }
            };
        }

        const scannerId = origin.scannerId;
        const scanner = this.scanController && this.scanController.scanners ? this.scanController.scanners.get(scannerId) : null;
        if (!scanner) {
            const reason = `Original scanner '${scannerId}' is not registered or unavailable.`;
            const md = `### ⚠️ Re-Scan Verification\n- Scanner: \`${scannerId}\`\n- Status: \`NOT VERIFIED\` (Scanner unavailable on local host)\n`;
            return {
                status: VERIFICATION_STATUS.NOT_VERIFIED,
                machineStatus: OUTCOME_STATUS.NOT_VERIFIED,
                isResolved: false,
                reason,
                summary: reason,
                beforeFingerprint: originalFinding.findingFingerprint || originalFinding.Finding_Fingerprint || '',
                reScanDurationMs: 0,
                stillPresent: false,
                newFindingsCount: 0,
                evidence: [md],
                evidenceMarkdown: md,
                scannerDetails: { id: scannerId, name: scannerId, version: '' }
            };
        }

        // Check scanner availability
        const avail = await scanner.isAvailable();
        if (!avail.available) {
            const reason = `Scanner '${scanner.name}' runtime is not installed: ${avail.reason}`;
            const md = `### ⚠️ Re-Scan Verification: ${scanner.name}\n- Status: \`NOT VERIFIED\`\n- Reason: Required runtime unavailable on machine (${avail.reason})\n`;
            return {
                status: VERIFICATION_STATUS.NOT_VERIFIED,
                machineStatus: OUTCOME_STATUS.NOT_VERIFIED,
                isResolved: false,
                reason,
                summary: reason,
                beforeFingerprint: originalFinding.findingFingerprint || originalFinding.Finding_Fingerprint || '',
                reScanDurationMs: 0,
                stillPresent: false,
                newFindingsCount: 0,
                evidence: [md],
                evidenceMarkdown: md,
                scannerDetails: { id: scanner.id, name: scanner.name, version: '' }
            };
        }

        // Resolve scan target: specific remediated file or repository folder (supporting isolated worktree root override)
        const effectiveRoot = params.workspaceRoot || this.workspaceRoot;
        const relLocPath = originalFinding.filePath || originalFinding.Location_Path || '';
        const scanTarget = targetFilePath && fs.existsSync(targetFilePath)
            ? targetFilePath
            : (relLocPath ? path.join(effectiveRoot, relLocPath) : effectiveRoot);

        const startTime = Date.now();
        let reScanResult;

        try {
            reScanResult = await scanner.scan(effectiveRoot, scanTarget, {
                scanId: `rescan-${Date.now()}`
            });
        } catch (e) {
            const reason = `Scanner execution failed during re-scan: ${e.message}`;
            const md = `### ⚠️ Re-Scan Verification: ${scanner.name}\n- Status: \`NOT VERIFIED\`\n- Error: ${e.message}\n`;
            return {
                status: VERIFICATION_STATUS.NOT_VERIFIED,
                machineStatus: OUTCOME_STATUS.NOT_VERIFIED,
                isResolved: false,
                reason,
                summary: reason,
                beforeFingerprint: originalFinding.findingFingerprint || originalFinding.Finding_Fingerprint || '',
                reScanDurationMs: Date.now() - startTime,
                stillPresent: false,
                newFindingsCount: 0,
                evidence: [md],
                evidenceMarkdown: md,
                scannerDetails: { id: scanner.id, name: scanner.name, version: scanner.version }
            };
        }

        const durationMs = Date.now() - startTime;
        const findings = reScanResult.findings || [];

        // Check for explicit scanner execution failures or unavailable/incomplete states
        const scanFailed = reScanResult.status === SCANNER_STATUS.FAILED ||
            reScanResult.status === SCANNER_STATUS.UNAVAILABLE ||
            reScanResult.status === SCANNER_STATUS.NOT_INSTALLED ||
            reScanResult.status === SCANNER_STATUS.CANCELLED;
        const scanHasErrors = Array.isArray(reScanResult.errors) && reScanResult.errors.length > 0;

        // 1. Check if the original finding is still present (matching fingerprint OR matching ruleId + target file)
        const targetRelFile = relLocPath.replace(/\\/g, '/').toLowerCase();
        const ruleId = (originalFinding.ruleId || originalFinding.CVE_ID || '').toUpperCase();
        const baselineFp = originalFinding.findingFingerprint || originalFinding.Finding_Fingerprint || '';

        const matchingFinding = findings.find(f => {
            if (baselineFp && f.findingFingerprint === baselineFp) {
                return true;
            }
            const fFile = (f.filePath || '').replace(/\\/g, '/').toLowerCase();
            const fRule = (f.ruleId || '').toUpperCase();
            return fRule === ruleId && targetRelFile && fFile.endsWith(path.basename(targetRelFile));
        });

        // 2. Check for regressions (new security findings introduced in same file)
        const regressions = findings.filter(f => {
            if (matchingFinding && f === matchingFinding) return false;
            if (!targetRelFile) return true;
            const fFile = (f.filePath || '').replace(/\\/g, '/').toLowerCase();
            return fFile.endsWith(path.basename(targetRelFile));
        });

        const testOutcome = classifyTestOutcome(postFixTestResult, {
            allowZeroTests: params.requiresTests === false
        });

        let machineStatus = OUTCOME_STATUS.NOT_VERIFIED;
        let explanation = '';

        if (scanFailed) {
            machineStatus = OUTCOME_STATUS.NOT_VERIFIED;
            explanation = `Originating scanner '${scanner.name}' ended in status '${reScanResult.status}': ${(reScanResult.errors || []).join('; ') || 'Scan incomplete.'}`;
        } else if (scanHasErrors) {
            machineStatus = OUTCOME_STATUS.INCONCLUSIVE;
            explanation = `Originating scanner '${scanner.name}' reported errors during re-scan: ${reScanResult.errors.join('; ')}`;
        } else if (matchingFinding) {
            machineStatus = OUTCOME_STATUS.STILL_PRESENT;
            explanation = `The original vulnerability (${ruleId}) is still detected by ${scanner.name} at line ${matchingFinding.line}.`;
        } else if (regressions.length > 0) {
            machineStatus = OUTCOME_STATUS.REGRESSION_DETECTED;
            explanation = `The original vulnerability is no longer matched, but ${regressions.length} new security finding(s) were introduced: ${regressions.map(r => r.ruleId).join(', ')}.`;
        } else if (testOutcome === OUTCOME_STATUS.FAILED) {
            machineStatus = OUTCOME_STATUS.REGRESSION_DETECTED;
            explanation = 'The security finding was not detected on re-scan, but post-fix validation tests failed.';
        } else if (reScanResult.coverage && /(^|\s)0%/.test(reScanResult.coverage)) {
            machineStatus = OUTCOME_STATUS.INCONCLUSIVE;
            explanation = `Re-scan coverage was incomplete (${reScanResult.coverage}). Outcome is inconclusive.`;
        } else if (params.requiresTests !== false && testOutcome !== OUTCOME_STATUS.PASSED) {
            machineStatus = OUTCOME_STATUS.NOT_VERIFIED;
            explanation = `Security re-scan found 0 matching findings, but required post-fix test validation did not pass (status: ${testOutcome}). Cannot mark RESOLVED.`;
        } else {
            machineStatus = OUTCOME_STATUS.RESOLVED;
            explanation = `Original security vulnerability (${ruleId}) is completely absent from targeted re-scan (${scanner.name} v${scanner.version}) with verified post-fix tests and 0 regressions.`;
        }

        const finalStatus = toLegacyVerificationDisplay(machineStatus);

        // Format Markdown Comparison Evidence
        const evidenceMarkdown = [
            `### 🔬 Post-Remediation Verification & Re-Scan Audit`,
            `- **Scanner**: \`${scanner.name}\` (ID: \`${scanner.id}\`, Version: \`${scanner.version}\`)`,
            `- **Verification Status**: **\`${finalStatus}\`** (\`${machineStatus}\`)`,
            `- **Post-Fix Validation Outcome**: \`${testOutcome}\``,
            `- **Target Path**: \`${path.relative(effectiveRoot, scanTarget) || '.'}\``,
            `- **Original Rule ID**: \`${ruleId || 'N/A'}\``,
            `- **Baseline Fingerprint**: \`${baselineFp || 'N/A'}\``,
            `- **Re-Scan Duration**: \`${(durationMs / 1000).toFixed(2)}s\``,
            `- **Findings Detected Post-Fix**: \`${findings.length}\``,
            `- **Evaluation Summary**: ${explanation}`,
            ``
        ].join('\n');

        return {
            status: finalStatus,
            machineStatus,
            testOutcome,
            isResolved: machineStatus === OUTCOME_STATUS.RESOLVED,
            reason: explanation,
            summary: explanation,
            beforeFingerprint: baselineFp,
            reScanDurationMs: durationMs,
            stillPresent: !!matchingFinding,
            newFindingsCount: regressions.length,
            evidence: [evidenceMarkdown],
            evidenceMarkdown,
            scannerDetails: {
                id: scanner.id,
                name: scanner.name,
                version: scanner.version
            }
        };
    }
}

module.exports = {
    ReScanVerifier
};
