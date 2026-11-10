'use strict';

const { classifyFileOwnership, OWNERSHIP_TIER } = require('./remediationScopeGate');

const REMEDIATION_LADDER = Object.freeze([
    '1_SECURE_CONFIG_CHANGE',
    '2_SUPPORTED_RUNTIME_UPGRADE',
    '3_EXISTING_DEPENDENCY_UPGRADE',
    '4_MINIMAL_APPLICATION_CODE_CHANGE',
    '5_MANUAL_ARCHITECTURAL_REMEDIATION'
]);

const VULNERABILITY_TYPES = Object.freeze({
    SQL_INJECTION: 'SQL_INJECTION',
    COMMAND_INJECTION: 'COMMAND_INJECTION',
    PATH_TRAVERSAL: 'PATH_TRAVERSAL',
    XSS: 'XSS',
    HARDCODED_SECRET: 'HARDCODED_SECRET',
    WEAK_CRYPTO_MIGRATION: 'WEAK_CRYPTO_MIGRATION',
    DEPENDENCY_VULNERABILITY: 'DEPENDENCY_VULNERABILITY',
    SECURITY_CONFIG: 'SECURITY_CONFIG',
    INFRASTRUCTURE_NON_CODE: 'INFRASTRUCTURE_NON_CODE',
    UNKNOWN: 'UNKNOWN'
});

function inferVulnerabilityType(finding = {}) {
    const combined = `${finding.Title || ''} ${finding.Detailed_Name || ''} ${finding.CVE_ID || ''} ${finding.Source_Classification || ''} ${finding.Remediation_Guidance || ''}`.toLowerCase();
    const loc = String(finding.Location_Path || '').toLowerCase();

    if (combined.includes('ivanti') || combined.includes('buffer overflow') || loc.startsWith('/opt/') || combined.includes('appliance')) {
        return VULNERABILITY_TYPES.INFRASTRUCTURE_NON_CODE;
    }
    if (combined.includes('3pp') || loc.endsWith('.csproj') || loc.endsWith('pom.xml') || loc.endsWith('package.json') ||
        (finding.Current_Version && finding.Fixed_Version) || combined.includes('nuget') || combined.includes('cwe-1395')) {
        return VULNERABILITY_TYPES.DEPENDENCY_VULNERABILITY;
    }
    if (combined.includes('sql') || combined.includes('cwe-89')) {
        return VULNERABILITY_TYPES.SQL_INJECTION;
    }
    if (combined.includes('command injection') || combined.includes('os command') || combined.includes('cwe-78')) {
        return VULNERABILITY_TYPES.COMMAND_INJECTION;
    }
    if (combined.includes('path traversal') || combined.includes('directory traversal') || combined.includes('cwe-22')) {
        return VULNERABILITY_TYPES.PATH_TRAVERSAL;
    }
    if (combined.includes('xss') || combined.includes('cross-site scripting') || combined.includes('cwe-79')) {
        return VULNERABILITY_TYPES.XSS;
    }
    if (combined.includes('cryptographic') || combined.includes('des') || combined.includes('migration') || combined.includes('refactor') || combined.includes('protocol')) {
        return VULNERABILITY_TYPES.WEAK_CRYPTO_MIGRATION;
    }
    if (combined.includes('secret') || combined.includes('api key') || combined.includes('cwe-798') || combined.includes('password')) {
        return VULNERABILITY_TYPES.HARDCODED_SECRET;
    }
    if (loc.endsWith('.json') || loc.endsWith('.config') || loc.endsWith('.yml') || loc.endsWith('.yaml') || combined.includes('auth') || combined.includes('config')) {
        return VULNERABILITY_TYPES.SECURITY_CONFIG;
    }
    return VULNERABILITY_TYPES.UNKNOWN;
}

/**
 * Evaluates the lowest-risk legitimate remediation strategy using the 5-tier
 * Remediation Preference Ladder as a structured governance decision framework.
 */
function evaluateRemediationStrategy({ finding = {}, sourceCode = '', ownershipClassification = null, hasApprovedUpgradeTarget = null } = {}) {
    const vulnType = inferVulnerabilityType(finding);
    const loc = String(finding.Location_Path || 'unknown');
    const isManifest = /\.(?:csproj|json|xml|gradle)$/i.test(loc) && (loc.endsWith('.csproj') || loc.endsWith('pom.xml') || loc.endsWith('package.json'));
    const ownership = ownershipClassification || classifyFileOwnership(loc, { allowDependencyManifests: isManifest });
    const hasFixedVersion = Boolean(hasApprovedUpgradeTarget || (finding.Fixed_Version && String(finding.Fixed_Version).trim().length > 0));
    const combinedText = `${finding.Title || ''} ${finding.Detailed_Name || ''} ${finding.Remediation_Guidance || ''}`.toLowerCase();

    const isHighBlastRadius =
        vulnType === VULNERABILITY_TYPES.WEAK_CRYPTO_MIGRATION ||
        combinedText.includes('architectural') ||
        combinedText.includes('protocol migration') ||
        combinedText.includes('multi-service') ||
        combinedText.includes('large refactor');

    const isConfigFile = /\.(?:json|config|ya?ml|properties)$/i.test(loc);
    const alternativesEvaluated = [];
    let selectedTier = null;
    let recommendedStrategy = '';
    let requiresManualReview = false;
    let blastRadius = 'LOW';
    let automatedExecutionAllowed = true;
    let blockingReason = null;

    // Evaluate Tier 1: Secure Configuration Change
    if (vulnType === VULNERABILITY_TYPES.HARDCODED_SECRET && isConfigFile && ownership.editable) {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[0],
            feasible: true,
            suitable: true,
            reason: 'Application-owned configuration file exposes plaintext secret; replacing with secure environment/vault placeholder is lowest-risk.'
        });
        selectedTier = REMEDIATION_LADDER[0];
        recommendedStrategy = 'Replace plaintext credential in configuration with externalized environment/vault reference.';
    } else if (vulnType === VULNERABILITY_TYPES.SECURITY_CONFIG && isConfigFile && ownership.editable && !isHighBlastRadius) {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[0],
            feasible: true,
            suitable: true,
            reason: 'Configuration-level weakness in application-owned config file.'
        });
        selectedTier = REMEDIATION_LADDER[0];
        recommendedStrategy = 'Harden application security configuration setting.';
    } else {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[0],
            feasible: false,
            suitable: false,
            reason: vulnType === VULNERABILITY_TYPES.DEPENDENCY_VULNERABILITY
                ? 'Vulnerable third-party package cannot be patched safely via runtime configuration alone.'
                : 'Root cause lies in application source code logic or architectural/vendor layer rather than declarative config.'
        });
    }

    // Evaluate Tier 2: Supported Framework / Runtime Upgrade
    const mentionsFrameworkUpgrade = combinedText.includes('targetframework') || combinedText.includes('spring-boot-starter-parent') || combinedText.includes('runtime upgrade');
    if (!selectedTier && mentionsFrameworkUpgrade && hasFixedVersion && ownership.editable) {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[1],
            feasible: true,
            suitable: true,
            reason: 'Supported framework/runtime patch version is explicitly specified.'
        });
        selectedTier = REMEDIATION_LADDER[1];
        recommendedStrategy = `Upgrade supported framework/runtime reference to ${finding.Fixed_Version}.`;
    } else if (!selectedTier) {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[1],
            feasible: false,
            suitable: false,
            reason: 'No supported framework/runtime upgrade resolves this specific finding without unnecessary global blast radius.'
        });
    }

    // Evaluate Tier 3: Existing Dependency Upgrade
    if (!selectedTier && vulnType === VULNERABILITY_TYPES.DEPENDENCY_VULNERABILITY) {
        if (hasFixedVersion && ownership.tier === OWNERSHIP_TIER.APPLICATION_AUTHORED) {
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[2],
                feasible: true,
                suitable: true,
                reason: `Existing third-party dependency vulnerability has an approved target version (${finding.Fixed_Version}); preferred over custom code workarounds.`
            });
            selectedTier = REMEDIATION_LADDER[2];
            recommendedStrategy = `Upgrade dependency in manifest '${loc}' from '${finding.Current_Version || 'current'}' to '${finding.Fixed_Version}'.`;
        } else {
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[2],
                feasible: false,
                suitable: false,
                reason: 'Dependency vulnerability lacks a verified Fixed_Version or manifest ownership permission; routing to manual review.'
            });
            selectedTier = REMEDIATION_LADDER[4];
            requiresManualReview = true;
            automatedExecutionAllowed = false;
            blastRadius = 'MEDIUM';
            blockingReason = 'Dependency upgrade missing verified target version or approved manifest ownership.';
            recommendedStrategy = 'Manual dependency advisory review required.';
        }
    } else if (!selectedTier) {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[2],
            feasible: false,
            suitable: false,
            reason: 'Finding originates in custom/application code or infrastructure, not an outdated dependency manifest.'
        });
    }

    // Evaluate Tier 4: Minimal Application-Code Change
    if (!selectedTier) {
        const ownershipAllowsCodeEdit = ownership.tier === OWNERSHIP_TIER.APPLICATION_AUTHORED && ownership.editable && !ownership.isProtectedPolicyPath;
        if (vulnType === VULNERABILITY_TYPES.INFRASTRUCTURE_NON_CODE || vulnType === VULNERABILITY_TYPES.UNKNOWN) {
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[3],
                feasible: false,
                suitable: false,
                reason: vulnType === VULNERABILITY_TYPES.INFRASTRUCTURE_NON_CODE
                    ? 'Non-code infrastructure/appliance vulnerability cannot be remediated by editing application source files.'
                    : 'Vulnerability type or source ownership is uncertain; cannot safely automate source code changes.'
            });
        } else if (isHighBlastRadius) {
            blastRadius = 'HIGH';
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[3],
                feasible: false,
                suitable: false,
                reason: 'High-blast-radius cryptographic/architectural migration cannot be resolved safely via isolated single-file patch.'
            });
        } else if (!ownershipAllowsCodeEdit) {
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[3],
                feasible: false,
                suitable: false,
                reason: `Target file ownership '${ownership.tier}' prohibits direct automated code modification.`
            });
        } else {
            alternativesEvaluated.push({
                tier: REMEDIATION_LADDER[3],
                feasible: true,
                suitable: true,
                reason: 'Config/runtime/dependency options cannot fix custom application dataflow; minimal targeted code change in application-authored file is smallest safe fix.'
            });
            selectedTier = REMEDIATION_LADDER[3];
            recommendedStrategy = `Apply minimal targeted secure coding fix in application-authored '${loc}'.`;
        }
    }

    // Evaluate Tier 5: Manual Architectural Remediation (fallback / high-blast-radius / unsupported)
    if (!selectedTier) {
        selectedTier = REMEDIATION_LADDER[4];
        requiresManualReview = true;
        automatedExecutionAllowed = false;
        if (isHighBlastRadius) blastRadius = 'HIGH';
        blockingReason = blockingReason || 'No safe automated low-blast-radius remediation strategy; manual architectural or governance review required.';
        recommendedStrategy = 'Halt automated editing and escalate to Manual Architectural / Security Review.';
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[4],
            feasible: true,
            suitable: true,
            reason: blockingReason
        });
    } else {
        alternativesEvaluated.push({
            tier: REMEDIATION_LADDER[4],
            feasible: true,
            suitable: false,
            reason: 'Not required because a lower-risk automated tier is safe and sufficient.'
        });
    }

    return {
        vulnerabilityId: finding.Vulnerability_ID || 'UNKNOWN',
        vulnerabilityType: vulnType,
        affectedComponent: loc,
        ownershipTier: ownership.tier,
        sourceIsApplicationAuthored: ownership.tier === OWNERSHIP_TIER.APPLICATION_AUTHORED,
        blastRadius,
        selectedTier,
        recommendedStrategy,
        alternativesEvaluated,
        requiresManualReview,
        automatedExecutionAllowed,
        disposition: automatedExecutionAllowed ? 'AUTOMATED_CANDIDATE' : 'MANUAL_REVIEW',
        blockingReason
    };
}

/**
 * Deterministic source-to-sink RCA evidence builder inspecting actual source code.
 * Never claims formal taint-analysis proof unless genuine SARIF codeFlows were supplied.
 */
function extractSourceToSinkEvidence({ finding = {}, sourceCode = '', rca = null, baselineValidation = null, sarifCodeFlows = null } = {}) {
    const vulnType = inferVulnerabilityType(finding);
    const file = finding.Location_Path || 'unknown';
    const lines = String(sourceCode || '').split(/\r?\n/);
    const reportedLine = Math.max(1, parseInt(finding.Line_Number, 10) || 1);

    const hasFormalAnalyzerFlows = Array.isArray(sarifCodeFlows) && sarifCodeFlows.length > 0;
    const analysisMethod = hasFormalAnalyzerFlows
        ? 'FORMAL_SARIF_TAINT_ANALYZER'
        : 'DETERMINISTIC_SOURCE_SINK_HEURISTIC';

    // Find enclosing function/method name above reportedLine
    let affectedFunction = 'UnknownMethod';
    for (let i = Math.min(reportedLine - 1, lines.length - 1); i >= 0; i--) {
        const m = lines[i].match(/(?:public|private|protected|internal|async|static)\s+[A-Za-z0-9_<>\[\],\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/) ||
            lines[i].match(/(?:function|async\s+function)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/);
        if (m) {
            affectedFunction = `${m[1]}(${(m[2] || '').trim()})`;
            break;
        }
    }

    // Locate untrusted source parameters/inputs in actual code
    let untrustedSource = null;
    const sourcePatterns = [
        /\[From(?:Query|Body|Route|Form|Header)\]\s*[A-Za-z0-9_<>\[\]?]+\s+([A-Za-z_][A-Za-z0-9_]*)/,
        /@(?:RequestParam|PathVariable|RequestBody)\b[^A-Za-z_]*[A-Za-z0-9_<>]+\s+([A-Za-z_][A-Za-z0-9_]*)/,
        /\b(?:req\.(?:query|body|params)|Request\.(?:Query|Form|Headers))(?:\.[A-Za-z0-9_]+|\[['"][^'"]+['"]\])?/,
        /\(\s*(?:string|String)\s+([A-Za-z_][A-Za-z0-9_]*)/
    ];
    for (let i = 0; i < lines.length; i++) {
        for (const rx of sourcePatterns) {
            const m = lines[i].match(rx);
            if (m) {
                untrustedSource = {
                    symbol: m[1] || m[0],
                    file,
                    line: i + 1,
                    snippet: lines[i].trim()
                };
                break;
            }
        }
        if (untrustedSource) break;
    }

    // Locate dangerous sink & propagation evidence
    const sinkRegexByType = {
        [VULNERABILITY_TYPES.SQL_INJECTION]: /(?:CommandText|ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|SELECT\s+.*\+|INSERT\s+.*\+|UPDATE\s+.*\+|DELETE\s+.*\+)/i,
        [VULNERABILITY_TYPES.COMMAND_INJECTION]: /(?:Process\.Start|ProcessStartInfo|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|execSync|exec\(|spawn\()/i,
        [VULNERABILITY_TYPES.PATH_TRAVERSAL]: /(?:Path\.Combine|PhysicalFile|File\.(?:ReadAll|Open|WriteAll)|Paths\.get|Files\.read|fs\.(?:readFile|createReadStream))/i,
        [VULNERABILITY_TYPES.XSS]: /(?:Content\s*\(|Html\.Raw|innerHTML|res\.send\s*\()/i
    };

    const sinkRx = sinkRegexByType[vulnType] || /(?:CommandText|Process\.Start|Path\.Combine|Content\s*\(|Execute)/i;
    let dangerousSink = null;
    const dataPropagationEvidence = [];

    for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i].trim();
        if (!lineText || lineText.startsWith('//')) continue;

        if (untrustedSource && untrustedSource.symbol && lineText.includes(untrustedSource.symbol)) {
            dataPropagationEvidence.push({
                line: i + 1,
                snippet: lineText,
                note: `References candidate untrusted input '${untrustedSource.symbol}'.`
            });
        }

        if (sinkRx.test(lineText) && !dangerousSink) {
            dangerousSink = {
                file,
                line: i + 1,
                snippet: lineText
            };
        }
    }

    // Check missing validation or encoding
    let missingValidationOrEncoding = 'Missing explicit validation/encoding/parameterization verified along candidate path.';
    const fullText = lines.join('\n');
    if (vulnType === VULNERABILITY_TYPES.SQL_INJECTION && !/Parameters\.Add|@AccountId|@name|PreparedStatement/i.test(fullText)) {
        missingValidationOrEncoding = 'SQL query uses string concatenation/interpolation without parameterized query placeholders (e.g. SqlParameter / PreparedStatement).';
    } else if (vulnType === VULNERABILITY_TYPES.COMMAND_INJECTION && !/Regex\.IsMatch|ArgumentList/i.test(fullText)) {
        missingValidationOrEncoding = 'User-supplied input reaches shell/process command invocation without strict allowlist validation or ArgumentList separation.';
    } else if (vulnType === VULNERABILITY_TYPES.PATH_TRAVERSAL && !(/GetFullPath/i.test(fullText) && /StartsWith/i.test(fullText))) {
        missingValidationOrEncoding = 'File path input lacks canonical Path.GetFullPath() + base-directory prefix containment validation.';
    } else if (vulnType === VULNERABILITY_TYPES.XSS && !/HtmlEncode|HtmlEncoder/i.test(fullText)) {
        missingValidationOrEncoding = 'Untrusted output is emitted into HTML response without HTML encoding.';
    }

    const baselineTestEvidence = baselineValidation
        ? {
            status: baselineValidation.status || baselineValidation.machineStatus || 'NOT_EXECUTED',
            command: baselineValidation.command || null,
            exitCode: baselineValidation.exitCode ?? null,
            summary: baselineValidation.summary || ''
        }
        : {
            status: 'NOT_EXECUTED',
            command: null,
            exitCode: null,
            summary: 'No reproducible baseline test runner executed yet; documented static inspection evidence.'
        };

    return {
        vulnerabilityType: vulnType,
        analysisMethod,
        formalTaintProofSupplied: hasFormalAnalyzerFlows,
        formalTaintNotice: hasFormalAnalyzerFlows
            ? 'Taint flow supplied by external CodeQL/SARIF analyzer.'
            : 'Heuristic AST-free static source/sink trace on target file; not a formal whole-program taint proof.',
        untrustedSource: untrustedSource || {
            symbol: 'Unresolved (inspect method parameters)',
            file,
            line: reportedLine,
            snippet: lines[reportedLine - 1] ? lines[reportedLine - 1].trim() : ''
        },
        dataPropagationEvidence,
        dangerousSink: dangerousSink || {
            file,
            line: reportedLine,
            snippet: lines[reportedLine - 1] ? lines[reportedLine - 1].trim() : ''
        },
        missingValidationOrEncoding,
        affectedFile: file,
        affectedFunction,
        affectedLines: rca?.affectedLines || `Line ${dangerousSink ? dangerousSink.line : reportedLine}`,
        proposedRemediation: rca?.proposedFix || finding.Remediation_Guidance || 'Apply targeted secure coding control.',
        baselineTestEvidence
    };
}

module.exports = {
    REMEDIATION_LADDER,
    VULNERABILITY_TYPES,
    inferVulnerabilityType,
    evaluateRemediationStrategy,
    extractSourceToSinkEvidence
};

