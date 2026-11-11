const crypto = require('crypto');

/**
 * Normalized Finding Model for GCAC Vulnerability Remediation Hub
 * Conforms to Milestone B Specifications, Phase 1-3 Security Controls,
 * and Canonical Finding-to-Repository Context Contract (GCAC-FINDING-CTX-1.0).
 */

const SEVERITY_LEVELS = Object.freeze({
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFORMATIONAL: 'Informational'
});

const SCANNER_STATUS = Object.freeze({
    NOT_INSTALLED: 'Not Installed',
    NOT_CONFIGURED: 'Not Configured',
    READY: 'Ready',
    RUNNING: 'Running',
    COMPLETED: 'Completed',
    PARTIAL: 'Partial',
    FAILED: 'Failed',
    CANCELLED: 'Cancelled',
    UNAVAILABLE: 'Unavailable',
    NO_SCANNABLE_INPUTS: 'No Scannable Inputs'
});

const VERIFICATION_STATUS = Object.freeze({
    RESOLVED: 'RESOLVED',
    STILL_PRESENT: 'STILL PRESENT',
    INCONCLUSIVE: 'INCONCLUSIVE',
    NOT_VERIFIED: 'NOT VERIFIED',
    REGRESSION_DETECTED: 'REGRESSION DETECTED'
});

/**
 * Infers language/technology stack from file extension when explicit technology isn't supplied.
 */
function inferTechnologyFromFilePath(filePath, fallbackTech = '') {
    const p = String(filePath || '').toLowerCase();
    if (p.endsWith('.cs') || p.endsWith('.csproj') || p.endsWith('.sln') || p.endsWith('packages.config')) {
        return 'dotnet';
    }
    if (p.endsWith('.java') || p.endsWith('pom.xml') || p.endsWith('.gradle') || p.endsWith('.properties')) {
        return 'java-spring';
    }
    if (/\.(?:js|ts|jsx|tsx|mjs|cjs)$/i.test(p) || p.endsWith('package.json')) {
        return 'nodejs';
    }
    if (p.endsWith('.py') || p.endsWith('requirements.txt')) {
        return 'python';
    }
    return fallbackTech || 'unknown';
}

/**
 * Generates a deterministic, location-resilient finding fingerprint.
 * Fingerprint is based on ruleId + normalized file path + sanitized code token/evidence pattern
 * so that line number shifts during editing do not lose finding identity.
 * 
 * @param {string} ruleId 
 * @param {string} filePath 
 * @param {string} codeContext 
 * @returns {string} SHA-256 hex digest (truncated to 16 chars)
 */
function generateFindingFingerprint(ruleId, filePath, codeContext = '') {
    const normFile = (filePath || '').replace(/\\/g, '/').toLowerCase();
    const normRule = (ruleId || '').trim().toUpperCase();
    const normContext = (codeContext || '').trim().replace(/\s+/g, ' ').substring(0, 120);
    const content = `${normRule}:${normFile}:${normContext}`;
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex').substring(0, 16);
}

/**
 * Sanitizes and masks sensitive credential values in evidence strings
 * Ensures secrets, passwords, and private tokens are never stored or exposed in full.
 * 
 * @param {string} text 
 * @returns {string} masked text
 */
function maskSensitiveEvidence(text) {
    if (!text || typeof text !== 'string') return '';
    
    // Mask API Keys (sk_live_..., sk_test_..., AKIA..., etc.)
    let masked = text.replace(/(sk_[a-zA-Z0-9]*?_)([a-zA-Z0-9_-]{8,})/gi, (m, prefix, secret) => {
        return `${prefix}****${secret.slice(-4)}`;
    });

    // Mask AWS access keys
    masked = masked.replace(/(AKIA[0-9A-Z]{4})([0-9A-Z]{12})/g, (m, prefix, secret) => {
        return `${prefix}****${secret.slice(-4)}`;
    });

    // Mask generic passwords and secrets in JSON/config
    masked = masked.replace(/(["']?(?:password|pwd|secret|apikey|api_key|token|access_key)["']?\s*[:=]\s*["'])([^"'\r\n]{4,})(["'])/gi, 
        (m, prefix, secret, suffix) => {
            const visible = secret.length > 6 ? `${secret.substring(0, 2)}****${secret.slice(-2)}` : '****';
            return `${prefix}${visible}${suffix}`;
        }
    );

    // Mask JWTs
    masked = masked.replace(/(eyJ[a-zA-Z0-9_-]{10,}\.)([a-zA-Z0-9_-]{10,})\.([a-zA-Z0-9_-]{10,})/g, (m, p1, p2, p3) => {
        return `${p1.substring(0, 8)}...[JWT_PAYLOAD_MASKED]...${p3.slice(-6)}`;
    });

    return masked;
}

/**
 * Normalized Finding class representing a discovered security issue from any scanner.
 */
class NormalizedFinding {
    constructor(data = {}) {
        this.contextSchemaVersion = data.contextSchemaVersion || 'GCAC-FINDING-CTX-1.0';
        this.scannerId = data.scannerId || 'unknown';
        this.scannerVersion = data.scannerVersion || '1.0.0';
        this.ruleId = data.ruleId || 'GENERIC-SECURITY';
        this.title = data.title || 'Security Finding';
        this.description = data.description || '';
        this.severity = this._normalizeSeverity(data.severity);
        this.confidence = data.confidence || null; // 'High' | 'Medium' | 'Low' | null
        this.detectionMethod = data.detectionMethod || (data.classificationType === 'POTENTIAL_SECRET_REVIEW' ? 'HEURISTIC_PATTERN' : 'ANALYZER_RULE');
        this.cwe = data.cwe || null; // e.g. 'CWE-798', 'CWE-89'
        this.filePath = (data.filePath || '').replace(/\\/g, '/');
        this.line = typeof data.line === 'number' ? data.line : (parseInt(data.line, 10) || null);
        this.column = typeof data.column === 'number' ? data.column : (parseInt(data.column, 10) || null);
        this.evidence = maskSensitiveEvidence(data.evidence || '');
        this.evidenceRef = data.evidenceRef || (this.filePath ? `${this.filePath}:${this.line || 1}` : '');
        this.remediationGuidance = data.remediationGuidance || '';
        this.scanId = data.scanId || '';
        this.timestamp = data.timestamp || new Date().toISOString();
        this.findingFingerprint = data.findingFingerprint || data.fingerprint || generateFindingFingerprint(this.ruleId, this.filePath, data.rawCodeContext || data.evidence);
        this.findingId = data.findingId || `SCAN-${this.ruleId}-${this.findingFingerprint.substring(0, 8).toUpperCase()}`;
        this.status = data.status || 'Detected'; // 'Detected' | 'Remediating' | 'Resolved' | 'Still Present'
        this.rawSourceReference = data.rawSourceReference || null;
        this.sourceClassification = data.sourceClassification || 'LocalScanner';

        // Canonical repository & application provenance (never invent fake enterprise IDs!)
        this.repository = data.repository || '';
        this.repositoryRoot = data.repositoryRoot || '';
        this.canonicalRepositoryId = data.canonicalRepositoryId || '';
        this.projectPath = (data.projectPath || '').replace(/\\/g, '/');
        this.applicationNumber = data.applicationNumber || data.Application_Number || '';
        this.applicationName = data.applicationName || data.Application_Name || '';
        this.applicationIdentitySource = data.applicationIdentitySource || '';
        this.technology = data.technology || data.Technology || inferTechnologyFromFilePath(this.projectPath || this.filePath, '');
        this.packageName = data.packageName || '';
        this.currentVersion = data.currentVersion || data.Current_Version || '';
        this.fixedVersion = data.fixedVersion || data.Fixed_Version || '';
        this.advisoryUrl = data.advisoryUrl || '';
        this.isHistorical = Boolean(data.isHistorical);
        this.lastSeenScanId = data.lastSeenScanId || this.scanId || '';

        this.classificationType = data.classificationType || 'CONFIRMED_RULE_VIOLATION'; // 'CONFIRMED_RULE_VIOLATION' | 'POTENTIAL_SECRET_REVIEW' | 'INFORMATIONAL_OBSERVATION'
    }

    get fingerprint() {
        return this.findingFingerprint;
    }

    _normalizeSeverity(sev) {
        if (!sev) return SEVERITY_LEVELS.MEDIUM;
        const s = sev.toString().toUpperCase();
        if (s.includes('CRIT')) return SEVERITY_LEVELS.CRITICAL;
        if (s.includes('HIGH') || s === 'ERROR') return SEVERITY_LEVELS.HIGH;
        if (s.includes('MED') || s === 'WARNING') return SEVERITY_LEVELS.MEDIUM;
        if (s.includes('LOW')) return SEVERITY_LEVELS.LOW;
        if (s.includes('INFO') || s === 'NOTE') return SEVERITY_LEVELS.INFORMATIONAL;
        return SEVERITY_LEVELS.MEDIUM;
    }

    /**
     * Converts to compatible CSV row object matching the GCAC vulnerabilities.csv schema
     * and preserving canonical finding-to-repository provenance metadata.
     */
    toCsvCompatibleRecord() {
        const repoDisplay = this.repository || this.repositoryRoot || '';
        const repoBase = repoDisplay ? repoDisplay.replace(/\\/g, '/').split('/').filter(Boolean).pop() : '';
        const inferredTech = this.technology || inferTechnologyFromFilePath(this.projectPath || this.filePath, 'unknown');

        return {
            Vulnerability_ID: this.findingId,
            Context_Schema_Version: this.contextSchemaVersion || 'GCAC-FINDING-CTX-1.0',
            Source_Type: 'SCANNER',
            Source_Origin: 'LocalScanner',
            Scanner_ID: this.scannerId,
            Scanner_Version: this.scannerVersion,
            Scan_ID: this.scanId || '',
            Detection_Method: this.detectionMethod || 'ANALYZER_RULE',
            Finding_Fingerprint: this.findingFingerprint,
            Application_Number: this.applicationNumber || '',
            Application_Name: this.applicationName || repoBase || 'Unmapped Local Repository',
            Application_Identity_Source: this.applicationIdentitySource || '',
            Severity: this.severity ? this.severity.toString().toUpperCase() : 'MEDIUM',
            SLA_Status: 'In SLA',
            Finding_Date: this.timestamp.split('T')[0],
            CVE_ID: this.cwe || this.ruleId,
            Title: this.title,
            Detailed_Name: `${this.ruleId} - ${this.title}`,
            Package_Name: this.packageName || '',
            Current_Version: this.currentVersion || '',
            Fixed_Version: this.fixedVersion || '',
            Advisory_URL: this.advisoryUrl || '',
            Remediation_Guidance: this.remediationGuidance || 'Review finding details and remediate using recommended security practice.',
            Location_Path: this.filePath,
            Line_Number: this.line ? this.line.toString() : '1',
            Evidence_Ref: this.evidenceRef || (this.filePath ? `${this.filePath}:${this.line || 1}` : ''),
            Source_Classification: this.sourceClassification,
            Technology: inferredTech,
            Repository: this.repository || '',
            Repository_Root: this.repositoryRoot || '',
            Canonical_Repository_ID: this.canonicalRepositoryId || '',
            Project_Path: this.projectPath || '',
            Is_Historical: this.isHistorical ? 'true' : 'false',
            Last_Seen_Scan_ID: this.lastSeenScanId || this.scanId || '',
            Internet_Facing: 'false',
            Product_Owner: 'Security Team',
            Primary_Manager: 'Engineering Lead',
            Requires_Human_Review: (this.classificationType === 'POTENTIAL_SECRET_REVIEW' || !this.repository || !this.applicationNumber) ? 'true' : 'false',
            Agent_Code_Analysis_Output: this.description,
            Agent_Unit_Test_Output: '',
            Agent_Remediation_Output: '',
            Agent_Regression_Output: '',
            Agent_Final_Validation_Output: '',
            Agent_Documentation_Output: '',
            Remediation_Status: this.status === 'Resolved' ? 'Remediated' : (this.status === 'Detected' ? 'Pending' : (this.status || 'Pending')),
            Final_Validation_Status: 'Pending',
            Final_Confidence_Score: '0',
            Test_Status: 'Pending',
            Regression_Status: 'Pending',
            Files_Changed: '',
            Remediation_Report: ''
        };
    }

    /**
     * Exports finding to a SARIF 2.1.0 result object
     */
    toSarifResult() {
        return {
            ruleId: this.ruleId,
            message: { text: this.description || this.title },
            level: this.severity === SEVERITY_LEVELS.CRITICAL || this.severity === SEVERITY_LEVELS.HIGH ? 'error' : 
                   (this.severity === SEVERITY_LEVELS.MEDIUM ? 'warning' : 'note'),
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: { uri: this.filePath },
                        region: {
                            startLine: this.line || 1,
                            startColumn: this.column || 1
                        }
                    }
                }
            ],
            properties: {
                findingId: this.findingId,
                scannerId: this.scannerId,
                scanId: this.scanId,
                confidence: this.confidence,
                detectionMethod: this.detectionMethod,
                cwe: this.cwe,
                fingerprint: this.findingFingerprint,
                classificationType: this.classificationType,
                repository: this.repository,
                repositoryRoot: this.repositoryRoot,
                canonicalRepositoryId: this.canonicalRepositoryId,
                applicationNumber: this.applicationNumber
            }
        };
    }
}

module.exports = {
    SEVERITY_LEVELS,
    SCANNER_STATUS,
    VERIFICATION_STATUS,
    inferTechnologyFromFilePath,
    generateFindingFingerprint,
    maskSensitiveEvidence,
    NormalizedFinding
};
