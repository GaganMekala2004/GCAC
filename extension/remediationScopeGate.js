'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { assertPathWithinWorkspace } = require('./pathUtils');

const OWNERSHIP_TIER = Object.freeze({
    APPLICATION_AUTHORED: 'APPLICATION_AUTHORED',
    FRAMEWORK_EMBEDDED: 'FRAMEWORK_EMBEDDED',
    VENDORED_THIRD_PARTY: 'VENDORED_THIRD_PARTY',
    UNKNOWN_REQUIRES_REVIEW: 'UNKNOWN_REQUIRES_REVIEW'
});

const PROTECTED_POLICY_PATTERNS = Object.freeze([
    /(?:^|\/)\.github(?:\/|$)/i,
    /(?:^|\/)\.vscode(?:\/|$)/i,
    /(?:^|\/)\.agents(?:\/|$)/i,
    /(?:^|\/)\.git(?:\/|$)/i,
    /(?:^|\/)vulnerability\/vulnerabilities\.csv$/i,
    /(?:^|\/)vulnerabilities\.csv$/i,
    /(?:^|\/)vulnerabilities\.db(?:-wal|-shm)?$/i,
    /\.xlsx?$/i,
    /(?:^|\/)\.env(?:\.[^/\s]+)?$/i,
    /\.(?:pem|key|pfx|p12|jks|keystore)$/i,
    /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
    /(?:^|\/)credentials\.json$/i,
    /(?:^|\/)(?:\.eslintrc[^/]*|codeql-config[^/]*|\.gitleaks[^/]*|Directory\.Build\.props|\.editorconfig|jest\.config[^/]*|xunit\.runner\.json)$/i,
    /\.(?:ruleset|runsettings)$/i
]);

const VENDORED_PATH_PATTERNS = Object.freeze([
    /(?:^|\/)(?:vendor|third_party|third-party|node_modules|packages|bower_components|wwwroot\/lib|lib\/vendor)(?:\/|$)/i,
    /\.min\.(?:js|css)$/i
]);

const FRAMEWORK_PATH_PATTERNS = Object.freeze([
    /(?:^|\/)(?:bin|obj|Migrations|generated)(?:\/|$)/i,
    /(?:^|\/)Properties\/AssemblyInfo\.cs$/i,
    /\.(?:designer|g|g\.i)\.(?:cs|vb)$/i
]);

const DEPENDENCY_MANIFEST_PATTERNS = Object.freeze([
    /\.csproj$/i,
    /(?:^|\/)(?:packages\.config|Directory\.Packages\.props|package\.json|package-lock\.json|pom\.xml|build\.gradle(?:\.kts)?|requirements\.txt)$/i
]);

const TEST_FILE_PATTERNS = Object.freeze([
    /(?:^|\/)(?:tests?|__tests__|spec)(?:\/|$)/i,
    /\.(?:test|spec)\.(?:js|ts|cs|java)$/i,
    /Tests?\.(?:cs|java)$/i
]);

const SUPPRESSION_PATTERNS = Object.freeze([
    /#pragma\s+warning\s+disable/i,
    /@SuppressWarnings/i,
    /\[SuppressMessage/i,
    /\/\/\s*(?:nosec|noqa)/i,
    /\/\*\s*eslint-disable/i,
    /\/\/\s*eslint-disable/i,
    /<NoWarn>/i
]);

const TEST_WEAKENING_DETECTION_LIMITATIONS =
    'Automated test-weakening checks detect syntactic indicators (skip attributes, deleted test methods/assertions, ' +
    'and trivial Assert.True(true)/assert(true) replacements). Semantic test weakening—such as altering test input ' +
    'fixtures so an exploit payload is no longer exercised or mocking away a vulnerable function—cannot be reliably ' +
    'guaranteed without human diff inspection.';

class ScopeViolationError extends Error {
    constructor(reason, violations = []) {
        super(`BLOCKED (ScopeViolation): ${reason}`);
        this.name = 'ScopeViolationError';
        this.machineStatus = 'BLOCKED';
        this.violations = violations;
    }
}

function normalizeRelPath(p) {
    return String(p || '').trim().replace(/\\/g, '/').replace(/^\.\//, '');
}

function isProtectedPolicyPath(relPath, customDenylist = []) {
    const norm = normalizeRelPath(relPath);
    if (!norm) return true;
    if (PROTECTED_POLICY_PATTERNS.some(rx => rx.test(norm))) return true;
    return (customDenylist || []).some(rx => (rx instanceof RegExp ? rx.test(norm) : norm.toLowerCase().includes(String(rx).toLowerCase())));
}

function isDependencyManifestPath(relPath) {
    return DEPENDENCY_MANIFEST_PATTERNS.some(rx => rx.test(normalizeRelPath(relPath)));
}

function isTestFilePath(relPath) {
    return TEST_FILE_PATTERNS.some(rx => rx.test(normalizeRelPath(relPath)));
}

/**
 * Deterministically classifies a file into one of four ownership tiers.
 * Defaults uncertain files to UNKNOWN_REQUIRES_REVIEW.
 */
function classifyFileOwnership(relPath, options = {}) {
    const norm = normalizeRelPath(relPath);
    if (!norm || norm.startsWith('..') || path.isAbsolute(relPath)) {
        return {
            path: norm,
            tier: OWNERSHIP_TIER.UNKNOWN_REQUIRES_REVIEW,
            editable: false,
            isProtectedPolicyPath: true,
            isDependencyManifest: false,
            reason: 'Invalid, empty, or non-relative path defaults to review.'
        };
    }

    if (isProtectedPolicyPath(norm, options.denylist)) {
        return {
            path: norm,
            tier: OWNERSHIP_TIER.UNKNOWN_REQUIRES_REVIEW,
            editable: false,
            isProtectedPolicyPath: true,
            isDependencyManifest: false,
            reason: 'Protected policy, CI/CD, agent config, credential, or master data path is denied.'
        };
    }

    if (VENDORED_PATH_PATTERNS.some(rx => rx.test(norm))) {
        return {
            path: norm,
            tier: OWNERSHIP_TIER.VENDORED_THIRD_PARTY,
            editable: false,
            isProtectedPolicyPath: false,
            isDependencyManifest: false,
            reason: 'Vendored third-party code cannot be edited directly during remediation.'
        };
    }

    if (FRAMEWORK_PATH_PATTERNS.some(rx => rx.test(norm))) {
        return {
            path: norm,
            tier: OWNERSHIP_TIER.FRAMEWORK_EMBEDDED,
            editable: false,
            isProtectedPolicyPath: false,
            isDependencyManifest: false,
            reason: 'Framework-embedded or generated artifact cannot be edited directly.'
        };
    }

    const isManifest = isDependencyManifestPath(norm);
    if (isManifest) {
        const allowManifest = options.allowDependencyManifests === true;
        return {
            path: norm,
            tier: OWNERSHIP_TIER.APPLICATION_AUTHORED,
            editable: allowManifest,
            isProtectedPolicyPath: false,
            isDependencyManifest: true,
            reason: allowManifest
                ? 'Approved dependency manifest change permitted for dependency remediation.'
                : 'Dependency manifest changes require explicit dependency-upgrade authorization.'
        };
    }

    const isKnownAppSource = /\.(?:cs|java|js|jsx|ts|tsx|py|go|rb|php|json|xml|ya?ml|config|properties)$/i.test(norm);
    if (isKnownAppSource) {
        return {
            path: norm,
            tier: OWNERSHIP_TIER.APPLICATION_AUTHORED,
            editable: true,
            isProtectedPolicyPath: false,
            isDependencyManifest: false,
            reason: 'Application-authored source/configuration file.'
        };
    }

    return {
        path: norm,
        tier: OWNERSHIP_TIER.UNKNOWN_REQUIRES_REVIEW,
        editable: false,
        isProtectedPolicyPath: false,
        isDependencyManifest: false,
        reason: 'Uncertain file ownership defaults to manual review.'
    };
}

/**
 * Inspects unified diff lines for added diagnostic suppressions or test-weakening indicators.
 */
function inspectDiffForPolicyAndTestWeakening(diffText, touchedFiles = []) {
    const findings = [];
    const lines = String(diffText || '').split(/\r?\n/);

    let currentFile = touchedFiles[0] || '';
    const removedAssertionsByFile = new Map();
    const addedAssertionsByFile = new Map();

    for (const line of lines) {
        if (line.startsWith('+++ b/')) {
            currentFile = normalizeRelPath(line.slice(6));
            continue;
        }
        if (line.startsWith('+') && !line.startsWith('+++')) {
            const added = line.slice(1);
            if (SUPPRESSION_PATTERNS.some(rx => rx.test(added))) {
                findings.push({
                    type: 'SUPPRESSION_DIRECTIVE',
                    file: currentFile,
                    detail: 'Diagnostic or security suppression directive added in patch.'
                });
            }
            if (/\[(?:Fact|Theory)\s*\([^\)]*Skip\s*=|@(?:Disabled|Ignore)\b|\b(?:it|test|describe)\.skip\s*\(/i.test(added)) {
                findings.push({
                    type: 'TEST_SKIP_ADDED',
                    file: currentFile,
                    detail: 'Test skip/disable attribute added in patch.'
                });
            }
            if (/\b(?:Assert\.True\s*\(\s*true\s*\)|assert\s*\(\s*true\s*\)|assert\.ok\s*\(\s*true\s*\)|assertTrue\s*\(\s*true\s*\))/i.test(added)) {
                findings.push({
                    type: 'TEST_TRIVIAL_ASSERTION',
                    file: currentFile,
                    detail: 'Trivial always-true assertion detected.'
                });
            }
            if (/\b(?:Assert\.|assert\(|assert\.|assertEquals|assertTrue|assertThrows|expect\()/i.test(added)) {
                addedAssertionsByFile.set(currentFile, (addedAssertionsByFile.get(currentFile) || 0) + 1);
            }
        } else if (line.startsWith('-') && !line.startsWith('---')) {
            const removed = line.slice(1);
            if (/\b(?:Assert\.|assert\(|assert\.|assertEquals|assertTrue|assertThrows|expect\(|\[Fact\]|\[Theory\]|@Test)\b/i.test(removed)) {
                removedAssertionsByFile.set(currentFile, (removedAssertionsByFile.get(currentFile) || 0) + 1);
            }
        }
    }

    for (const [file, removedCount] of removedAssertionsByFile.entries()) {
        const addedCount = addedAssertionsByFile.get(file) || 0;
        if (removedCount > addedCount) {
            findings.push({
                type: 'TEST_ASSERTION_REMOVED',
                file,
                detail: `Net removal of ${removedCount - addedCount} test assertion/case declaration(s) detected in '${file}'.`
            });
        }
    }

    return findings;
}

/**
 * Checks whether a candidate path inside worktreeDir involves any symlink escape.
 */
function assertNoSymlinkEscape(worktreeDir, relPath) {
    const cleanRel = normalizeRelPath(relPath);
    if (!cleanRel || cleanRel.startsWith('..') || path.isAbsolute(relPath) || cleanRel.includes('\0')) {
        return { safe: false, reason: `Unsafe relative path '${relPath}'.` };
    }
    const candidate = path.resolve(worktreeDir, cleanRel);
    const contained = assertPathWithinWorkspace(candidate, worktreeDir);
    if (!contained) {
        return { safe: false, reason: `Path '${relPath}' escapes workspace boundary.` };
    }

    // Walk segments to ensure no existing symlink component exists
    const segments = cleanRel.split('/').filter(Boolean);
    let cursor = path.resolve(worktreeDir);
    for (const seg of segments) {
        cursor = path.join(cursor, seg);
        if (fs.existsSync(cursor)) {
            const st = fs.lstatSync(cursor);
            if (st.isSymbolicLink()) {
                return { safe: false, reason: `Symlink detected at '${cleanRel}' — symlink escapes and symlink writes are blocked.` };
            }
        }
    }
    return { safe: true, resolvedPath: contained };
}

/**
 * Pre-write validation of proposed file paths, ownership tiers, denylist, symlinks,
 * suppression rules, and test-weakening indicators.
 */
function validateProposedChangesScope(params = {}) {
    const {
        worktreeDir,
        proposedFiles = [],
        approvedFilePaths = [],
        patchDiff = '',
        fullRemediatedCode = '',
        allowDependencyManifests = false,
        denylist = []
    } = params;

    const violations = [];
    const approvedSet = new Set((approvedFilePaths || []).map(normalizeRelPath).filter(Boolean));
    const filesToCheck = Array.from(new Set((proposedFiles || []).map(normalizeRelPath).filter(Boolean)));

    if (filesToCheck.length === 0) {
        violations.push({ type: 'NO_FILES_SPECIFIED', detail: 'No target file paths present in proposed scope.' });
    }

    for (const rel of filesToCheck) {
        if (worktreeDir) {
            const symCheck = assertNoSymlinkEscape(worktreeDir, rel);
            if (!symCheck.safe) {
                violations.push({ type: 'SYMLINK_OR_ESCAPE', file: rel, detail: symCheck.reason });
                continue;
            }
        }

        const ownership = classifyFileOwnership(rel, { allowDependencyManifests, denylist });
        if (ownership.isProtectedPolicyPath) {
            violations.push({ type: 'PROTECTED_POLICY_PATH', file: rel, detail: ownership.reason });
        } else if (!ownership.editable) {
            violations.push({ type: `DISALLOWED_OWNERSHIP_${ownership.tier}`, file: rel, detail: ownership.reason });
        }

        if (approvedSet.size > 0 && !approvedSet.has(rel)) {
            violations.push({
                type: 'UNAPPROVED_FILE',
                file: rel,
                detail: `File '${rel}' is not in approved manifest [${Array.from(approvedSet).join(', ')}].`
            });
        }
    }

    if (SUPPRESSION_PATTERNS.some(rx => rx.test(fullRemediatedCode || ''))) {
        violations.push({ type: 'SUPPRESSION_DIRECTIVE', detail: 'Diagnostic suppression directive detected in remediated code.' });
    }

    const diffFindings = inspectDiffForPolicyAndTestWeakening(patchDiff, filesToCheck);
    for (const df of diffFindings) {
        violations.push(df);
    }

    if (violations.length > 0) {
        throw new ScopeViolationError(violations.map(v => v.detail).join(' | '), violations);
    }

    return { allowed: true, checkedFiles: filesToCheck };
}

/**
 * Captures pre-remediation filesystem + Git state inside worktreeDir.
 */
function captureWorkspaceSnapshot(worktreeDir) {
    const fileHashes = new Map();
    const symlinks = new Set();

    const walk = (dir) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.name === '.git' || entry.name === 'bin' || entry.name === 'obj' || entry.name === 'node_modules' || entry.name === 'TestResults') continue;
            const full = path.join(dir, entry.name);
            const rel = normalizeRelPath(path.relative(worktreeDir, full));
            if (entry.isSymbolicLink()) {
                symlinks.add(rel);
                continue;
            }
            if (entry.isDirectory()) {
                walk(full);
            } else if (entry.isFile()) {
                const buf = fs.readFileSync(full);
                const sha = crypto.createHash('sha256').update(buf).digest('hex');
                fileHashes.set(rel, sha);
            }
        }
    };
    if (fs.existsSync(worktreeDir)) {
        walk(worktreeDir);
    }

    let gitStatusLines = [];
    if (fs.existsSync(path.join(worktreeDir, '.git'))) {
        try {
            const raw = execFileSync('git', ['status', '--porcelain=v1', '-uall'], {
                cwd: worktreeDir,
                encoding: 'utf8',
                shell: false,
                stdio: ['ignore', 'pipe', 'pipe']
            });
            gitStatusLines = raw.split(/\r?\n/).filter(Boolean);
        } catch {}
    }

    return {
        worktreeDir,
        capturedAt: new Date().toISOString(),
        fileHashes,
        symlinks,
        gitStatusLines
    };
}

/**
 * Post-remediation inspection of actual filesystem & Git state.
 * Never trusts model-reported file lists.
 */
function verifyPostExecutionScope(params = {}) {
    const {
        worktreeDir,
        preSnapshot,
        approvedFilePaths = [],
        allowDependencyManifests = false,
        denylist = []
    } = params;

    const postSnapshot = captureWorkspaceSnapshot(worktreeDir);
    const approvedSet = new Set((approvedFilePaths || []).map(normalizeRelPath).filter(Boolean));
    const violations = [];

    const modified = [];
    const added = [];
    const deleted = [];
    const renamed = [];
    const symlinkChanges = [];

    // 1. Filesystem diff comparison
    for (const [rel, sha] of postSnapshot.fileHashes.entries()) {
        if (!preSnapshot.fileHashes.has(rel)) {
            added.push(rel);
        } else if (preSnapshot.fileHashes.get(rel) !== sha) {
            modified.push(rel);
        }
    }
    for (const rel of preSnapshot.fileHashes.keys()) {
        if (!postSnapshot.fileHashes.has(rel)) {
            deleted.push(rel);
        }
    }
    for (const sym of postSnapshot.symlinks) {
        if (!preSnapshot.symlinks.has(sym)) {
            symlinkChanges.push(sym);
        }
    }

    // 2. Git porcelain status inspection (catches renames, mode 120000 symlinks, etc.)
    let actualGitDiff = '';
    if (fs.existsSync(path.join(worktreeDir, '.git'))) {
        try {
            const porcelain = execFileSync('git', ['status', '--porcelain=v1', '-uall'], {
                cwd: worktreeDir,
                encoding: 'utf8',
                shell: false
            });
            for (const line of porcelain.split(/\r?\n/).filter(Boolean)) {
                const statusCode = line.slice(0, 2);
                const payload = line.slice(3).trim();
                if (statusCode.includes('R') && payload.includes(' -> ')) {
                    const [fromP, toP] = payload.split(' -> ').map(normalizeRelPath);
                    renamed.push({ from: fromP, to: toP });
                }
            }
            actualGitDiff = execFileSync('git', ['diff', '--no-ext-diff', 'HEAD'], {
                cwd: worktreeDir,
                encoding: 'utf8',
                shell: false
            });
            // Also check git diff for symlink mode 120000
            if (/^new file mode 120000/m.test(actualGitDiff)) {
                violations.push({ type: 'GIT_SYMLINK_CREATED', detail: 'Git diff created a symbolic link (mode 120000).' });
            }
        } catch {}
    }

    if (symlinkChanges.length > 0) {
        violations.push({ type: 'SYMLINK_CREATED', detail: `Symlink(s) created in workspace: ${symlinkChanges.join(', ')}` });
    }
    if (deleted.length > 0) {
        violations.push({ type: 'UNAUTHORIZED_DELETE', detail: `Unexpected file deletion(s): ${deleted.join(', ')}` });
    }
    if (renamed.length > 0) {
        violations.push({ type: 'UNAUTHORIZED_RENAME', detail: `Unexpected file rename(s): ${renamed.map(r => `${r.from}->${r.to}`).join(', ')}` });
    }

    const allTouched = Array.from(new Set([...modified, ...added, ...deleted, ...renamed.flatMap(r => [r.from, r.to])]));
    for (const rel of allTouched) {
        const ownership = classifyFileOwnership(rel, { allowDependencyManifests, denylist });
        if (ownership.isProtectedPolicyPath) {
            violations.push({ type: 'PROTECTED_POLICY_MODIFIED', file: rel, detail: `Protected policy path modified: ${rel}` });
        } else if (!ownership.editable) {
            violations.push({ type: `OWNERSHIP_VIOLATION_${ownership.tier}`, file: rel, detail: ownership.reason });
        }

        if (approvedSet.size > 0 && !approvedSet.has(rel)) {
            violations.push({
                type: 'UNAPPROVED_FILE_MODIFIED',
                file: rel,
                detail: `Actual filesystem edit to '${rel}' is outside approved files [${Array.from(approvedSet).join(', ')}].`
            });
        }

        // Check actual file content for suppressions or test weakening
        const abs = path.join(worktreeDir, rel);
        if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
            const content = fs.readFileSync(abs, 'utf8');
            if (SUPPRESSION_PATTERNS.some(rx => rx.test(content)) && !isProtectedPolicyPath(rel)) {
                // Only flag if added in git diff (or newly introduced)
                if (!actualGitDiff || inspectDiffForPolicyAndTestWeakening(actualGitDiff, [rel]).some(d => d.type === 'SUPPRESSION_DIRECTIVE')) {
                    violations.push({ type: 'SUPPRESSION_ADDED', file: rel, detail: `Suppression directive introduced in '${rel}'.` });
                }
            }
        }
    }

    if (actualGitDiff) {
        const diffPolicyViolations = inspectDiffForPolicyAndTestWeakening(actualGitDiff, allTouched);
        for (const v of diffPolicyViolations) {
            violations.push(v);
        }
    }

    if (violations.length > 0) {
        throw new ScopeViolationError(violations.map(v => v.detail).join(' | '), violations);
    }

    return {
        allowed: true,
        status: 'SCOPE_VERIFIED',
        modified,
        added,
        deleted,
        renamed,
        symlinkChanges,
        filesChanged: allTouched,
        actualGitDiff,
        testWeakeningLimitations: TEST_WEAKENING_DETECTION_LIMITATIONS
    };
}

module.exports = {
    OWNERSHIP_TIER,
    TEST_WEAKENING_DETECTION_LIMITATIONS,
    ScopeViolationError,
    normalizeRelPath,
    isProtectedPolicyPath,
    isDependencyManifestPath,
    isTestFilePath,
    classifyFileOwnership,
    inspectDiffForPolicyAndTestWeakening,
    assertNoSymlinkEscape,
    validateProposedChangesScope,
    captureWorkspaceSnapshot,
    verifyPostExecutionScope
};
