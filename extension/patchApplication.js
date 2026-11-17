'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const { extractDiffFilePaths } = require('./approvalGovernance');
function applyExactPatch(worktreeDir, patchDiff, checkOnly = false) {
    if (!fs.existsSync(worktreeDir) || !/^@@ /m.test(patchDiff || '') || extractDiffFilePaths(patchDiff).length === 0) {
        const error = new Error('PATCH_INVALID: A real unified patch and isolated worktree are required.');
        error.failureCategory = 'PATCH_INVALID';
        error.patchDiagnostic = { reasonCode: 'MISSING_UNIFIED_DIFF' };
        throw error;
    }
    try {
        execFileSync('git', ['-c', 'core.hooksPath=/dev/null', 'apply', ...(checkOnly ? ['--check'] : []), '--unidiff-zero', '--whitespace=nowarn', '-'], {
            cwd: worktreeDir, input: patchDiff.replace(/\n?$/, '\n'), shell: false, timeout: 15000,
            encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
            env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' }
        });
    } catch (err) {
        // Git stderr may quote raw source. Keep values out of diagnostics/model feedback.
        const stderr = String(err.stderr || '');
        const reasonCode = /corrupt patch|patch fragment|invalid patch|garbage/i.test(stderr)
            ? 'MALFORMED_DIFF' : /No such file|does not exist/i.test(stderr)
                ? 'TARGET_MISSING' : /patch failed|does not apply/i.test(stderr)
                    ? 'SOURCE_MISMATCH' : 'GIT_APPLY_FAILED';
        const failure = new Error(`PATCH_DOES_NOT_APPLY (${reasonCode}): Regenerate the unified diff against the exact isolated source, preserving context lines and accurate hunk counts.`);
        failure.failureCategory = 'PATCH_INVALID';
        failure.patchDiagnostic = { reasonCode, exitCode: err.status ?? null };
        throw failure;
    }
}
function extractProposedPatch(response) {
    const fenced = String(response).match(/```(?:diff|patch)\s*\n([\s\S]*?)```/i);
    if (fenced) return fenced[1].replace(/\r\n/g, '\n').replace(/\n?$/, '\n');
    const lines = String(response).replace(/\r\n/g, '\n').split('\n');
    const start = lines.findIndex(line => /^(diff --git |--- a\/)/.test(line));
    if (start < 0) return '';
    const end = lines.findIndex((line, i) => i > start && /^(SUMMARY:|```)/.test(line));
    // Never filter individual lines: blank context, file headers, and no-newline
    // markers are significant unified-diff syntax.
    return lines.slice(start, end < 0 ? undefined : end).join('\n').replace(/\n?$/, '\n');
}
function canonicalizeProposedPatch(worktreeDir, proposedPatch, targetRelPath) {
    try { applyExactPatch(worktreeDir, proposedPatch, true); if (!/\.cs$/i.test(targetRelPath)) return proposedPatch; }
    catch (error) {
        if (!['MALFORMED_DIFF', 'SOURCE_MISMATCH'].includes(error.patchDiagnostic?.reasonCode)) throw error;
    }
    const invalid = reason => {
        const error = new Error(`PATCH_DOES_NOT_APPLY (EXACT_EDIT_RECONSTRUCTION_FAILED): ${reason}`);
        error.failureCategory = 'PATCH_INVALID';
        error.patchDiagnostic = { reasonCode: 'EXACT_EDIT_RECONSTRUCTION_FAILED' };
        return error;
    };
    if (!targetRelPath || /[\r\n\0]/.test(targetRelPath) || path.isAbsolute(targetRelPath) || targetRelPath.split(/[\\/]/).includes('..')) {
        throw invalid('Invalid target path.');
    }
    const root = fs.realpathSync(worktreeDir);
    const target = fs.realpathSync(path.join(root, targetRelPath));
    if (!target.startsWith(root + path.sep) || !fs.statSync(target).isFile()) throw invalid('Target is outside the isolated source.');
    const lines = proposedPatch.replace(/\r\n/g, '\n').split('\n');
    const oldHeaders = lines.filter(line => line.startsWith('--- '));
    const newHeaders = lines.filter(line => line.startsWith('+++ '));
    if (oldHeaders.length !== 1 || newHeaders.length !== 1 || oldHeaders[0] !== `--- a/${targetRelPath}` || newHeaders[0] !== `+++ b/${targetRelPath}`) {
        throw invalid('Reconstruction requires exactly one unchanged target path.');
    }
    const source = fs.readFileSync(target, 'utf8');
    if (source.includes('\0') || source.includes('\uFFFD')) throw invalid('Only UTF-8 text edits can be reconstructed.');
    const eol = source.includes('\r\n') ? '\r\n' : '\n';
    const edits = []; let hunk = null;
    for (let i = lines.indexOf(newHeaders[0]) + 1; i < lines.length; i++) {
        const line = lines[i];
        if (/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/.test(line)) {
            hunk = { old: '', next: '', last: null }; edits.push(hunk); continue;
        }
        if (!hunk) { if (line !== '') throw invalid('Unexpected content before hunk.'); continue; }
        if (line === '\\ No newline at end of file') {
            if (!hunk.last) throw invalid('Invalid no-newline marker.');
            if (hunk.last !== '+') hunk.old = hunk.old.slice(0, -eol.length);
            if (hunk.last !== '-') hunk.next = hunk.next.slice(0, -eol.length);
            hunk.last = null; continue;
        }
        if (line === '' && i === lines.length - 1) continue;
        if (!/^[ +\-]/.test(line)) throw invalid('Unexpected content inside hunk.');
        const prefix = line[0], value = line.slice(1) + eol;
        if (prefix !== '+') hunk.old += value;
        if (prefix !== '-') hunk.next += value;
        hunk.last = prefix;
    }
    if (!edits.length) throw invalid('No edit hunks found.');
    let cursor = 0, updated = '';
    for (const edit of edits) {
        if (!edit.old) throw invalid('An insertion needs exact source context.');
        // Models often omit Git's EOF marker. Preserve the source's existing
        // missing final newline only when the entire old text matches its suffix.
        if (!source.endsWith(eol) && source.indexOf(edit.old) < 0 && edit.old.endsWith(eol) &&
            source.endsWith(edit.old.slice(0, -eol.length))) {
            edit.old = edit.old.slice(0, -eol.length);
            if (edit.next.endsWith(eol)) edit.next = edit.next.slice(0, -eol.length);
        }
        const offset = source.indexOf(edit.old);
        if (offset < cursor || source.indexOf(edit.old, offset + 1) !== -1) {
            throw invalid('Old hunk text is absent, ambiguous, overlapping, or out of order.');
        }
        updated += source.slice(cursor, offset) + edit.next;
        cursor = offset + edit.old.length;
    }
    updated += source.slice(cursor);
    if (updated === source) throw invalid('Proposal makes no change.');
    return diffForContents(worktreeDir, targetRelPath, source, updated);
}
function diffForContents(worktreeDir, targetRelPath, source, updated) {
    if (/\.cs$/i.test(targetRelPath)) {
        const duplicateLocals = text => {
            // A focused syntax guard, not a substitute for compiler validation.
            const clean = text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' ');
            const stack = [new Set()], duplicates = new Set();
            const tokens = /[{}]|\b(?:using\s+)?var\s+([A-Za-z_]\w*)\s*=/g;
            for (const match of clean.matchAll(tokens)) {
                if (match[0] === '{') stack.push(new Set());
                else if (match[0] === '}') { if (stack.length > 1) stack.pop(); }
                else {
                    // Loop/using-statement declarations have their own implicit
                    // scope; this guard only diagnoses ordinary block locals.
                    if (/\b(?:for|foreach|using)\s*\(\s*$/.test(clean.slice(0, match.index))) continue;
                    const scope = stack[stack.length - 1];
                    if (scope.has(match[1])) duplicates.add(match[1]);
                    scope.add(match[1]);
                }
            }
            return duplicates;
        };
        const before = duplicateLocals(source);
        if ([...duplicateLocals(updated)].some(name => !before.has(name))) {
            const error = new Error('PATCH_INVALID (DUPLICATE_LOCAL_DECLARATION): Proposal introduces a repeated local declaration. Reuse the existing variable; do not declare it twice.');
            error.failureCategory = 'PATCH_INVALID';
            error.patchDiagnostic = { reasonCode: 'DUPLICATE_LOCAL_DECLARATION' };
            throw error;
        }
    }
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-canonical-diff-'));
    try {
        fs.writeFileSync(path.join(temp, 'before'), source, { mode: 0o600 });
        fs.writeFileSync(path.join(temp, 'after'), updated, { mode: 0o600 });
        let diff;
        try {
            diff = execFileSync('git', ['-c', 'core.hooksPath=/dev/null', 'diff', '--no-index', '--no-ext-diff', '--no-textconv', '--no-color', '--', 'before', 'after'], {
                cwd: temp, encoding: 'utf8', shell: false, timeout: 15000,
                stdio: ['ignore', 'pipe', 'pipe'],
                env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' }
            });
        } catch (error) { if (error.status !== 1 || !error.stdout) throw error; diff = error.stdout; }
        diff = diff.replace(/^diff --git .*$/m, () => `diff --git a/${targetRelPath} b/${targetRelPath}`)
            .replace(/^--- a\/before$/m, () => `--- a/${targetRelPath}`).replace(/^\+\+\+ b\/after$/m, () => `+++ b/${targetRelPath}`);
        applyExactPatch(worktreeDir, diff, true);
        return diff;
    } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
function patchFromExactEdits(worktreeDir, response, targetRelPath) {
    const fail = message => {
        const error = new Error(`PATCH_INVALID (EXACT_EDITS): ${message}`);
        error.failureCategory = 'PATCH_INVALID'; error.patchDiagnostic = { reasonCode: 'EXACT_EDITS_INVALID' }; return error;
    };
    let proposal;
    try {
        const fenced = String(response).match(/```json\s*\n([\s\S]*?)```/i);
        proposal = JSON.parse(fenced ? fenced[1] : response);
    } catch { throw fail('Return valid JSON with an edits array.'); }
    if (!proposal || !Array.isArray(proposal.edits) || !proposal.edits.length || proposal.edits.length > 32) throw fail('Expected 1–32 exact edits.');
    const root = fs.realpathSync(worktreeDir);
    if (!targetRelPath || path.isAbsolute(targetRelPath) || /[\r\n\0]/.test(targetRelPath) || targetRelPath.split(/[\\/]/).includes('..')) throw fail('Invalid target path.');
    const target = fs.realpathSync(path.join(root, targetRelPath));
    if (!target.startsWith(root + path.sep) || !fs.statSync(target).isFile()) throw fail('Target must be inside the isolated source.');
    const source = fs.readFileSync(target, 'utf8');
    const edits = proposal.edits.map(edit => {
        if (!edit || typeof edit.oldText !== 'string' || !edit.oldText || typeof edit.newText !== 'string' ||
            Object.keys(edit).some(key => !['oldText', 'newText'].includes(key))) throw fail('Each edit requires only oldText and newText strings.');
        const offset = source.indexOf(edit.oldText);
        if (offset < 0) throw fail('oldText is absent. Copy the original lines exactly, including every unchanged line inside the replacement.');
        if (source.indexOf(edit.oldText, offset + 1) !== -1) throw fail('oldText is ambiguous. Include more exact surrounding context.');
        return { ...edit, offset };
    }).sort((a, b) => a.offset - b.offset);
    let cursor = 0, updated = '';
    for (const edit of edits) {
        if (edit.offset < cursor) throw fail('Edits overlap.');
        updated += source.slice(cursor, edit.offset) + edit.newText;
        cursor = edit.offset + edit.oldText.length;
    }
    updated += source.slice(cursor);
    if (updated === source) throw fail('The edits make no change.');
    return diffForContents(worktreeDir, targetRelPath, source, updated);
}
module.exports = { applyExactPatch, extractProposedPatch, canonicalizeProposedPatch, patchFromExactEdits };
