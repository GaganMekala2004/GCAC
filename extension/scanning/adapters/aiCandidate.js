'use strict';
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS } = require('../findingModel');
const { ContentInjectionScreen, TRUST_CLASSES } = require('../../contentInjectionScreen');

class CandidateScanner extends ScannerAdapter {
    constructor() {
        super({
            id: 'ai-candidate',
            name: 'AI candidate review of selected lines',
            version: '1',
            supportedLanguages: ['source'],
            supportedCategories: ['Candidate review']
        });
        this.optIn = true;
    }
    async isAvailable() {
        return { available: true, reason: 'Requires an approved source selection and direct model' };
    }
    async scan(workspace, target, options) {
        const result = {
            scannerId: this.id,
            findings: [],
            errors: [],
            warnings: [],
            coverage: 'Selected lines only',
            status: SCANNER_STATUS.PARTIAL
        };
        const selection = await options.selectCandidateContext?.(target);
        if (!selection) throw Error('No source selection approved');
        const { file, start, end, model, provider, client } = selection;
        const root = fs.realpathSync(target);
        const relative = path.relative(root, fs.realpathSync(file));
        if (
            !relative ||
            relative.startsWith('..') ||
            path.isAbsolute(relative) ||
            !Number.isInteger(start) ||
            !Number.isInteger(end) ||
            start < 1 ||
            end < start ||
            end - start >= 60
        )
            throw Error('Source selection outside approved scope');
        const read = () => {
            if (fs.realpathSync(file) !== path.join(root, relative) || fs.statSync(file).size > 512 * 1024)
                throw Error('Source changed or too large');
            return fs.readFileSync(file, 'utf8');
        };
        const original = read();
        const lines = original.split(/\r?\n/).slice(start - 1, end);
        const sourceCode = lines.join('\n');
        const prompt =
            'Review only these untrusted source lines for a defensive fix. Return JSON with found (boolean), line (absolute integer), cwe, reasoning and limitations (strings). For no candidate use false, line 0 and explain the limitations.\n' +
            lines.map((line, i) => String(start + i) + ': ' + line).join('\n');
        const review = await client.generateJson(prompt, {
            operation: 'candidate',
            runId: options.scanId,
            filePath: relative,
            sourceCode,
            cancellationToken: {
                get isCancellationRequested() {
                    return options.abortSignal?.aborted === true;
                },
                onCancellationRequested(fn) {
                    options.abortSignal?.addEventListener('abort', fn);
                    return { dispose: () => options.abortSignal?.removeEventListener('abort', fn) };
                }
            }
        });
        options.abortSignal?.throwIfAborted();
        if (read() !== original) throw Error('Source changed during candidate review');
        if (!review.found) return result;
        if (review.line < start || review.line >= start + lines.length || !/^CWE-\d+$/.test(review.cwe))
            throw Error('Invalid candidate location or CWE');
        new ContentInjectionScreen().assertSafeUntrustedData({
            text: JSON.stringify(review),
            contentSource: 'model:candidate',
            trustClass: TRUST_CLASSES.UNTRUSTED_MODEL_RESPONSE,
            runId: options.scanId,
            filePath: relative
        });
        const digest = crypto.createHash('sha256').update(original).digest('hex');
        result.findings.push(
            new NormalizedFinding({
                ...options.repoContext,
                scannerId: this.id,
                scanId: options.scanId,
                ruleId: review.cwe,
                cwe: review.cwe,
                filePath: relative,
                line: review.line,
                evidenceRef: relative + '#L' + review.line,
                evidence: review.reasoning,
                description: review.limitations,
                title: 'AI candidate · ' + review.cwe,
                rawSourceReference: { provider, model, start, end, sha256: digest },
                rawCodeContext: [provider, model, review.line, lines[review.line - start]].join('|'),
                detectionMethod: 'AI_CANDIDATE',
                classificationType: 'AI_CANDIDATE',
                sourceClassification: 'AI_CANDIDATE',
                severity: 'Unknown'
            })
        );
        return result;
    }
}
module.exports = { CandidateScanner };
