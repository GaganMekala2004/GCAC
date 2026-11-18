'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { ScannerAdapter } = require('../scannerAdapter');
const { NormalizedFinding, SCANNER_STATUS } = require('../findingModel');
const { requestJson } = require('../../providers/transport');

class OsvScanner extends ScannerAdapter {
    constructor(send = requestJson) {
        super({
            id: 'osv',
            name: 'OSV public npm dependency intelligence',
            version: '1',
            supportedLanguages: ['npm'],
            supportedCategories: ['Dependency advisory']
        });
        this.send = send;
        this.optIn = true;
    }
    async isAvailable() {
        return { available: true, reason: 'Requires an approved package list for each scan' };
    }
    async scan(workspace, target, options) {
        const start = Date.now();
        const result = {
            scannerId: this.id,
            status: SCANNER_STATUS.PARTIAL,
            findings: [],
            errors: [],
            warnings: [],
            coverage: 'Root package-lock.json public npm dependencies only'
        };
        try {
            const lock = path.join(target, 'package-lock.json');
            const read = () => {
                const fd = fs.openSync(lock, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
                try {
                    const stat = fs.fstatSync(fd);
                    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw Error('Unsupported lockfile');
                    return fs.readFileSync(fd, 'utf8');
                } finally {
                    fs.closeSync(fd);
                }
            };
            const snapshot = read();
            const packages = JSON.parse(snapshot).packages;
            if (!packages || Array.isArray(packages) || typeof packages !== 'object')
                throw Error('Requires npm lockfile version 2 or 3');
            const queries = new Map();
            for (const [location, pkg] of Object.entries(packages)) {
                if (!location) continue;
                const name = pkg.name || location.split('node_modules/').pop();
                if (
                    !pkg.resolved?.startsWith('https://registry.npmjs.org/') ||
                    !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) ||
                    !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(pkg.version)
                ) {
                    result.warnings.push('Skipped a non-public or unresolved dependency');
                    continue;
                }
                queries.set(name + '@' + pkg.version, {
                    package: { ecosystem: 'npm', name },
                    version: pkg.version
                });
            }
            if (queries.size > 100 || !queries.size)
                throw Error('Requires 1–100 verified public dependency versions');
            if (!(await options.approvePackages?.([...queries.keys()])))
                throw Error('Package disclosure was not approved');
            for (const query of queries.values()) {
                options.abortSignal?.throwIfAborted();
                const data = await this.send(new URL('https://api.osv.dev/v1/query'), {
                    body: query,
                    timeout: 15000,
                    signal: options.abortSignal
                });
                if (
                    !data ||
                    typeof data !== 'object' ||
                    Array.isArray(data) ||
                    Object.keys(data).some((k) => !['vulns', 'next_page_token'].includes(k)) ||
                    (data.vulns !== undefined && !Array.isArray(data.vulns))
                )
                    throw Error('Invalid OSV response');
                if (data.next_page_token)
                    result.warnings.push('OSV returned additional pages. Advisory coverage is incomplete.');
                for (const advisory of data.vulns || []) {
                    if (!/^[A-Za-z0-9_-]{1,100}$/.test(advisory.id || ''))
                        throw Error('Invalid OSV advisory identity');
                    result.findings.push(
                        new NormalizedFinding({
                            ...options.repoContext,
                            scannerId: this.id,
                            scanId: options.scanId,
                            ruleId: advisory.id,
                            filePath: 'package-lock.json',
                            title: advisory.id + ' affects ' + query.package.name,
                            evidence: query.package.name + '@' + query.version + ' matched ' + advisory.id,
                            packageName: query.package.name,
                            currentVersion: query.version,
                            sourceClassification: 'ExternalAdvisory',
                            detectionMethod: 'OSV_PACKAGE_VERSION',
                            severity: 'Unknown',
                            originalSeverity: advisory.severity || [],
                            advisoryUrl: 'https://osv.dev/vulnerability/' + advisory.id
                        })
                    );
                }
            }
            if (snapshot !== read()) {
                result.findings = [];
                throw Error('Lockfile changed during scan');
            }
            result.status = result.warnings.length ? SCANNER_STATUS.PARTIAL : SCANNER_STATUS.COMPLETED;
        } catch (error) {
            result.findings = [];
            result.errors.push(error.message);
            result.status = options.abortSignal?.aborted
                ? SCANNER_STATUS.CANCELLED
                : SCANNER_STATUS.UNAVAILABLE;
        }
        return { ...result, durationMs: Date.now() - start };
    }
}
module.exports = { OsvScanner };
