'use strict';
// Data-only provisioning. No repository content is uploaded and no build is run.
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const zlib = require('zlib');
const SOURCE = 'https://api.nuget.org/v3/index.json';
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
function snapshotPath(root) { return path.join(root, 'output', 'scans', 'nuget-advisories.json'); }
function getJson(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'api.nuget.org' || parsed.username || parsed.password || parsed.port) {
        throw new Error('Advisory download destination is not the official NuGet HTTPS endpoint.');
    }
    return new Promise((resolve, reject) => {
        const request = https.get(parsed, { timeout: 30000 }, response => {
            if (response.statusCode !== 200) { response.resume(); reject(new Error(`NuGet advisory HTTP ${response.statusCode}`)); return; }
            let size = 0; const chunks = [];
            response.on('data', chunk => {
                size += chunk.length;
                if (size > 32 * 1024 * 1024) response.destroy(new Error('Advisory response exceeds size limit.'));
                else chunks.push(chunk);
            });
            response.on('error', reject);
            response.on('end', () => {
                try {
                    let body = Buffer.concat(chunks);
                    if (response.headers['content-encoding'] === 'gzip' || (body[0] === 0x1f && body[1] === 0x8b)) {
                        body = zlib.gunzipSync(body, { maxOutputLength: 32 * 1024 * 1024 });
                    }
                    resolve(JSON.parse(body.toString('utf8')));
                } catch (error) { reject(error); }
            });
        });
        request.on('timeout', () => request.destroy(new Error('NuGet advisory request timed out.')));
        request.on('error', reject);
    });
}
function validatePackages(packages) {
    if (!packages || Array.isArray(packages) || typeof packages !== 'object') throw new Error('Invalid advisory dictionary.');
    for (const [id, entries] of Object.entries(packages)) {
        if (!/^[a-z0-9_.-]+$/.test(id) || !Array.isArray(entries)) throw new Error('Invalid advisory package.');
        for (const entry of entries) {
            if (!Number.isInteger(entry.severity) || entry.severity < 0 || entry.severity > 3 ||
                typeof entry.versions !== 'string' || !/^https:\/\//.test(entry.url || '')) throw new Error('Invalid advisory record.');
        }
    }
}
async function refreshSnapshot(destination, fetchJson = getJson) {
    const service = await fetchJson(SOURCE);
    const resource = service.resources?.find(r => r['@type'] === 'VulnerabilityInfo/6.7.0');
    if (!resource) throw new Error('NuGet service has no VulnerabilityInfo resource.');
    const pages = await fetchJson(resource['@id']);
    if (!Array.isArray(pages) || pages.length < 1 || pages.length > 16) throw new Error('Incomplete vulnerability index.');
    const packages = Object.create(null);
    for (const page of pages) {
        const data = await fetchJson(page['@id']);
        if (Array.isArray(data) && data.length === 0) continue;
        validatePackages(data);
        for (const [id, advisories] of Object.entries(data)) packages[id] = [...(packages[id] || []), ...advisories];
    }
    validatePackages(packages);
    const snapshot = { schemaVersion: 1, source: SOURCE, fetchedAt: new Date().toISOString(), pages, packages };
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const temp = `${destination}.${crypto.randomUUID()}.tmp`;
    try { fs.writeFileSync(temp, JSON.stringify(snapshot)); fs.renameSync(temp, destination); }
    finally { if (fs.existsSync(temp)) fs.unlinkSync(temp); }
    return snapshot;
}
function readSnapshot(file, now = Date.now()) {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const age = now - Date.parse(data.fetchedAt);
    if (data.schemaVersion !== 1 || data.source !== SOURCE || !Array.isArray(data.pages) || !data.pages.length ||
        !Number.isFinite(age) || age < -60000 || age > MAX_AGE_MS) throw new Error('Advisory snapshot is invalid or older than 24 hours.');
    validatePackages(data.packages);
    return data;
}
// NuGet versions allow 1–4 numeric components and SemVer prerelease labels.
// Unsupported syntax fails closed rather than producing a clean audit.
function compareVersions(a, b) {
    const parse = value => {
        const match = String(value).trim().match(/^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
        if (!match) throw new Error('Unsupported NuGet version syntax.');
        return { numbers: match[1].split('.').map(BigInt), pre: match[2]?.toLowerCase().split('.') };
    };
    const x = parse(a), y = parse(b);
    for (let i = 0; i < 4; i++) { const n = x.numbers[i] || 0n, m = y.numbers[i] || 0n; if (n !== m) return n < m ? -1 : 1; }
    if (!x.pre || !y.pre) return x.pre ? -1 : y.pre ? 1 : 0;
    for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
        const n = x.pre[i], m = y.pre[i];
        if (n === m) continue;
        if (n === undefined || m === undefined) return n === undefined ? -1 : 1;
        const numericN = /^\d+$/.test(n), numericM = /^\d+$/.test(m);
        if (numericN && numericM) { if (BigInt(n) !== BigInt(m)) return BigInt(n) < BigInt(m) ? -1 : 1; continue; }
        if (numericN !== numericM) return numericN ? -1 : 1;
        return n < m ? -1 : 1;
    }
    return 0;
}
function inRange(version, range) {
    const text = range.trim();
    const exact = text.match(/^\[([^,]+)\]$/);
    if (exact) return compareVersions(version, exact[1]) === 0;
    const bounds = text.match(/^([[(])\s*([^,]*)\s*,\s*([^,]*)\s*([)\]])$/);
    if (!bounds) throw new Error('Unsupported NuGet advisory range.');
    const [, left, min, max, right] = bounds;
    const low = min.trim() ? compareVersions(version, min.trim()) : 1;
    const high = max.trim() ? compareVersions(version, max.trim()) : -1;
    return (low > 0 || (low === 0 && left === '[')) && (high < 0 || (high === 0 && right === ']'));
}
module.exports = { snapshotPath, refreshSnapshot, readSnapshot, compareVersions, inRange };
