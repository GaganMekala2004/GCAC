'use strict';

const fs = require('fs');
const { isSeparateRepositoryDirectory } = require('../repositoryContext');
const path = require('path');
const crypto = require('crypto');
const { SCANNER_STATUS } = require('./findingModel');

const DEFAULT_IGNORED_DIRS = new Set([
    '.git',
    'node_modules',
    'bin',
    'obj',
    'packages',
    'dist',
    'build',
    'coverage',
    'TestResults',
    '.vs',
    '.vscode-test',
    'workspaces',
    'remediation-output'
]);

const DEFAULT_MAX_ENTRIES = 64;
const DEFAULT_ADVISORY_TTL_MS = 60 * 60 * 1000; // 1 hour freshness window for SCA advisories
const DEFAULT_STATIC_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours max safety TTL (still content-hash bound)

function stableHashObject(obj) {
    const normalize = (val) => {
        if (val === null || val === undefined) return null;
        if (Array.isArray(val)) return val.map(normalize);
        if (typeof val === 'object') {
            const out = {};
            for (const key of Object.keys(val).sort()) {
                out[key] = normalize(val[key]);
            }
            return out;
        }
        return val;
    };
    return crypto.createHash('sha256').update(JSON.stringify(normalize(obj))).digest('hex');
}

async function computeFileSha256(filePath, maxBytes = 2 * 1024 * 1024) {
    const stat = await fs.promises.stat(filePath);
    if (stat.size > maxBytes) {
        return { hash: `OVERSIZED:${stat.size}`, size: stat.size, oversized: true };
    }
    const buf = await fs.promises.readFile(filePath);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    return { hash, size: stat.size, oversized: false };
}

/**
 * Traverses a target directory or single file and builds a deterministic SHA-256
 * digest over all eligible source/config/manifest files while tracking repository
 * and eligible file counts. Symlinks are never followed across directory trees.
 */
async function computeInputFingerprint(targetPath, options = {}) {
    const maxFileBytes = options.maxFileBytes || (2 * 1024 * 1024);
    const ignoredDirs = options.ignoredDirs || DEFAULT_IGNORED_DIRS;
    const files = [];
    let repositoryFileCount = 0;

    if (!targetPath || !fs.existsSync(targetPath)) {
        return {
            inputHash: crypto.createHash('sha256').update('EMPTY_TARGET').digest('hex'),
            repositoryFileCount: 0,
            eligibleFileCount: 0,
            files: []
        };
    }

    const rootStat = await fs.promises.lstat(targetPath);
    if (rootStat.isSymbolicLink()) {
        return {
            inputHash: crypto.createHash('sha256').update('SYMLINK_REJECTED').digest('hex'),
            repositoryFileCount: 0,
            eligibleFileCount: 0,
            files: []
        };
    }

    if (rootStat.isFile()) {
        repositoryFileCount = 1;
        files.push({ fullPath: targetPath, relPath: path.basename(targetPath) });
    } else if (rootStat.isDirectory()) {
        const stack = [targetPath];
        while (stack.length > 0) {
            if (options.abortSignal && options.abortSignal.aborted) {
                throw new Error('Scan cancelled during discovery.');
            }
            const dir = stack.pop();
            let entries = [];
            try {
                entries = await fs.promises.readdir(dir, { withFileTypes: true });
            } catch {
                continue;
            }
            for (const entry of entries) {
                if (entry.isSymbolicLink()) continue;
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    if (ignoredDirs.has(entry.name) || entry.name.startsWith('.git') || isSeparateRepositoryDirectory(full)) {
                        continue;
                    }
                    stack.push(full);
                } else if (entry.isFile()) {
                    repositoryFileCount++;
                    const rel = path.relative(targetPath, full).replace(/\\/g, '/');
                    files.push({ fullPath: full, relPath: rel });
                }
            }
        }
    }

    files.sort((a, b) => a.relPath.localeCompare(b.relPath));

    const hashRecords = new Array(files.length);
    const concurrency = Math.max(1, Math.min(16, options.concurrency || 16));
    let cursor = 0;

    async function worker() {
        while (cursor < files.length) {
            if (options.abortSignal && options.abortSignal.aborted) {
                throw new Error('Scan cancelled during input hashing.');
            }
            const idx = cursor++;
            const item = files[idx];
            try {
                const { hash, size } = await computeFileSha256(item.fullPath, maxFileBytes);
                hashRecords[idx] = `${item.relPath}|${size}|${hash}`;
            } catch {
                hashRecords[idx] = `${item.relPath}|ERR`;
            }
        }
    }

    const workers = [];
    const workerCount = Math.min(concurrency, Math.max(1, files.length));
    for (let i = 0; i < workerCount; i++) {
        workers.push(worker());
    }
    await Promise.all(workers);

    const inputHash = crypto.createHash('sha256')
        .update(hashRecords.join('\n'))
        .digest('hex');

    return {
        inputHash,
        repositoryFileCount,
        eligibleFileCount: files.length,
        files
    };
}

/**
 * Deterministic, repository-bound incremental scan cache.
 * Never shares results across repositories, toolchain contexts, rulesets, or stale advisories.
 */
class ScanCache {
    constructor(storageDir = null, options = {}) {
        this.storageDir = storageDir;
        this.cacheFile = storageDir ? path.join(storageDir, 'scan-cache.json') : null;
        this.maxEntries = options.maxEntries || DEFAULT_MAX_ENTRIES;
        this.advisoryTtlMs = options.advisoryTtlMs !== undefined ? options.advisoryTtlMs : DEFAULT_ADVISORY_TTL_MS;
        this.staticTtlMs = options.staticTtlMs !== undefined ? options.staticTtlMs : DEFAULT_STATIC_TTL_MS;
        this.entries = new Map();
        this._loaded = false;
        this._loadFromDisk();
    }

    _loadFromDisk() {
        if (this._loaded) return;
        this._loaded = true;
        if (!this.cacheFile || !fs.existsSync(this.cacheFile)) return;
        try {
            const raw = fs.readFileSync(this.cacheFile, 'utf8');
            const parsed = JSON.parse(raw);
            if (parsed && Array.isArray(parsed.entries)) {
                for (const entry of parsed.entries) {
                    if (entry && entry.cacheKey) {
                        this.entries.set(entry.cacheKey, entry);
                    }
                }
            }
        } catch {
            // Corrupt cache is safely ignored (cache miss)
            this.entries.clear();
        }
    }

    _persistToDisk() {
        if (!this.cacheFile) return;
        try {
            if (!fs.existsSync(this.storageDir)) {
                fs.mkdirSync(this.storageDir, { recursive: true });
            }
            const payload = {
                schemaVersion: 'GCAC-SCAN-CACHE-1.0',
                updatedAt: new Date().toISOString(),
                entries: Array.from(this.entries.values())
            };
            fs.writeFileSync(this.cacheFile, JSON.stringify(payload, null, 2), 'utf8');
        } catch {
            // Cache persistence failure is non-fatal
        }
    }

    buildCacheKey(descriptor = {}) {
        if (!descriptor.canonicalRepositoryId || !descriptor.scannerId || !descriptor.inputHash) {
            return null;
        }
        return stableHashObject({
            canonicalRepositoryId: String(descriptor.canonicalRepositoryId),
            targetRelativePath: String(descriptor.targetRelativePath || ''),
            inputHash: String(descriptor.inputHash),
            scannerId: String(descriptor.scannerId),
            scannerVersion: String(descriptor.scannerVersion || 'unknown'),
            ruleConfigHash: String(descriptor.ruleConfigHash || 'default'),
            toolchainHash: String(descriptor.toolchainHash || 'default')
        });
    }

    get(descriptor, options = {}) {
        if (!descriptor || !descriptor.canonicalRepositoryId) {
            return { hit: false, reason: 'MISSING_REPOSITORY_IDENTITY' };
        }
        const cacheKey = this.buildCacheKey(descriptor);
        if (!cacheKey) {
            return { hit: false, reason: 'INCOMPLETE_CACHE_KEY' };
        }

        const record = this.entries.get(cacheKey);
        if (!record) {
            return { hit: false, reason: 'CACHE_MISS', cacheKey };
        }

        // Strict repository isolation guard
        if (record.canonicalRepositoryId !== descriptor.canonicalRepositoryId) {
            return { hit: false, reason: 'REPOSITORY_MISMATCH', cacheKey };
        }

        const nowMs = options.nowMs !== undefined ? options.nowMs : Date.now();
        const ageMs = Math.max(0, nowMs - new Date(record.cachedAt).getTime());
        const isAdvisory = descriptor.isAdvisoryDependent === true || descriptor.scannerId === 'nuget-audit';
        const effectiveTtl = isAdvisory
            ? (options.advisoryTtlMs !== undefined ? options.advisoryTtlMs : this.advisoryTtlMs)
            : (options.staticTtlMs !== undefined ? options.staticTtlMs : this.staticTtlMs);

        if (effectiveTtl <= 0 || ageMs > effectiveTtl) {
            this.entries.delete(cacheKey);
            this._persistToDisk();
            return {
                hit: false,
                reason: isAdvisory ? 'ADVISORY_DATA_EXPIRED' : 'CACHE_TTL_EXPIRED',
                ageMs,
                cacheKey
            };
        }

        // Move to MRU position
        this.entries.delete(cacheKey);
        this.entries.set(cacheKey, record);

        const clonedResult = JSON.parse(JSON.stringify(record.result));
        if (Array.isArray(clonedResult.findings)) {
            const scanId = options.scanId || clonedResult.scanId;
            for (const f of clonedResult.findings) {
                if (scanId) f.scanId = scanId;
                f.fromCache = true;
                f.cachedAt = record.cachedAt;
            }
        }
        clonedResult.fromCache = true;
        clonedResult.cachedAt = record.cachedAt;
        clonedResult.cacheAgeMs = ageMs;
        clonedResult.freshnessStatus = isAdvisory ? 'CACHED_ADVISORY_WITHIN_TTL' : 'CACHED_SOURCE_HASH_VERIFIED';
        clonedResult.cacheKeyHash = cacheKey.slice(0, 16);

        return {
            hit: true,
            cacheKey,
            cachedAt: record.cachedAt,
            ageMs,
            freshnessStatus: clonedResult.freshnessStatus,
            result: clonedResult
        };
    }

    set(descriptor, scanResult) {
        if (!scanResult || !descriptor || !descriptor.canonicalRepositoryId) return false;
        if (
            scanResult.status !== SCANNER_STATUS.COMPLETED &&
            scanResult.status !== SCANNER_STATUS.NO_SCANNABLE_INPUTS
        ) {
            return false;
        }
        if (scanResult.cancelled || scanResult.timedOut) {
            return false;
        }
        const cacheKey = this.buildCacheKey(descriptor);
        if (!cacheKey) return false;

        const safeSnapshot = JSON.parse(JSON.stringify(scanResult));
        delete safeSnapshot.metrics; // Caller records live cache-lookup timing separately

        const cachedAt = new Date().toISOString();
        if (this.entries.has(cacheKey)) {
            this.entries.delete(cacheKey);
        }
        this.entries.set(cacheKey, {
            cacheKey,
            canonicalRepositoryId: descriptor.canonicalRepositoryId,
            scannerId: descriptor.scannerId,
            scannerVersion: descriptor.scannerVersion || 'unknown',
            inputHash: descriptor.inputHash,
            ruleConfigHash: descriptor.ruleConfigHash || 'default',
            toolchainHash: descriptor.toolchainHash || 'default',
            cachedAt,
            result: safeSnapshot
        });

        while (this.entries.size > this.maxEntries) {
            const oldestKey = this.entries.keys().next().value;
            this.entries.delete(oldestKey);
        }

        this._persistToDisk();
        return true;
    }

    clear(canonicalRepositoryId = null) {
        if (!canonicalRepositoryId) {
            this.entries.clear();
        } else {
            for (const [key, entry] of this.entries.entries()) {
                if (entry.canonicalRepositoryId === canonicalRepositoryId) {
                    this.entries.delete(key);
                }
            }
        }
        this._persistToDisk();
    }
}

module.exports = {
    ScanCache,
    computeInputFingerprint,
    stableHashObject,
    DEFAULT_IGNORED_DIRS,
    DEFAULT_ADVISORY_TTL_MS,
    DEFAULT_STATIC_TTL_MS
};

