#!/usr/bin/env node
/**
 * CodeQL CLI Setup & Installation Helper
 * ----------------------------------------
 * Downloads the official GitHub CodeQL CLI bundle for Windows (x64) into
 * <workspace>/tools/codeql/ so that the GCAC scanning adapter can find it
 * at a deterministic local path without requiring a system-wide installation.
 *
 * Usage:
 *   node scripts/setup-codeql.js [--version 2.20.1]
 *
 * After running this script the CodeQL binary will be available at:
 *   tools/codeql/codeql.exe  (Windows)
 *   tools/codeql/codeql      (Linux/macOS)
 *
 * The ScanController adapter automatically discovers this local path.
 */

'use strict';

const path = require('path');
const fs   = require('fs');
const os   = require('os');
const { execSync } = require('child_process');
const https = require('https');

// ── Configuration ──────────────────────────────────────────────────────────────
const WORKSPACE_ROOT = path.resolve(__dirname, '..');
const TOOLS_DIR      = path.join(WORKSPACE_ROOT, 'tools');
const CODEQL_DIR     = path.join(TOOLS_DIR, 'codeql');
const CODEQL_BIN     = path.join(CODEQL_DIR, process.platform === 'win32' ? 'codeql.exe' : 'codeql');

// Default to latest stable; override with --version flag
const DEFAULT_VERSION = '2.20.1';
const args = process.argv.slice(2);
const versionArg = args.find(a => a.startsWith('--version'));
const CODEQL_VERSION = versionArg ? versionArg.split('=')[1] || args[args.indexOf(versionArg) + 1] || DEFAULT_VERSION : DEFAULT_VERSION;

// ── Platform-specific bundle URL ───────────────────────────────────────────────
function getBundleUrl(version) {
    const base = `https://github.com/github/codeql-action/releases/download/codeql-bundle-v${version}`;
    const platform = process.platform;
    if (platform === 'win32')   return `${base}/codeql-bundle-win64.tar.gz`;
    if (platform === 'darwin')  return `${base}/codeql-bundle-osx64.tar.gz`;
    return `${base}/codeql-bundle-linux64.tar.gz`;
}

// ── State file ─────────────────────────────────────────────────────────────────
const STATE_FILE = path.join(CODEQL_DIR, '.setup-state.json');

function readState() {
    try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')); } catch { return {}; }
}

function writeState(state) {
    try {
        fs.mkdirSync(CODEQL_DIR, { recursive: true });
        fs.writeFileSync(STATE_FILE, JSON.stringify({ ...state, updatedAt: new Date().toISOString() }, null, 2));
    } catch {}
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function log(msg, level = 'info') {
    const prefix = { info: '  ℹ ', ok: '  ✓ ', warn: '  ⚠ ', error: '  ✗ ' }[level] || '    ';
    console.log(`${prefix}${msg}`);
}

function checkAlreadyInstalled() {
    if (fs.existsSync(CODEQL_BIN)) {
        try {
            const result = execSync(`"${CODEQL_BIN}" version --format=json`, { timeout: 6000, encoding: 'utf-8' });
            const parsed = JSON.parse(result.trim());
            return parsed.version || 'unknown';
        } catch {
            return null;
        }
    }
    // Also check PATH
    try {
        const cmd = process.platform === 'win32' ? 'where codeql' : 'which codeql';
        execSync(cmd, { stdio: 'ignore', timeout: 3000 });
        const result = execSync('codeql version --format=json', { timeout: 5000, encoding: 'utf-8' });
        const parsed = JSON.parse(result.trim());
        return parsed.version || 'unknown';
    } catch {
        return null;
    }
}

function httpsGet(url) {
    return new Promise((resolve, reject) => {
        const handleResponse = (res) => {
            if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 303 || res.statusCode === 307 || res.statusCode === 308) {
                const redirectUrl = res.headers.location;
                if (!redirectUrl) return reject(new Error(`Redirect with no Location header from ${url}`));
                return https.get(redirectUrl, handleResponse).on('error', reject);
            }
            if (res.statusCode !== 200) {
                return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
            }
            resolve(res);
        };
        https.get(url, handleResponse).on('error', reject);
    });
}

async function downloadFile(url, destPath) {
    const res = await httpsGet(url);
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(destPath);
        let downloaded = 0;
        res.on('data', (chunk) => {
            downloaded += chunk.length;
            const mb = (downloaded / 1024 / 1024).toFixed(1);
            process.stdout.write(`\r  ⬇  Downloading... ${mb} MB`);
        });
        res.pipe(file);
        file.on('finish', () => { process.stdout.write('\n'); file.close(resolve); });
        file.on('error', reject);
    });
}

function extractTarGz(archivePath, destDir) {
    fs.mkdirSync(destDir, { recursive: true });
    // Use tar (available on Windows 10 v1803+ and all Unix)
    execSync(`tar -xzf "${archivePath}" -C "${destDir}" --strip-components=1`, {
        timeout: 300000,
        stdio: 'inherit'
    });
}

// ── Main ───────────────────────────────────────────────────────────────────────
async function main() {
    console.log('\n╔══════════════════════════════════════════════════════╗');
    console.log('║     GCAC — CodeQL CLI Setup & Integration Helper     ║');
    console.log('╚══════════════════════════════════════════════════════╝\n');

    // 1. Check if already installed
    const existingVersion = checkAlreadyInstalled();
    if (existingVersion) {
        log(`CodeQL CLI v${existingVersion} is already installed and functional.`, 'ok');
        if (fs.existsSync(CODEQL_BIN)) {
            log(`Local binary: ${CODEQL_BIN}`, 'ok');
        } else {
            log('Found on system PATH.', 'ok');
        }
        writeState({ installed: true, version: existingVersion, binaryPath: CODEQL_BIN });
        console.log('\n✅ No installation needed. CodeQL scanning is ready.\n');
        return 0;
    }

    log(`CodeQL CLI not found. Target version: ${CODEQL_VERSION}`, 'warn');
    log(`Install destination: ${CODEQL_DIR}`, 'info');

    // 2. Check network access (this script requires bypass for download)
    const bundleUrl = getBundleUrl(CODEQL_VERSION);
    log(`Bundle URL: ${bundleUrl}`, 'info');

    const tempArchive = path.join(os.tmpdir(), `codeql-bundle-${CODEQL_VERSION}.tar.gz`);

    try {
        // 3. Download
        log('Initiating download (requires network access)...', 'info');
        await downloadFile(bundleUrl, tempArchive);
        log(`Downloaded to: ${tempArchive}`, 'ok');

        // 4. Extract
        log(`Extracting to ${CODEQL_DIR}...`, 'info');
        if (fs.existsSync(CODEQL_DIR)) {
            fs.rmSync(CODEQL_DIR, { recursive: true, force: true });
        }
        extractTarGz(tempArchive, CODEQL_DIR);

        // 5. Verify
        const installedVersion = checkAlreadyInstalled();
        if (!installedVersion) {
            log('Binary not functional after extraction. Check archive contents.', 'error');
            process.exit(1);
        }

        log(`CodeQL CLI v${installedVersion} installed successfully!`, 'ok');
        log(`Binary: ${CODEQL_BIN}`, 'ok');

        writeState({ installed: true, version: installedVersion, binaryPath: CODEQL_BIN });

        console.log('\n✅ CodeQL CLI installation complete.');
        console.log('   The GCAC scanner adapter will automatically discover this installation.\n');
        return 0;

    } catch (err) {
        log(`Download/install failed: ${err.message}`, 'error');
        console.log('\n── Manual Installation Instructions ────────────────────────');
        console.log(`1. Download: ${bundleUrl}`);
        console.log(`2. Extract to: ${CODEQL_DIR}`);
        console.log('3. Ensure codeql.exe is at: ' + CODEQL_BIN);
        console.log('4. Or set CODEQL_PATH environment variable to the codeql executable path.');
        console.log('───────────────────────────────────────────────────────────\n');
        process.exit(1);
    } finally {
        // Clean up temp archive
        try { if (fs.existsSync(tempArchive)) fs.unlinkSync(tempArchive); } catch {}
    }
}

main().catch(err => {
    console.error('Fatal error:', err.message);
    process.exit(1);
});

