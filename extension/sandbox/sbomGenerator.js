'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SBOM_FORMAT = 'CycloneDX';
const SBOM_SPEC_VERSION = '1.5';

function sha256Hex(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

function collectComponentsFromRepo(repoRoot) {
    const components = [];
    const diagnostics = [];

    if (!repoRoot || !fs.existsSync(repoRoot)) {
        return { components, diagnostics: ['Repository directory does not exist for SBOM component inspection.'] };
    }

    // 1. .NET (*.csproj + root/nested packages.lock.json)
    const lockFiles = [];
    const scanNugetLocks = (dir, depth = 0) => {
        if (depth > 3) return;
        let entries = [];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (['.git', 'node_modules', 'bin', 'obj'].includes(e.name)) continue;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) scanNugetLocks(full, depth + 1);
            else if (e.isFile() && e.name === 'packages.lock.json') lockFiles.push(full);
        }
    };
    scanNugetLocks(repoRoot, 0);

    for (const packagesLockPath of lockFiles) {
        try {
            const lock = JSON.parse(fs.readFileSync(packagesLockPath, 'utf8'));
            const relLock = path.relative(repoRoot, packagesLockPath).replace(/\\/g, '/');
            const deps = lock.dependencies || {};
            for (const tfm of Object.keys(deps)) {
                for (const [pkgName, info] of Object.entries(deps[tfm] || {})) {
                    const ver = info.resolved || info.requested || 'unknown';
                    if (!components.some(c => c.ecosystem === 'nuget' && c.name === pkgName && c.version === ver)) {
                        components.push({
                            name: pkgName,
                            version: ver,
                            ecosystem: 'nuget',
                            type: 'library',
                            purl: `pkg:nuget/${encodeURIComponent(pkgName)}@${encodeURIComponent(ver)}`,
                            sourceFile: relLock
                        });
                    }
                }
            }
        } catch (err) {
            diagnostics.push(`Failed to parse ${path.relative(repoRoot, packagesLockPath)}: ${err.message}`);
        }
    }

    const scanCsproj = (dir, depth = 0) => {
        if (depth > 3) return;
        let entries = [];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (['.git', 'node_modules', 'bin', 'obj'].includes(e.name)) continue;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) scanCsproj(full, depth + 1);
            else if (e.isFile() && e.name.endsWith('.csproj')) {
                const xml = fs.readFileSync(full, 'utf8');
                const pkgRx = /<PackageReference\s+[^>]*Include=["']([^"']+)["'][^>]*Version=["']([^"']+)["']/gi;
                let m;
                while ((m = pkgRx.exec(xml)) !== null) {
                    const name = m[1];
                    const ver = m[2];
                    if (!components.some(c => c.ecosystem === 'nuget' && c.name === name && c.version === ver)) {
                        components.push({
                            name,
                            version: ver,
                            ecosystem: 'nuget',
                            type: 'library',
                            purl: `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(ver)}`,
                            sourceFile: path.relative(repoRoot, full).replace(/\\/g, '/')
                        });
                    }
                    if (/[\*\[\]\(\)]/.test(ver)) {
                        diagnostics.push(`Floating or range NuGet version detected for '${name}': '${ver}'`);
                    }
                }
            }
        }
    };
    scanCsproj(repoRoot, 0);

    // 2. Node.js (package-lock.json or package.json)
    const npmLockPath = path.join(repoRoot, 'package-lock.json');
    const pkgJsonPath = path.join(repoRoot, 'package.json');
    if (fs.existsSync(npmLockPath)) {
        try {
            const lock = JSON.parse(fs.readFileSync(npmLockPath, 'utf8'));
            const packages = lock.packages || {};
            for (const [pkgPath, meta] of Object.entries(packages)) {
                if (!pkgPath || !meta.version) continue;
                const cleanName = pkgPath.replace(/^.*node_modules\//, '');
                if (!cleanName) continue;
                components.push({
                    name: cleanName,
                    version: meta.version,
                    ecosystem: 'npm',
                    type: 'library',
                    purl: `pkg:npm/${cleanName}@${meta.version}`,
                    sourceFile: 'package-lock.json'
                });
            }
        } catch (err) {
            diagnostics.push(`Failed to parse package-lock.json: ${err.message}`);
        }
    } else if (fs.existsSync(pkgJsonPath)) {
        diagnostics.push('package-lock.json absent; extracting unpinned declared dependencies from package.json only.');
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
            const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            for (const [name, ver] of Object.entries(allDeps)) {
                components.push({
                    name,
                    version: String(ver),
                    ecosystem: 'npm',
                    type: 'library',
                    purl: `pkg:npm/${name}@${encodeURIComponent(String(ver))}`,
                    sourceFile: 'package.json'
                });
            }
        } catch (err) {
            diagnostics.push(`Failed to parse package.json: ${err.message}`);
        }
    }

    // 3. Java Maven (pom.xml)
    const pomPath = path.join(repoRoot, 'pom.xml');
    if (fs.existsSync(pomPath)) {
        try {
            const pom = fs.readFileSync(pomPath, 'utf8');
            const depRx = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/gi;
            let m;
            while ((m = depRx.exec(pom)) !== null) {
                const groupId = m[1].trim();
                const artifactId = m[2].trim();
                const version = (m[3] || 'managed-by-parent').trim();
                components.push({
                    name: `${groupId}:${artifactId}`,
                    version,
                    ecosystem: 'maven',
                    type: 'library',
                    purl: `pkg:maven/${encodeURIComponent(groupId)}/${encodeURIComponent(artifactId)}@${encodeURIComponent(version)}`,
                    sourceFile: 'pom.xml'
                });
            }
        } catch (err) {
            diagnostics.push(`Failed to parse pom.xml: ${err.message}`);
        }
    }

    return { components, diagnostics };
}

/**
 * Generates offline supply-chain SBOM evidence in CycloneDX 1.5 format when supported,
 * explicitly keeping SBOM status separate from mandatory build/test verification
 * and reporting NOT_AVAILABLE for missing external SBOM CLIs.
 */
function generateSupplyChainSbom(params = {}) {
    const {
        runId,
        applicationId = '',
        vulnerabilityId = '',
        repoRoot,
        outputDir = null,
        imageDigest = null,
        envReport = null
    } = params;

    const generatedAt = new Date().toISOString();
    const hasExternalSbomCli = Boolean(envReport?.scannersAndSbom?.sbomTools?.anyExternalSbomCliAvailable);
    const { components, diagnostics } = collectComponentsFromRepo(repoRoot);

    const toolUsed = 'gcac-manifest-sbom-extractor';
    const toolVersion = '1.0.0';

    const bom = {
        bomFormat: SBOM_FORMAT,
        specVersion: SBOM_SPEC_VERSION,
        serialNumber: `urn:uuid:${runId || 'unbound'}`,
        version: 1,
        metadata: {
            timestamp: generatedAt,
            tools: [
                {
                    vendor: 'GCAC',
                    name: toolUsed,
                    version: toolVersion
                }
            ],
            component: {
                type: 'application',
                name: applicationId || vulnerabilityId || 'target-application',
                bomRef: applicationId || 'application'
            },
            properties: [
                { name: 'gcac:runId', value: String(runId || '') },
                { name: 'gcac:vulnerabilityId', value: String(vulnerabilityId || '') },
                { name: 'gcac:imageDigest', value: String(imageDigest || 'NONE') },
                { name: 'gcac:externalSbomCliStatus', value: hasExternalSbomCli ? 'AVAILABLE' : 'NOT_AVAILABLE' }
            ]
        },
        components: components.map(c => ({
            type: c.type,
            name: c.name,
            version: c.version,
            purl: c.purl,
            properties: [
                { name: 'gcac:ecosystem', value: c.ecosystem },
                { name: 'gcac:sourceFile', value: c.sourceFile }
            ]
        }))
    };

    const bomJson = JSON.stringify(bom, null, 2);
    const artifactHash = sha256Hex(bomJson);

    let artifactPath = null;
    if (outputDir) {
        fs.mkdirSync(outputDir, { recursive: true });
        artifactPath = path.join(outputDir, 'sbom.cdx.json');
        fs.writeFileSync(artifactPath, bomJson, 'utf8');
    }

    const sbomStatus = components.length > 0
        ? (hasExternalSbomCli ? 'GENERATED_WITH_EXTERNAL_TOOL' : 'MANIFEST_INVENTORY_ONLY_EXTERNAL_CLI_NOT_AVAILABLE')
        : 'NOT_AVAILABLE';

    return {
        sbomStatus,
        externalSbomCliStatus: hasExternalSbomCli ? 'AVAILABLE' : 'NOT_AVAILABLE',
        applicationId,
        runId,
        vulnerabilityId,
        format: `${SBOM_FORMAT}/${SBOM_SPEC_VERSION}`,
        toolUsed,
        toolVersion,
        imageDigest: imageDigest || null,
        artifactHash,
        artifactPath,
        generatedAt,
        componentCount: components.length,
        components,
        diagnostics,
        bom,
        securityDisclaimer: 'SBOM documents declared dependency inventory only and does NOT prove software security or vulnerability closure.'
    };
}

module.exports = {
    SBOM_FORMAT,
    SBOM_SPEC_VERSION,
    collectComponentsFromRepo,
    generateSupplyChainSbom
};

