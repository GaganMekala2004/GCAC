'use strict';
const fs = require('fs');
const { isSeparateRepositoryDirectory } = require('../repositoryContext');
const path = require('path');
const { assertPathWithinWorkspace } = require('../pathUtils');
const { readSnapshot, snapshotPath, inRange, compareVersions } = require('./nugetAdvisories');

// Only offer stable, published packages already restored from NuGet.org.
function cachedUpgrade(id, current, advisories, cacheRoot) {
    if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(id)) return '';
    const packageDir = path.join(cacheRoot, id.toLowerCase());
    let entries;
    try { entries = fs.readdirSync(packageDir, { withFileTypes: true }); } catch { return ''; }
    const candidates = entries.filter(entry => entry.isDirectory() && /^\d+(?:\.\d+){1,3}$/.test(entry.name))
        .map(entry => entry.name).filter(v => compareVersions(v, current) > 0 && !advisories.some(a => inRange(v, a.versions)))
        .sort(compareVersions);
    return candidates.find(version => {
        const dir = path.join(packageDir, version);
        try {
            const metadata = JSON.parse(fs.readFileSync(path.join(dir, '.nupkg.metadata'), 'utf8'));
            return metadata.source === 'https://api.nuget.org/v3/index.json' && Boolean(metadata.contentHash) &&
                fs.existsSync(path.join(dir, id.toLowerCase() + '.' + version + '.nupkg'));
        } catch { return false; }
    }) || '';
}

function findAuditProjects(target, abortSignal) {
    const projects = [];
    const skipped = new Set(['.git', 'node_modules', 'bin', 'obj', 'packages', 'output', 'remediation-output', 'workspaces', 'evidence']);
    const walk = dir => {
        if (abortSignal?.aborted) throw new Error('NuGet audit cancelled.');
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            if (entry.isSymbolicLink()) continue;
            const full = path.join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && !skipped.has(entry.name) && !isSeparateRepositoryDirectory(full)) walk(full);
            else if (entry.isFile() && entry.name.endsWith('.csproj')) projects.push(full);
        }
    };
    if (target.endsWith('.csproj')) projects.push(target);
    else if (fs.statSync(target).isDirectory()) walk(target);
    else throw new Error('Offline audit requires a project or repository directory.');
    if (!projects.length) throw new Error('No .NET projects available for offline auditing.');
    return projects;
}

function auditResolvedProjects(target, snapshot, abortSignal, cacheRoot = process.env.NUGET_PACKAGES || path.join(require('os').homedir(), '.nuget', 'packages'), restoredGraph = null) {
    const projects = findAuditProjects(target, abortSignal);
    const results = [], seen = new Set(); let packagesChecked = 0;
    for (const project of projects) {
        const dir = path.dirname(project);
        // These imports can alter dependency resolution outside the project.
        const assetsFile = path.join(dir, 'obj', 'project.assets.json');
        const assets = restoredGraph || JSON.parse(fs.readFileSync(assetsFile, 'utf8'));
        if (!assets.targets || !assets.libraries || !assets.project?.frameworks ||
            assets.logs?.some(log => log.level === 'Error')) throw new Error('Resolved package graph is incomplete; restore in the approved sandbox first.');
        const source = fs.readFileSync(project, 'utf8');
        if (fs.existsSync(path.join(dir, 'packages.config'))) throw new Error('Legacy packages.config requires sandbox NuGet auditing.');
        for (const framework of Object.values(assets.project.frameworks)) {
            for (const [id, dependency] of Object.entries(framework.dependencies || {})) {
                if (dependency.target && dependency.target !== 'Package') continue;
                const identity = Object.entries(assets.libraries).find(([key, value]) =>
                    value.type === 'package' && key.slice(0, key.lastIndexOf('/')).toLowerCase() === id.toLowerCase());
                if (!identity) throw new Error('Resolved graph is missing a declared dependency; restore before auditing.');
            }
        }
        const references = [...source.matchAll(/<PackageReference\b[^>]*\bInclude=["']([^"']+)["'][^>]*>/gi)];
        if ((source.match(/<PackageReference\b/gi) || []).length !== references.length) throw new Error('Unsupported package reference; refresh the resolved graph in the approved sandbox.');
        for (const reference of references) {
            const version = reference[0].match(/\bVersion=["']([^"']+)["']/i)?.[1];
            const versions = Object.values(assets.project.frameworks).map(fw => Object.entries(fw.dependencies || {})
                .find(([id]) => id.toLowerCase() === reference[1].toLowerCase())?.[1]?.version).filter(Boolean);
            if (!version || !versions.length) throw new Error('Central, conditional, or unevaluated dependencies require sandbox NuGet auditing.');
            for (const resolvedRange of versions) {
                const minimum = resolvedRange.match(/^\[([^,]+),\s*\)$/)?.[1];
                if (minimum ? compareVersions(version, minimum) !== 0 : version.replace(/\s/g, '') !== resolvedRange.replace(/\s/g, '')) {
                    throw new Error('Project dependencies differ from the restored package graph; restore before auditing.');
                }
            }
        }
        // Reject graphs older than project/central/import manifests. Never silently
        // audit cached dependencies after an edit to package declarations.
        let parent = dir;
        if (!restoredGraph && fs.statSync(project).mtimeMs > fs.statSync(assetsFile).mtimeMs) throw new Error('Resolved package graph predates the project; restore before auditing.');
        while (true) {
            for (const name of ['Directory.Packages.props', 'Directory.Build.props', 'Directory.Build.targets']) {
                const file = path.join(parent, name);
                if (fs.existsSync(file)) throw new Error('Imported dependency configuration requires sandbox NuGet auditing.');
            }
            if (fs.existsSync(path.join(parent, '.git')) || path.dirname(parent) === parent) break;
            parent = path.dirname(parent);
        }
        if (/<Import\b/i.test(source)) throw new Error('Imported dependencies require sandbox NuGet auditing.');
        const projectReferences = [...source.matchAll(/<ProjectReference\b[^>]*Include=["']([^"']+)["']/gi)];
        if ((source.match(/<ProjectReference\b/gi) || []).length !== projectReferences.length || (!restoredGraph && projectReferences.some(reference =>
            !projects.some(candidate => path.resolve(candidate) === path.resolve(dir, reference[1].replace(/\\/g, '/')))))) {
            throw new Error('Referenced projects outside the audited target require sandbox NuGet auditing.');
        }
        for (const [identity, library] of Object.entries(assets.libraries)) {
            if (library.type !== 'package') continue;
            if (!Object.values(assets.targets).some(target => target[identity]?.type === 'package')) {
                throw new Error('Resolved graph contains an unverified package entry; restore before auditing.');
            }
            const split = identity.lastIndexOf('/');
            const id = identity.slice(0, split), version = identity.slice(split + 1);
            packagesChecked++;
            for (const advisory of snapshot.packages[id.toLowerCase()] || []) {
                if (!inRange(version, advisory.versions)) continue;
                const key = `${project}|${identity}|${advisory.url}`;
                if (seen.has(key)) continue;
                seen.add(key);
                const direct = references.filter(ref => ref[1].toLowerCase() === id.toLowerCase());
                const exact = direct.length === 1 && direct[0][0].match(/\bVersion=["']([^"']+)["']/i)?.[1] === version;
                // A single-framework project can explicitly pin a resolved transitive package.
                const frameworks = Object.values(assets.project.frameworks);
                const transitivePin = !direct.length && frameworks.length === 1 && !Object.keys(frameworks[0].dependencies || {})
                    .some(name => name.toLowerCase() === id.toLowerCase());
                const fixedVersion = exact || transitivePin ? cachedUpgrade(id, version, snapshot.packages[id.toLowerCase()], cacheRoot) : '';
                results.push({ path: project, frameworks: [{ [direct.length ? 'topLevelPackages' : 'transitivePackages']: [{ id, resolvedVersion: version, fixedVersion,
                    vulnerabilities: [{ advisoryUrl: advisory.url, severity: ['Low', 'Moderate', 'High', 'Critical'][advisory.severity] }] }] }] });
            }
        }
    }
    return { projects: results, projectsChecked: projects.length, packagesChecked };
}
function verifiedNugetUpgrade(finding, repository, workspace) {
    const project = assertPathWithinWorkspace(finding.Location_Path, repository);
    if (!project?.endsWith('.csproj')) return null;
    const assets = path.join(path.dirname(project), 'obj', 'project.assets.json');
    if (!assertPathWithinWorkspace(assets, repository)) return null;
    const snapshot = readSnapshot(snapshotPath(workspace));
    const audit = auditResolvedProjects(repository, snapshot);
    for (const item of audit.projects) {
        if (path.resolve(item.path) !== path.resolve(project)) continue;
        for (const framework of item.frameworks) {
            for (const pkg of [...(framework.topLevelPackages || []), ...(framework.transitivePackages || [])]) {
                if (pkg.id.toLowerCase() === String(finding.Package_Name).toLowerCase() &&
                    pkg.resolvedVersion === finding.Current_Version && pkg.fixedVersion &&
                    pkg.vulnerabilities.some(entry => entry.advisoryUrl === finding.Advisory_URL)) {
                    return { version: pkg.fixedVersion, transitive: Boolean(framework.transitivePackages) };
                }
            }
        }
    }
    return null;
}
module.exports = { auditResolvedProjects, findAuditProjects, verifiedNugetUpgrade };
