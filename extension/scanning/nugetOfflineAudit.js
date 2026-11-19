'use strict';
const fs = require('fs');
const { isSeparateRepositoryDirectory } = require('../repositoryContext');
const path = require('path');
const { inRange, compareVersions } = require('./nugetAdvisories');

function auditResolvedProjects(target, snapshot, abortSignal) {
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
    const results = [], seen = new Set(); let packagesChecked = 0;
    for (const project of projects) {
        const dir = path.dirname(project);
        // These imports can alter dependency resolution outside the project.
        const assetsFile = path.join(dir, 'obj', 'project.assets.json');
        const assets = JSON.parse(fs.readFileSync(assetsFile, 'utf8'));
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
        const graphTime = fs.statSync(assetsFile).mtimeMs;
        if (fs.statSync(project).mtimeMs > graphTime) throw new Error('Resolved package graph predates the project; restore before auditing.');
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
        if ((source.match(/<ProjectReference\b/gi) || []).length !== projectReferences.length || projectReferences.some(reference =>
            !projects.some(candidate => path.resolve(candidate) === path.resolve(dir, reference[1].replace(/\\/g, '/'))))) {
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
                results.push({ path: project, frameworks: [{ topLevelPackages: [{ id, resolvedVersion: version,
                    vulnerabilities: [{ advisoryUrl: advisory.url, severity: ['Low', 'Moderate', 'High', 'Critical'][advisory.severity] }] }] }] });
            }
        }
    }
    return { projects: results, projectsChecked: projects.length, packagesChecked };
}
module.exports = { auditResolvedProjects };
