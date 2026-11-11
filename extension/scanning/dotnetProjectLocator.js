'use strict';

const fs = require('fs');
const path = require('path');

const IGNORED_DIRS = new Set([
    '.git', 'node_modules', 'bin', 'obj', 'output',
    'remediation-output', 'evidence', 'workspaces', 'TestResults', '.gcac'
]);

/**
 * Searches downward inside targetDir (bounded depth) for .sln first, then .csproj.
 */
function findDotnetProjectBelow(targetDir, maxDepth = 4) {
    let foundCsproj = null;
    const queue = [{ dir: targetDir, depth: 0 }];

    while (queue.length > 0) {
        const { dir, depth } = queue.shift();
        let entries = [];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            continue;
        }

        const sortedNames = entries.map(e => e.name).sort((a, b) => a.localeCompare(b));
        for (const name of sortedNames) {
            const entry = entries.find(e => e.name === name);
            if (!entry || entry.isSymbolicLink()) continue;
            if (entry.isFile()) {
                const lower = entry.name.toLowerCase();
                if (lower.endsWith('.sln')) {
                    return path.join(dir, entry.name);
                }
                if (!foundCsproj && lower.endsWith('.csproj')) {
                    foundCsproj = path.join(dir, entry.name);
                }
            }
        }

        if (depth < maxDepth) {
            for (const entry of entries) {
                if (entry.isSymbolicLink()) continue;
                if (entry.isDirectory() && !IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                    queue.push({ dir: path.join(dir, entry.name), depth: depth + 1 });
                }
            }
        }
    }

    return foundCsproj;
}

/**
 * Resolves the enclosing .sln or .csproj file for a target file or directory
 * without escaping workspaceRoot or climbing out of a target repository directory.
 */
function resolveDotnetProjectFile(workspaceRoot, targetPath) {
    const startPath = targetPath || workspaceRoot;
    if (!startPath || !fs.existsSync(startPath)) {
        return null;
    }

    const stat = fs.statSync(startPath);
    if (stat.isFile()) {
        const lower = startPath.toLowerCase();
        if (lower.endsWith('.csproj') || lower.endsWith('.sln')) {
            return startPath;
        }
    } else if (stat.isDirectory()) {
        // When scanning a directory, search ONLY within that directory (never climb into parent GCAC repo!)
        return findDotnetProjectBelow(path.resolve(startPath), 4);
    }

    // For a source file, walk up to enclosing .csproj/.sln, stopping at any .git root or workspaceRoot
    const rootNorm = workspaceRoot ? path.resolve(workspaceRoot) : null;
    let currentDir = path.dirname(path.resolve(startPath));

    while (currentDir) {
        try {
            const files = fs.readdirSync(currentDir);
            const sln = files.find(f => f.toLowerCase().endsWith('.sln'));
            const csproj = files.find(f => f.toLowerCase().endsWith('.csproj'));
            if (csproj) return path.join(currentDir, csproj);
            if (sln) return path.join(currentDir, sln);
            // Stop climbing if we hit a repository boundary (.git)
            if (files.includes('.git')) {
                break;
            }
        } catch {}

        if (rootNorm && path.resolve(currentDir).toLowerCase() === rootNorm.toLowerCase()) {
            break;
        }
        const parent = path.dirname(currentDir);
        if (!parent || parent === currentDir) break;
        if (rootNorm) {
            const parentLower = parent.toLowerCase();
            const rootLower = rootNorm.toLowerCase();
            if (parentLower !== rootLower && !parentLower.startsWith(rootLower + path.sep)) {
                break;
            }
        }
        currentDir = parent;
    }

    return null;
}

/**
 * Checks whether a .csproj or .sln directory actually declares NuGet dependencies
 * or lockfiles (so empty .csproj projects don't attempt or fabricate package findings).
 */
function hasDotnetPackageDependencies(projectFilePath) {
    if (!projectFilePath || !fs.existsSync(projectFilePath)) return false;
    const dir = path.dirname(projectFilePath);
    const lower = projectFilePath.toLowerCase();

    if (lower.endsWith('.csproj')) {
        try {
            const xml = fs.readFileSync(projectFilePath, 'utf8');
            if (/<PackageReference\b/i.test(xml)) return true;
        } catch {}
        if (fs.existsSync(path.join(dir, 'packages.config'))) return true;
        if (fs.existsSync(path.join(dir, 'packages.lock.json'))) return true;
        if (fs.existsSync(path.join(dir, 'Directory.Packages.props'))) return true;
        return false;
    }

    // For .sln, inspect child .csproj files
    let hasDeps = false;
    const inspectDir = (d, depth = 0) => {
        if (hasDeps || depth > 4) return;
        let entries = [];
        try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            if (hasDeps) return;
            if (e.isSymbolicLink()) continue;
            if (e.isDirectory() && !IGNORED_DIRS.has(e.name) && !e.name.startsWith('.')) {
                inspectDir(path.join(d, e.name), depth + 1);
            } else if (e.isFile()) {
                const full = path.join(d, e.name);
                if (e.name.toLowerCase().endsWith('.csproj')) {
                    try {
                        const xml = fs.readFileSync(full, 'utf8');
                        if (/<PackageReference\b/i.test(xml)) hasDeps = true;
                    } catch {}
                } else if (e.name === 'packages.lock.json' || e.name === 'packages.config' || e.name === 'Directory.Packages.props') {
                    hasDeps = true;
                }
            }
        }
    };
    inspectDir(dir, 0);
    return hasDeps;
}

module.exports = {
    resolveDotnetProjectFile,
    findDotnetProjectBelow,
    hasDotnetPackageDependencies
};
