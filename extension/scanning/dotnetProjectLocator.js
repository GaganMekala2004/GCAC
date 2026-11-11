'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Resolves the enclosing .sln or .csproj file for a target file or directory
 * without escaping workspaceRoot.
 */
function resolveDotnetProjectFile(workspaceRoot, targetPath) {
    const startPath = targetPath || workspaceRoot;
    if (!startPath || !fs.existsSync(startPath)) {
        return null;
    }

    const stat = fs.statSync(startPath);
    if (stat.isFile() && (startPath.endsWith('.csproj') || startPath.endsWith('.sln'))) {
        return startPath;
    }

    const rootNorm = workspaceRoot ? path.resolve(workspaceRoot) : null;
    let currentDir = stat.isFile() ? path.dirname(startPath) : path.resolve(startPath);

    while (currentDir) {
        try {
            const files = fs.readdirSync(currentDir);
            const sln = files.find(f => f.endsWith('.sln'));
            const csproj = files.find(f => f.endsWith('.csproj'));
            if (sln) return path.join(currentDir, sln);
            if (csproj) return path.join(currentDir, csproj);
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

module.exports = {
    resolveDotnetProjectFile
};
