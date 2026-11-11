const path = require('path');
const fs = require('fs');

/**
 * Validates that a candidate file path is strictly within the allowed workspace boundary.
 * Prevents directory traversal attacks (../, absolute paths outside workspace, symlink escapes).
 * 
 * @param {string} candidatePath Path supplied by webview, scanner, or user input
 * @param {string} workspaceRoot Allowed workspace root directory
 * @returns {string|null} Canonical absolute path if valid and contained, null if rejected
 */
function resolveCanonicalWithExistingAncestor(targetPath) {
    const resolved = path.resolve(targetPath);
    const canonFn = typeof fs.realpathSync.native === 'function' ? fs.realpathSync.native : fs.realpathSync;
    if (fs.existsSync(resolved)) {
        return canonFn(resolved);
    }
    const suffixParts = [];
    let probe = resolved;
    while (probe && !fs.existsSync(probe)) {
        const parent = path.dirname(probe);
        if (parent === probe) break;
        suffixParts.unshift(path.basename(probe));
        probe = parent;
    }
    if (probe && fs.existsSync(probe)) {
        return path.join(canonFn(probe), ...suffixParts);
    }
    return resolved;
}

function assertPathWithinWorkspace(candidatePath, workspaceRoot) {
    if (!candidatePath || typeof candidatePath !== 'string' || !workspaceRoot) {
        return null;
    }

    const resolvedWs = path.resolve(workspaceRoot);
    const resolvedPath = path.isAbsolute(candidatePath)
        ? path.resolve(candidatePath)
        : path.resolve(resolvedWs, candidatePath);

    try {
        const realWs = resolveCanonicalWithExistingAncestor(resolvedWs);
        const realPath = resolveCanonicalWithExistingAncestor(resolvedPath);
        const realRel = path.relative(realWs, realPath);
        if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
            return null;
        }
        return realPath;
    } catch (e) {
        return null;
    }
}

module.exports = {
    assertPathWithinWorkspace
};
