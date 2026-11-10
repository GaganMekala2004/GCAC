'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertPathWithinWorkspace } = require('./pathUtils');
const { ContentInjectionScreen, TRUST_CLASSES, SCREEN_OUTCOME } = require('./contentInjectionScreen');

class AgentConfigIntegrityError extends Error {
    constructor(reason, code = 'AGENT_INTEGRITY_BLOCKED', details = {}) {
        super(`BLOCKED (${code}): ${reason}`);
        this.name = 'AgentConfigIntegrityError';
        this.code = code;
        this.machineStatus = 'BLOCKED';
        this.details = details;
    }
}

function computeNormalizedSha256(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
    return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

/**
 * Lightweight deterministic YAML frontmatter extractor for agent markdown files.
 */
function parseAgentFrontmatter(markdownContent) {
    const match = String(markdownContent || '').match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (!match) return null;

    const lines = match[1].split(/\r?\n/);
    const result = {
        name: null,
        version: null,
        description: null,
        tools: [],
        skills: [],
        agents: []
    };

    let currentListKey = null;
    for (const rawLine of lines) {
        const line = rawLine.trimEnd();
        if (!line.trim()) continue;

        const listItemMatch = line.match(/^\s*-\s+(.+)$/);
        if (listItemMatch && currentListKey && Array.isArray(result[currentListKey])) {
            result[currentListKey].push(listItemMatch[1].trim().replace(/^["']|["']$/g, ''));
            continue;
        }

        const kvMatch = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
        if (kvMatch) {
            const key = kvMatch[1];
            const val = kvMatch[2].trim().replace(/^["']|["']$/g, '');
            if (key === 'tools' || key === 'skills' || key === 'agents') {
                currentListKey = key;
                if (val.startsWith('[') && val.endsWith(']')) {
                    const inlineItems = val.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
                    result[key].push(...inlineItems);
                    currentListKey = null;
                }
            } else {
                currentListKey = null;
                if (key === 'name') result.name = val;
                else if (key === 'version') result.version = val;
                else if (key === 'description') result.description = val;
            }
        }
    }

    return result;
}

/**
 * Loads the trusted baseline manifest (either an administrator-controlled bundle path
 * or the extension-distributed baseline inside extension/config/approved-agent-bundle.json).
 */
function loadTrustedBaselineManifest({ extensionRoot, adminBundlePath = null, requireSignedBundle = false, signatureVerifier = null } = {}) {
    const manifestPath = adminBundlePath
        ? path.resolve(adminBundlePath)
        : path.join(extensionRoot || path.resolve(__dirname, '..'), 'extension', 'config', 'approved-agent-bundle.json');

    const fallbackAlt = path.join(extensionRoot || __dirname, 'config', 'approved-agent-bundle.json');
    const resolvedPath = fs.existsSync(manifestPath) ? manifestPath : (adminBundlePath ? manifestPath : fallbackAlt);

    if (!fs.existsSync(resolvedPath)) {
        throw new AgentConfigIntegrityError(
            `Trusted agent configuration baseline manifest is missing at '${resolvedPath}'.`,
            'MISSING_AGENT_MANIFEST'
        );
    }

    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
    } catch (err) {
        throw new AgentConfigIntegrityError(
            `Trusted agent configuration baseline manifest is malformed: ${err.message}`,
            'MALFORMED_AGENT_MANIFEST'
        );
    }

    if (!manifest || !manifest.bundleVersion || !manifest.toolPolicyVersion || !manifest.sharedInstructionHash || !Array.isArray(manifest.agents) || manifest.agents.length === 0) {
        throw new AgentConfigIntegrityError(
            'Trusted agent baseline manifest lacks required bundleVersion, toolPolicyVersion, sharedInstructionHash, or agents array.',
            'MALFORMED_AGENT_MANIFEST'
        );
    }

    if (requireSignedBundle) {
        if (typeof signatureVerifier !== 'function' || !manifest.bundleSignature || !signatureVerifier(manifest)) {
            throw new AgentConfigIntegrityError(
                'Signed enterprise agent bundle verification required, but no valid verified signature was supplied.',
                'UNSIGNED_AGENT_BUNDLE'
            );
        }
    }

    return { manifest, manifestPath: resolvedPath };
}

/**
 * Verifies workspace agent definitions, shared instructions, tool permissions, and versions
 * against the trusted baseline manifest before starting a governed remediation run.
 */
function verifyAgentConfigurationIntegrity(options = {}) {
    const {
        extensionRoot = path.resolve(__dirname, '..'),
        workspaceRoot,
        adminBundlePath = null,
        requireSignedBundle = false,
        signatureVerifier = null,
        strictWorkspaceCheck = null
    } = options;

    const { manifest, manifestPath } = loadTrustedBaselineManifest({
        extensionRoot,
        adminBundlePath,
        requireSignedBundle,
        signatureVerifier
    });

    if (!workspaceRoot || !fs.existsSync(workspaceRoot)) {
        throw new AgentConfigIntegrityError('Valid workspaceRoot is required for agent configuration verification.', 'INVALID_WORKSPACE');
    }

    const hasGithubDir = fs.existsSync(path.join(workspaceRoot, '.github'));
    const hasGitDir = fs.existsSync(path.join(workspaceRoot, '.git'));
    const mustVerifyWorkspaceFiles = strictWorkspaceCheck !== null
        ? strictWorkspaceCheck === true
        : (hasGithubDir || hasGitDir);

    const verifiedAgents = [];
    const forbiddenTools = new Set((manifest.forbiddenTools || []).map(t => String(t).toLowerCase()));
    const injectionScreen = new ContentInjectionScreen();

    if (mustVerifyWorkspaceFiles) {
        // 1. Verify shared instruction file
        const sharedRel = manifest.sharedInstructionPath || '.github/copilot-instructions.md';
        const sharedAbs = assertPathWithinWorkspace(path.join(workspaceRoot, sharedRel), workspaceRoot);
        if (!sharedAbs || !fs.existsSync(sharedAbs) || fs.lstatSync(sharedAbs).isSymbolicLink()) {
            throw new AgentConfigIntegrityError(
                `Required shared instruction file '${sharedRel}' is missing, symlinked, or escapes workspace.`,
                'SHARED_INSTRUCTIONS_MISSING'
            );
        }
        const actualSharedHash = computeNormalizedSha256(sharedAbs);
        if (actualSharedHash !== manifest.sharedInstructionHash) {
            throw new AgentConfigIntegrityError(
                `Shared instructions '${sharedRel}' hash mismatch (tampering or unapproved modification detected).`,
                'SHARED_INSTRUCTIONS_TAMPERED',
                { expected: manifest.sharedInstructionHash, actual: actualSharedHash }
            );
        }

        // 2. Verify all approved agents
        const expectedFilesSet = new Set();
        for (const agentSpec of manifest.agents) {
            expectedFilesSet.add(path.basename(agentSpec.filePath));
            const agentAbs = assertPathWithinWorkspace(path.join(workspaceRoot, agentSpec.filePath), workspaceRoot);
            if (!agentAbs || !fs.existsSync(agentAbs) || fs.lstatSync(agentAbs).isSymbolicLink()) {
                throw new AgentConfigIntegrityError(
                    `Approved agent definition '${agentSpec.filePath}' is missing, symlinked, or outside workspace.`,
                    'AGENT_DEFINITION_MISSING'
                );
            }

            const actualHash = computeNormalizedSha256(agentAbs);
            if (actualHash !== agentSpec.configurationHash) {
                throw new AgentConfigIntegrityError(
                    `Agent definition '${agentSpec.agentName}' (${agentSpec.filePath}) hash mismatch; unauthorized modification detected.`,
                    'AGENT_DEFINITION_TAMPERED',
                    { agentName: agentSpec.agentName, expected: agentSpec.configurationHash, actual: actualHash }
                );
            }

            const content = fs.readFileSync(agentAbs, 'utf8');
            const fm = parseAgentFrontmatter(content);
            if (!fm || fm.name !== agentSpec.agentName) {
                throw new AgentConfigIntegrityError(
                    `Agent definition '${agentSpec.filePath}' frontmatter name '${fm?.name}' does not match '${agentSpec.agentName}'.`,
                    'AGENT_NAME_MISMATCH'
                );
            }
            if (fm.version && fm.version !== agentSpec.approvedVersion) {
                throw new AgentConfigIntegrityError(
                    `Agent '${agentSpec.agentName}' version '${fm.version}' does not match approved version '${agentSpec.approvedVersion}'.`,
                    'UNEXPECTED_AGENT_VERSION'
                );
            }

            // Tool permission verification
            const actualTools = fm.tools || [];
            for (const tool of actualTools) {
                if (forbiddenTools.has(tool.toLowerCase())) {
                    throw new AgentConfigIntegrityError(
                        `Forbidden tool '${tool}' declared in agent '${agentSpec.agentName}'.`,
                        'FORBIDDEN_TOOL_PERMISSION'
                    );
                }
            }
            const expectedTools = agentSpec.allowedTools || [];
            const sortedActual = [...actualTools].sort();
            const sortedExpected = [...expectedTools].sort();
            if (sortedActual.length !== sortedExpected.length || sortedActual.some((t, i) => t !== sortedExpected[i])) {
                throw new AgentConfigIntegrityError(
                    `Tool permissions modified for agent '${agentSpec.agentName}'.`,
                    'TOOL_PERMISSION_TAMPERED',
                    { expected: sortedExpected, actual: sortedActual }
                );
            }

            verifiedAgents.push({
                agentName: agentSpec.agentName,
                agentRole: agentSpec.agentRole,
                approvedVersion: agentSpec.approvedVersion,
                configurationHash: actualHash
            });
        }

        // 3. Reject unexpected unapproved *.agent.md files in .github/agents/
        const agentsDir = assertPathWithinWorkspace(path.join(workspaceRoot, '.github', 'agents'), workspaceRoot);
        if (agentsDir && fs.existsSync(agentsDir)) {
            const diskAgents = fs.readdirSync(agentsDir).filter(f => f.endsWith('.agent.md'));
            for (const diskFile of diskAgents) {
                if (!expectedFilesSet.has(diskFile)) {
                    throw new AgentConfigIntegrityError(
                        `Unapproved extra agent definition detected in workspace: '.github/agents/${diskFile}'.`,
                        'UNAPPROVED_AGENT_PRESENT'
                    );
                }
            }
        }
    }

    // 4. Screen any untrusted repo README/instructions to guarantee repo-owned text cannot elevate policy
    const readmePath = path.join(workspaceRoot, 'README.md');
    let readmeTrustStatus = 'NOT_PRESENT';
    if (fs.existsSync(readmePath) && fs.statSync(readmePath).isFile()) {
        const readmeText = fs.readFileSync(readmePath, 'utf8').slice(0, 16384);
        const screenRes = injectionScreen.screen({
            text: readmeText,
            contentSource: 'workspace:README.md',
            trustClass: TRUST_CLASSES.UNTRUSTED_README,
            runId: 'agent-config-check',
            filePath: 'README.md'
        });
        readmeTrustStatus = screenRes.outcome;
        if (screenRes.outcome === SCREEN_OUTCOME.BLOCK || screenRes.outcome === SCREEN_OUTCOME.QUARANTINE) {
            throw new AgentConfigIntegrityError(
                `Untrusted repository README attempted instruction/policy override (${screenRes.ruleId}).`,
                'UNTRUSTED_REPO_INSTRUCTION_OVERRIDE'
            );
        }
    }

    return {
        verified: true,
        workspaceFilesChecked: mustVerifyWorkspaceFiles,
        manifestPath,
        bundleVersion: manifest.bundleVersion,
        toolPolicyVersion: manifest.toolPolicyVersion,
        sharedInstructionHash: manifest.sharedInstructionHash,
        trustModel: manifest.trustModel,
        verifiedAgentsCount: verifiedAgents.length || manifest.agents.length,
        verifiedAgents,
        readmeTrustStatus,
        trustHierarchy: 'EXTENSION_POLICY > ADMIN_SIGNED_BUNDLE > WORKSPACE_INSTRUCTIONS (LOCKED_BY_BASELINE)',
        verifiedAt: new Date().toISOString()
    };
}

module.exports = {
    AgentConfigIntegrityError,
    computeNormalizedSha256,
    parseAgentFrontmatter,
    loadTrustedBaselineManifest,
    verifyAgentConfigurationIntegrity
};
