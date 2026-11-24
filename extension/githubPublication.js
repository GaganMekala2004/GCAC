'use strict';
const { execFileSync } = require('child_process');
const https = require('https');
const zlib = require('node:zlib');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function git(cwd, args, env = {}) {
    return execFileSync('git', ['-c', 'core.hooksPath=/dev/null', ...args], {
        cwd, shell: false, encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', ...env }
    }).trim();
}
function githubRepository(remote) {
    const match = String(remote).match(/^(?:https:\/\/github\.com\/|git@github\.com:)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/);
    return match ? { owner: match[1], repository: match[2] } : null;
}

function pushFailureReason(error) {
    const diagnostic = `${error.stderr || ''}\n${error.stdout || ''}`;
    if (/403|401|authentication failed|permission to .* denied|write access|repository not found|could not read username/i.test(diagnostic)) {
        return 'The signed-in GitHub account could not write to the reviewed repository. Sign in with an account that has write access, then retry.';
    }
    if (/protected branch|repository rule|GH006|GH013|pre-receive hook declined/i.test(diagnostic)) {
        return 'GitHub repository rules rejected the branch update. Check the rules for the reviewed destination before retrying.';
    }
    if (/non-fast-forward|fetch first|\[rejected\]/i.test(diagnostic)) {
        return 'GitHub rejected the branch update. Check whether the dedicated remediation branch already contains a different commit.';
    }
    if (error.code === 'ETIMEDOUT' || /could not resolve|failed to connect|timed out|certificate|proxy/i.test(diagnostic)) {
        return 'Git could not complete the connection to GitHub. Check network access, proxy settings, and certificates before retrying.';
    }
    return 'Check that the signed-in GitHub account can push to the reviewed repository and that GitHub is reachable.';
}
function api(method, resource, token, body) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const request = https.request({ hostname: 'api.github.com', path: resource, method, timeout: 30000,
            headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'Accept-Encoding': 'identity',
                'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'GCAC-Remediation',
                ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) }
        }, response => {
            const chunks = [];
            let size = 0;
            const limit = 2 * 1024 * 1024;
            response.on('data', chunk => {
                size += chunk.length;
                if (size > limit) response.destroy(new Error('GitHub response exceeds the publication limit.'));
                else chunks.push(Buffer.from(chunk));
            });
            response.on('error', reject);
            response.on('end', () => {
                const status = response.statusCode;
                if (status < 200 || status >= 300) return reject(new Error(`GitHub ${method} pulls returned HTTP ${status}.`));
                try {
                    let bytes = Buffer.concat(chunks);
                    const encoding = response.headers['content-encoding'];
                    if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = zlib.gunzipSync(bytes, { maxOutputLength: limit });
                    else if (encoding === 'br') bytes = zlib.brotliDecompressSync(bytes, { maxOutputLength: limit });
                    else if (encoding === 'deflate') bytes = zlib.inflateSync(bytes, { maxOutputLength: limit });
                    resolve(JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, '')));
                } catch {
                    const error = new Error(`GitHub ${method} pulls returned HTTP ${status} with an unreadable response (${size} bytes). Check the Extension Host GitHub connection and proxy, then retry publication.`);
                    error.code = 'GITHUB_RESPONSE_UNREADABLE';
                    reject(error);
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('GitHub request timed out.')));
        request.on('error', () => reject(new Error('GitHub publication request failed.')));
        request.end(payload);
    });
}
class GitHubPublication {
    constructor({ getToken, gitFn = git, apiFn = api } = {}) { this.getToken = getToken; this.git = gitFn; this.api = apiFn; }
    prepare({ repositoryPath, runId, vulnerabilityId, proposedDiffSha256 }) {
        let remote;
        try { remote = this.git(repositoryPath, ['remote', 'get-url', 'origin']); }
        catch { return { status: 'NOT_CONFIGURED', reason: 'No origin remote. Final approval closes local evidence only; no GitHub PR can be created.' }; }
        const repo = githubRepository(remote);
        if (!repo) return { status: 'NOT_CONFIGURED', reason: 'Origin is not a supported github.com SSH/HTTPS remote. No PR will be created.' };
        let baseBranch;
        try { baseBranch = this.git(repositoryPath, ['symbolic-ref', '--short', 'refs/remotes/origin/HEAD']).replace(/^origin\//, ''); }
        catch { return { status: 'NOT_CONFIGURED', reason: 'Origin default branch is not recorded locally. Fetch origin and set origin/HEAD before preparing publication.' }; }
        if (!/^[A-Za-z0-9_./-]+$/.test(baseBranch) || baseBranch.startsWith('-') || baseBranch.includes('..')) throw new Error('Invalid GitHub base branch.');
        const branch = `gcac/${String(vulnerabilityId).toLowerCase().replace(/[^a-z0-9-]/g, '-')}/${String(runId).toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
        return { status: 'READY', ...repo, baseBranch, branch, runId, vulnerabilityId, proposedDiffSha256,
            remote: `https://github.com/${repo.owner}/${repo.repository}.git` };
    }
    async publish({ plan, worktreeDir, approvedFiles, patchDiff, finalApproved, runId, expectedHead, expectedFiles, commitTitle, summary }) {
        if (!finalApproved || plan?.status !== 'READY' || plan.runId !== runId ||
            crypto.createHash('sha256').update(patchDiff).digest('hex') !== plan.proposedDiffSha256) throw new Error('PUBLICATION_APPROVAL_MISMATCH: Publication must match the reviewed Stage 8 run and diff.');
        const destination = githubRepository(plan.remote);
        if (!destination || destination.owner !== plan.owner || destination.repository !== plan.repository ||
            plan.remote !== `https://github.com/${plan.owner}/${plan.repository}.git` ||
            !/^gcac\/[a-z0-9-]+\/[a-z0-9-]+$/.test(plan.branch) ||
            !/^[A-Za-z0-9_./-]+$/.test(plan.baseBranch) || plan.baseBranch.startsWith('-') || plan.baseBranch.includes('..') ||
            !approvedFiles?.length || approvedFiles.some(file => typeof file !== 'string' || path.isAbsolute(file) || /[\r\n\0]/.test(file) || file.split(/[\\/]/).includes('..'))) {
            throw new Error('PUBLICATION_DESTINATION_INVALID: Reviewed destination or scope is invalid.');
        }
        const token = await this.getToken?.();
        if (!token) throw new Error('GitHub authentication is required to create the reviewed pull request.');
        const endpoint = `/repos/${plan.owner}/${plan.repository}/pulls`;
        const lookup = async () => {
            const existing = await this.api('GET', `${endpoint}?state=all&head=${encodeURIComponent(plan.owner + ':' + plan.branch)}`, token);
            if (!Array.isArray(existing)) throw Error('GitHub pull-request lookup returned an unexpected response.');
            return existing.find(pr => pr.head?.ref === plan.branch && Number.isInteger(pr.number) &&
                pr.html_url === `https://github.com/${plan.owner}/${plan.repository}/pull/${pr.number}`);
        };
        let prior;
        try { prior = await lookup(); }
        catch (error) {
            if (error.code !== 'GITHUB_RESPONSE_UNREADABLE') throw error;
            prior = await lookup();
        }
        if (prior) return { status: 'CREATED', url: prior.html_url, number: prior.number, branch: plan.branch, reused: true };
        if (!approvedFiles?.length || approvedFiles.some(file => !expectedFiles?.[file] ||
            crypto.createHash('sha256').update(fs.readFileSync(path.join(worktreeDir, file))).digest('hex') !== expectedFiles[file])) {
            throw new Error('PUBLICATION_SOURCE_CHANGED: Approved source bytes changed after validation.');
        }
        const head = this.git(worktreeDir, ['rev-parse', 'HEAD']);
        const resuming = head !== expectedHead && this.git(worktreeDir, ['branch', '--show-current']) === plan.branch &&
            this.git(worktreeDir, ['rev-parse', 'HEAD^']) === expectedHead;
        if (head !== expectedHead && !resuming) throw new Error('PUBLICATION_HEAD_CHANGED: Isolated Git HEAD changed since the reviewed baseline.');
        const staged = this.git(worktreeDir, ['diff', '--cached', '--name-only']).split('\n').filter(Boolean);
        if (staged.some(file => !approvedFiles.includes(file))) throw new Error('PUBLICATION_SCOPE_CHANGED: Unexpected staged files.');
        if (resuming) {
            const committed = this.git(worktreeDir, ['diff', '--name-only', expectedHead, 'HEAD']).split('\n').filter(Boolean);
            if (!committed.length || committed.some(file => !approvedFiles.includes(file)) || this.git(worktreeDir, ['diff', '--name-only', 'HEAD'])) {
                throw new Error('PUBLICATION_SCOPE_CHANGED: Cannot resume an altered publication commit.');
            }
        }
        const changed = this.git(worktreeDir, ['diff', '--name-only', 'HEAD']).split('\n').filter(Boolean);
        if (!resuming && (!changed.length || changed.some(file => !approvedFiles.includes(file)))) throw new Error('PUBLICATION_SCOPE_CHANGED: Only approved files may be committed.');
        if (!resuming) {
            if (this.git(worktreeDir, ['branch', '--show-current']) !== plan.branch) this.git(worktreeDir, ['checkout', '-b', plan.branch]);
            this.git(worktreeDir, ['add', '--', ...approvedFiles]);
            this.git(worktreeDir, ['-c', 'user.name=GCAC Remediation', '-c', 'user.email=gcac-remediation@users.noreply.github.com',
                'commit', '--no-gpg-sign', '-m', commitTitle]);
        }
        const commit = this.git(worktreeDir, ['rev-parse', 'HEAD']);
        const auth = Buffer.from(`x-access-token:${token}`).toString('base64');
        try {
            this.git(worktreeDir, ['-c', 'http.followRedirects=false', 'push', '--porcelain', plan.remote, `HEAD:refs/heads/${plan.branch}`], {
                GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${auth}`
            });
        } catch (error) {
            throw new Error(`GITHUB_PUSH_FAILED: ${pushFailureReason(error)} Approved commit ${commit} remains on the local isolated branch.`);
        }
        let pr;
        try {
            pr = await this.api('POST', endpoint, token, { title: commitTitle, head: plan.branch, base: plan.baseBranch, body: summary, draft: true });
        } catch (error) {
            pr = await lookup();
            if (!pr) throw error;
        }
        if (!Number.isInteger(pr?.number) || pr.html_url !== `https://github.com/${plan.owner}/${plan.repository}/pull/${pr.number}`) throw new Error('GitHub did not return a verifiable pull request URL.');
        return { status: 'CREATED', url: pr.html_url, number: pr.number, branch: plan.branch, commit, draft: true };
    }
}
module.exports = { GitHubPublication, githubRepository };
