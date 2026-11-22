'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { GitHubPublication, githubRepository } = require('../../extension/githubPublication');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-publication-'));
    const git = args => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', ...args], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    try {
        assert.deepStrictEqual(githubRepository('git@github.com:owner/repo.git'), { owner: 'owner', repository: 'repo' });
        assert.strictEqual(githubRepository('https://token@github.com/owner/repo.git'), null);
        assert.strictEqual(githubRepository('https://github.com.evil.test/owner/repo'), null);
        git(['init', '-b', 'main']);
        fs.writeFileSync(path.join(root, 'source.cs'), 'old\n');
        git(['add', 'source.cs']);
        git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'baseline']);
        const base = git(['rev-parse', 'HEAD']);
        const publisher = new GitHubPublication();
        assert.strictEqual(publisher.prepare({ repositoryPath: root }).status, 'NOT_CONFIGURED');
        git(['remote', 'add', 'origin', 'https://github.com/owner/repo.git']);
        git(['update-ref', 'refs/remotes/origin/main', base]);
        git(['symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main']);
        fs.writeFileSync(path.join(root, 'source.cs'), 'fixed\n');
        const patchDiff = git(['diff']) + '\n';
        const sha = crypto.createHash('sha256').update(patchDiff).digest('hex');
        const plan = publisher.prepare({ repositoryPath: root, runId: 'run-test', vulnerabilityId: 'VUL-TEST', proposedDiffSha256: sha });
        assert.strictEqual(plan.status, 'READY');
        assert.strictEqual(plan.baseBranch, 'main');
        const pushes = [], requests = [];
        let remotePR = null;
        let initialLookup = true;
        const service = new GitHubPublication({ getToken: async () => 'fixture-token',
            gitFn: (cwd, args, env) => {
                if (args.includes('push')) { pushes.push({ args, env }); return ''; }
                return git(args);
            }, apiFn: async (method, endpoint, token, body) => {
                requests.push({ method, endpoint, body });
                if (method === 'GET') {
                    if (initialLookup) {
                        initialLookup = false;
                        throw Object.assign(new Error('Truncated response'), { code: 'GITHUB_RESPONSE_UNREADABLE' });
                    }
                    return remotePR ? [remotePR] : [];
                }
                remotePR = { number: 17, html_url: 'https://github.com/owner/repo/pull/17', head: { ref: plan.branch } };
                throw new Error('Response lost after draft creation');
            }
        });
        const input = { plan, worktreeDir: root, approvedFiles: ['source.cs'], patchDiff, runId: 'run-test', expectedHead: base,
            expectedFiles: { 'source.cs': crypto.createHash('sha256').update('fixed\n').digest('hex') }, commitTitle: 'Remediate VUL-TEST', summary: 'Verified fixture' };
        await assert.rejects(service.publish({ ...input, finalApproved: false }), /APPROVAL_MISMATCH/);
        assert.strictEqual(pushes.length, 0);
        await assert.rejects(service.publish({ ...input, finalApproved: true, patchDiff: 'changed' }), /APPROVAL_MISMATCH/);
        const result = await service.publish({ ...input, finalApproved: true });
        assert.strictEqual(requests.filter(r => r.method === 'POST').length, 1);
        assert.strictEqual(result.url, 'https://github.com/owner/repo/pull/17');
        assert.strictEqual(pushes.length, 1);
        assert(!pushes[0].args.join(' ').includes('fixture-token'));
        assert(pushes[0].env.GIT_CONFIG_VALUE_0.startsWith('AUTHORIZATION: basic '));
        assert.strictEqual(requests.find(request => request.method === 'POST').body.draft, true);
        const repeated = await service.publish({ ...input, finalApproved: true });
        assert.strictEqual(repeated.reused, true);
        assert.strictEqual(pushes.length, 1, 'Repeated publication must reuse the remote PR');
        console.log('GitHub publication: real local commit, explicit consent/diff binding, scoped branch push, verified draft URL and duplicate reuse tested with mocked remote services.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
