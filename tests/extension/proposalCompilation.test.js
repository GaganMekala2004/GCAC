'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { compileProposal } = require('../../extension/proposalCompilation');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-proposal-compile-test-'));
    try {
        fs.writeFileSync(path.join(root, 'App.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
        fs.writeFileSync(path.join(root, 'Code.cs'), 'class Original {}\n');
        const patchDiff = '--- a/Code.cs\n+++ b/Code.cs\n@@ -1 +1 @@\n-class Original {}\n+class Candidate {}\n';
        const input = { repository: root, patchDiff, finding: { Vulnerability_ID: 'COMPILER-TEST', Application_Number: 'APP-1' }, runId: 'compiler-test', artifactDir: path.join(root, 'proof') };
        let calls = 0;
        const gateway = { executeOperation: async request => {
            calls++;
            assert.strictEqual(request.operation, 'DOTNET_BUILD');
            assert.strictEqual(request.networkPolicy, 'NO_NETWORK');
            assert.notStrictEqual(request.workspaceRef, root);
            assert.strictEqual(fs.readFileSync(path.join(request.workspaceRef, 'Code.cs'), 'utf8'), 'class Candidate {}\n');
            return { executed: true, exitCode: 0, stdout: 'Build succeeded.', backendType: 'fixture-container' };
        } };
        const passed = await compileProposal({ ...input, gateway });
        assert.strictEqual(passed.passed, true);
        assert.strictEqual(calls, 1);
        await assert.rejects(compileProposal({ ...input, gateway, cryptoMigrationContract: { acknowledged: true } }),
            error => error.failureCategory === 'PROPOSAL_COMPILER_UNAVAILABLE');
        assert.strictEqual(fs.readFileSync(path.join(root, 'Code.cs'), 'utf8'), 'class Original {}\n');
        await assert.rejects(compileProposal({ ...input, gateway: { executeOperation: async () => ({ executed: true, exitCode: 1,
            stdout: "Code.cs(1,1): error CS0117: 'CipherMode' does not contain a definition for 'GCM'" }) } }),
            error => error.failureCategory === 'PATCH_INVALID' && error.message.includes('CS0117'));
        await assert.rejects(compileProposal({ ...input, gateway: { executeOperation: async () => ({ executed: false, exitCode: null, reason: 'SANDBOX_UNAVAILABLE' }) } }),
            error => error.failureCategory === 'PROPOSAL_COMPILER_UNAVAILABLE');
        console.log('Proposal compilation: candidate-only sandbox build, compiler feedback, source preservation and unavailable compiler rejection verified.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
