'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WorkspaceStagingManager } = require('../../extension/sandbox/workspaceStaging');
const { parseDotnetOutput, aggregateTrxReports, executeRealTestRunner } = require('../../extension/testRunner');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-baseline-regression-'));
    try {
        const source = path.join(root, 'source');
        const obj = path.join(source, 'tests', 'obj');
        fs.mkdirSync(obj, { recursive: true });
        const oldRoot = '/disposable/scanner/packages/';
        const assets = JSON.stringify({ packageFolders: { [oldRoot]: {} }, libraries: {} });
        fs.writeFileSync(path.join(obj, 'project.assets.json'), assets);
        fs.writeFileSync(path.join(obj, 'Tests.csproj.nuget.g.props'), `<Project><NuGetPackageRoot>${oldRoot}</NuGetPackageRoot><Import Project="${oldRoot}microsoft.net.test.sdk/17.11.1/test.props" /></Project>`);
        fs.writeFileSync(path.join(obj, 'untrusted.dll'), 'exclude');
        const staged = new WorkspaceStagingManager({ stagingRoot: path.join(root, 'staged') }).stageWorkspace({ instanceId: 'instance-baseline', runId: 'baseline-regression', sourceRoot: source });
        const stagedObj = path.join(staged.workDir, 'tests', 'obj');
        assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(stagedObj, 'project.assets.json'))).packageFolders, { '/sandbox-cache/nuget/': {} });
        const props = fs.readFileSync(path.join(stagedObj, 'Tests.csproj.nuget.g.props'), 'utf8');
        assert(props.includes('/sandbox-cache/nuget/microsoft.net.test.sdk/'));
        assert(!props.includes(oldRoot));
        assert(!fs.existsSync(path.join(stagedObj, 'untrusted.dll')));
        assert.strictEqual(fs.readFileSync(path.join(obj, 'project.assets.json'), 'utf8'), assets);
        const failure = parseDotnetOutput('error NETSDK1064: Package xunit.analyzers, version 1.16.0 was not found.\nBuild FAILED.', '', 1);
        assert.strictEqual(failure.failureCategory, 'RESTORE_FAILED');
        assert(failure.rootError.includes('NETSDK1064'));
        const report = '<TestRun><ResultSummary outcome="Completed"><Counters total="1" executed="1" passed="1" failed="0" notExecuted="0" /></ResultSummary></TestRun>';
        assert.strictEqual(aggregateTrxReports([report, report]).testsTotal, 2);
        assert.strictEqual(aggregateTrxReports([report, '<TestRun>']).valid, false);
        fs.mkdirSync(path.join(source, 'TestResults'));
        fs.writeFileSync(path.join(source, 'TestResults', 'stale.trx'), report);
        const result = await executeRealTestRunner('dotnet', ['test', '-v', 'normal', '--logger', 'trx'], source, {
            toolchainProfileId: 'unit-test-profile',
            executionGateway: { executeOperation: async request => {
                assert(!request.extraArgs.includes('-v'), 'Toolchain already supplies dotnet test verbosity');
                return { executed: true, exitCode: 0, stdout: '', stderr: '', outputArtifacts: {} };
            } }
        });
        assert.strictEqual(result.machineStatus, 'UNTESTED', 'Prior workspace TRX must never certify the current run');
        assert.strictEqual(result.testReportLocation, null);
        console.log('Baseline staging: stale scanner paths rebased; originals preserved; missing cache diagnosed.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(e => { console.error(e); process.exitCode = 1; });
