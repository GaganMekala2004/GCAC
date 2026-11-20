'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { extractProposedPatch, applyExactPatch } = require('../../extension/patchApplication');
const { formatTerminalConclusionMarkdown } = require('../../extension/copilotOutputFormatter');
const { normalizeCanonicalRunState } = require('../../extension/runStateContract');
const { refreshSnapshot, readSnapshot, inRange, compareVersions } = require('../../extension/scanning/nugetAdvisories');
const { auditResolvedProjects } = require('../../extension/scanning/nugetOfflineAudit');
const { NuGetAuditScanner } = require('../../extension/scanning/adapters/nugetAuditScanner');
const { CodeQLScanner } = require('../../extension/scanning/adapters/codeqlScanner');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-reliability-'));
    try {
        execFileSync('git', ['init', root], { stdio: 'ignore' });
        fs.writeFileSync(path.join(root, 'source.cs'), 'first\n\nvulnerable\nlast\n');
        const patch = '--- a/source.cs\n+++ b/source.cs\n@@ -1,4 +1,4 @@\n first\n \n-vulnerable\n+fixed\n last\n';
        const extracted = extractProposedPatch(`Proposal:\n${patch}SUMMARY: done`);
        assert.strictEqual(extracted, patch);
        applyExactPatch(root, extracted, true);
        assert.strictEqual(extractProposedPatch('```diff\n' + patch + '```'), patch);
        const malformed = patch.replace('@@ -1,4 +1,4 @@', '@@ -1,99 +1,99 @@');
        assert.throws(() => applyExactPatch(root, malformed, true), error => error.failureCategory === 'PATCH_INVALID' && error.patchDiagnostic.reasonCode === 'MALFORMED_DIFF');
        assert.throws(() => applyExactPatch(root, patch.replace('-vulnerable', '-different'), true), error => error.patchDiagnostic.reasonCode === 'SOURCE_MISMATCH');
        assert(!fs.readFileSync(path.join(root, 'source.cs'), 'utf8').includes('fixed'));
        const manual = { status: 'MANUAL_REVIEW', isManualReview: true, remediationDecision: { blockingReason: 'Crypto migration requires review.' } };
        const rendered = formatTerminalConclusionMarkdown('TEST', manual);
        assert(rendered.includes('Crypto migration requires review.'));
        assert(rendered.includes('NOT_EXECUTED'));
        assert(!rendered.includes('Validation Failed'));
        const state = normalizeCanonicalRunState(manual, 'TEST');
        assert.strictEqual(state.workflowLifecycle, 'BLOCKED');
        assert.strictEqual(state.securityValidationOutcome, 'NOT_EXECUTED');
        assert.strictEqual(state.approvalDecision, 'NOT_REQUESTED');
        assert(state.terminalBanner.includes('Manual'));
        assert(!formatTerminalConclusionMarkdown('TEST', { status: 'BLOCKED', failureCategory: 'NO_TESTS_DISCOVERED' }).includes('Toolchain Image Unavailable'));
        assert(inRange('1.2.0', '[1.0.0, 2.0.0)'));
        assert(!inRange('2.0.0', '[1.0.0, 2.0.0)'));
        assert(inRange('1.0.0-beta.2', '(,1.0.0)'));
        assert(inRange('1.0.0.1', '[1.0.0.1]'));
        assert.strictEqual(compareVersions('1.0', '1.0.0.0'), 0);
        assert(compareVersions('1.0.0-beta.10', '1.0.0-beta.2') > 0);
        assert.throws(() => inRange('1.0', '1.*'), /Unsupported/);
        const snapshotFile = path.join(root, 'snapshot.json');
        const pages = [{ '@id': 'https://api.nuget.org/base' }, { '@id': 'https://api.nuget.org/update' }];
        const advisory = { severity: 2, url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', versions: '(,2.0.0)' };
        await refreshSnapshot(snapshotFile, async url => url.endsWith('index.json') ? { resources: [{ '@type': 'VulnerabilityInfo/6.7.0', '@id': 'https://api.nuget.org/pages' }] }
            : url.endsWith('/pages') ? pages : url.endsWith('/base') ? { example: [advisory] } : []);
        const snapshot = readSnapshot(snapshotFile);
        const before = fs.readFileSync(snapshotFile, 'utf8');
        await assert.rejects(refreshSnapshot(snapshotFile, async () => { throw new Error('offline'); }), /offline/);
        assert.strictEqual(fs.readFileSync(snapshotFile, 'utf8'), before);
        assert.throws(() => readSnapshot(snapshotFile, Date.now() + 25 * 3600000), /older/);
        const project = path.join(root, 'App.csproj');
        fs.writeFileSync(project, '<Project><ItemGroup><PackageReference Include="Example" Version="1.0.0" /></ItemGroup></Project>');
        fs.mkdirSync(path.join(root, 'obj'));
        const assetsPath = path.join(root, 'obj', 'project.assets.json');
        fs.writeFileSync(assetsPath, JSON.stringify({ targets: { net10: { 'Example/1.0.0': { type: 'package' } } }, libraries: { 'Example/1.0.0': { type: 'package' } }, project: { frameworks: { net10: { dependencies: { Example: { version: '[1.0.0, )' } } } } } }));
        const cacheRoot = path.join(root, 'cache');
        const candidate = path.join(cacheRoot, 'example', '2.0.0');
        fs.mkdirSync(candidate, { recursive: true });
        fs.writeFileSync(path.join(candidate, '.nupkg.metadata'), JSON.stringify({
            source: 'https://api.nuget.org/v3/index.json', contentHash: 'fixture'
        }));
        fs.writeFileSync(path.join(candidate, 'example.2.0.0.nupkg'), 'fixture');
        const audited = auditResolvedProjects(root, snapshot, null, cacheRoot);
        assert.strictEqual(audited.projects[0].frameworks[0].topLevelPackages[0].fixedVersion, '2.0.0');
        const unsafe = auditResolvedProjects(root, { ...snapshot, packages: { example: [advisory,
            { ...advisory, versions: '[2.0.0]' }] } }, null, cacheRoot);
        assert.strictEqual(unsafe.projects[0].frameworks[0].topLevelPackages[0].fixedVersion, '');
        assert.strictEqual(audited.projects.length, 1);
        assert.strictEqual(audited.packagesChecked, 1);
        const scanner = new NuGetAuditScanner();
        const findings = scanner.parseJsonAuditOutput(audited, project, root, 'TEST');
        assert.strictEqual(findings.length, 1);
        const partial = scanner.parseAuditOutput('Project has the following vulnerable packages\n > Example 1.0.0 High https://github.com/advisories/GHSA-aaaa-bbbb-cccc', 'warning NU1900: feed unavailable', project, root, 'TEST');
        assert(partial.inaccessible);
        assert.strictEqual(partial.findings.length, 1, 'Retain genuine transitive findings even when feed coverage is incomplete');
        fs.writeFileSync(project, '<Project><PackageReference Include="Example" Version="3.0.0" /></Project>');
        assert.throws(() => auditResolvedProjects(root, snapshot), /differ|predates/);
        const codeql = new CodeQLScanner();
        codeql.isAvailable = async () => ({ available: true, binaryPath: 'codeql' });
        const calls = [];
        codeql._execCodeqlAsync = async (bin, args, options) => {
            calls.push({ args, options });
            const stagedRoot = args.find(arg => arg.startsWith('--source-root='))?.slice('--source-root='.length);
            if (stagedRoot) {
                assert.notStrictEqual(stagedRoot, root);
                fs.writeFileSync(path.join(stagedRoot, 'source.cs'), 'extractor-generated change');
            }
            const output = args.find(arg => arg.startsWith('--output='));
            if (output) fs.writeFileSync(output.slice('--output='.length), JSON.stringify({ runs: [{ results: [] }] }));
        };
        const result = await codeql.scan(root, root, { scanId: 'TEST' });
        assert.strictEqual(result.errors.length, 0);
        assert.strictEqual(calls.length, 3);
        assert(calls.every(call => call.options.timeout === 900000));
        assert.strictEqual(fs.readFileSync(path.join(root, 'source.cs'), 'utf8'), 'first\n\nvulnerable\nlast\n');
        const mapped = codeql.parseSarif({ runs: [{ results: [{ ruleId: 'cs/test', message: { text: 'test' }, locations: [{ physicalLocation: {
            artifactLocation: { uri: '/temporary/staged/Source.cs' }, region: { startLine: 1 }
        } }] }] }] }, '/original/repo', 'TEST', { sourceRoot: '/temporary/staged', sourcePathPrefix: 'src/API', repositoryRoot: '/original/repo' });
        assert.strictEqual(mapped[0].filePath, 'src/API/Source.cs');
        codeql._execCodeqlAsync = async (bin, args) => {
            const output = args.find(arg => arg.startsWith('--output='));
            if (output) fs.writeFileSync(output.slice('--output='.length), '{bad json');
        };
        const broken = await codeql.scan(root, root, { scanId: 'TEST' });
        assert(broken.errors.length > 0);
        assert(!broken.coverage.startsWith('100%'));
        const timeoutScanner = new CodeQLScanner();
        const timeoutStarted = Date.now();
        await assert.rejects(timeoutScanner._execCodeqlAsync(process.execPath, ['-e',
            'require("child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:["ignore","ignore","inherit"]});setInterval(()=>{},1000)'
        ], { timeout: 100 }), /ETIMEDOUT/);
        assert(Date.now() - timeoutStarted < 5000, 'Timeout must terminate descendants holding the output pipe');
        console.log('Remediation reliability: exact patches, honest manual review, fresh offline NuGet intelligence, partial findings, and CodeQL execution verified.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
