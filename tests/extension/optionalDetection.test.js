const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { OsvScanner } = require('../../extension/scanning/adapters/osv');
const { CandidateScanner } = require('../../extension/scanning/adapters/aiCandidate');
const { FindingsStore } = require('../../extension/scanning/findingsStore');

function fixture(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-detection-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
}
test('OSV submits only approved npm coordinates, preserves severity and discloses pagination', async (t) => {
    const dir = fixture(t);
    fs.writeFileSync(
        path.join(dir, 'package-lock.json'),
        JSON.stringify({
            packages: {
                'node_modules/lodash': {
                    version: '4.17.20',
                    resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'
                }
            }
        })
    );
    let calls = 0;
    const adapter = new OsvScanner(async (url, { body }) => {
        calls++;
        assert.equal(url.href, 'https://api.osv.dev/v1/query');
        assert.deepEqual(body, { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' });
        return { vulns: [{ id: 'GHSA-fixture' }], next_page_token: 'fixture' };
    });
    const denied = await adapter.scan(dir, dir, {});
    assert.equal(calls, 0);
    assert.equal(denied.findings.length, 0);
    const result = await adapter.scan(dir, dir, {
        scanId: 'fixture',
        approvePackages: async (ids) => ids.join() === 'lodash@4.17.20'
    });
    assert.equal(result.status, 'Partial');
    assert.equal(result.findings[0].severity, 'Unknown');
    assert.equal(result.findings[0].toCsvCompatibleRecord().Source_Origin, 'ExternalAdvisory');
    const unavailable = new OsvScanner(() => {
        throw Error('Provider HTTP 429');
    });
    assert.equal((await unavailable.scan(dir, dir, { approvePackages: () => true })).status, 'Unavailable');
    fs.unlinkSync(path.join(dir, 'package-lock.json'));
    assert.equal((await adapter.scan(dir, dir, {})).status, 'Unavailable');
});
test('AI review binds candidate evidence to the selected source and rejects stale results', async (t) => {
    const dir = fixture(t);
    const file = path.join(dir, 'example.js');
    fs.writeFileSync(file, 'element.innerHTML = input;');
    const record = {
        found: true,
        line: 1,
        cwe: 'CWE-79',
        reasoning: 'Input reaches an HTML setter.',
        limitations: 'Caller validation unknown.'
    };
    let mutate = false;
    const selectCandidateContext = () => ({
        file,
        start: 1,
        end: 1,
        provider: 'ollama',
        model: 'fixture',
        client: {
            generateJson() {
                if (mutate) fs.appendFileSync(file, '\n');
                return record;
            }
        }
    });
    const adapter = new CandidateScanner();
    const result = await adapter.scan(dir, dir, { selectCandidateContext, scanId: 'fixture' });
    const [candidate] = result.findings;
    assert.equal(candidate.classificationType, 'AI_CANDIDATE');
    assert.equal(candidate.rawSourceReference.model, 'fixture');
    assert.equal(candidate.severity, 'Unknown');
    const store = new FindingsStore(dir);
    store.ingestScanFindings([candidate, { ...candidate, scannerId: 'independent' }], 'fixture');
    assert.equal(store.loadFindings().length, 2);
    mutate = true;
    await assert.rejects(adapter.scan(dir, dir, { selectCandidateContext }), /changed/);
});
