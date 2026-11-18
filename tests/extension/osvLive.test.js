const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { OsvScanner } = require('../../extension/scanning/adapters/osv');

test('OSV identifies published advisories for a public lockfile fixture', {skip:process.env.GCAC_TEST_OSV !== '1'}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-osv-live-'));
    t.after(() => fs.rmSync(root,{recursive:true,force:true}));
    fs.writeFileSync(path.join(root,'package-lock.json'),JSON.stringify({packages:{
        'node_modules/lodash': {version:'4.17.20',resolved:'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'}
    }}));
    const result = await new OsvScanner().scan(root,root,{scanId:'public-fixture',approvePackages: async items => items.join() === 'lodash@4.17.20'});
    assert.equal(result.status,'Completed',result.errors.join(', '));
    assert(result.findings.length > 0);
    assert(result.findings.every(f => f.scannerId === 'osv' && f.scanId === 'public-fixture' && f.ruleId && f.currentVersion === '4.17.20'));
    console.log('Normalized OSV findings',result.findings.length);
});
