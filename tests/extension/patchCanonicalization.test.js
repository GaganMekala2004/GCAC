'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { canonicalizeProposedPatch, applyExactPatch, patchFromExactEdits } = require('../../extension/patchApplication');
const { evaluateRemediationStrategy, inferVulnerabilityType } = require('../../extension/remediationDecisionEngine');

async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-patch-reconstruction-'));
    try {
        const target = 'src/PaymentsAPI/Controllers/PaymentController.cs';
        const source = 'using System.Data.SqlClient;\n\nnamespace PaymentsAPI.Controllers;\n\npublic class PaymentRequest\n{\n    public string AccountId { get; set; } = string.Empty;\n    public decimal Amount { get; set; }\n}\n\npublic class PaymentController\n{\n    public void Process(PaymentRequest request)\n    {\n        string query = "SELECT * FROM Payments WHERE AccountId = \'" + request.AccountId + "\' AND Amount = " + request.Amount;\n        using var cmd = new SqlCommand(query);\n    }\n}';
        fs.mkdirSync(path.dirname(path.join(root, target)), { recursive: true });
        fs.writeFileSync(path.join(root, target), source);
        const oldQuery = source.split('\n').find(line => line.includes('string query ='));
        const oldCommand = '        using var cmd = new SqlCommand(query);';
        const structured = JSON.stringify({ edits: [
            { oldText: oldQuery, newText: '        string query = "SELECT * FROM Payments WHERE AccountId = @AccountId AND Amount = @Amount";' },
            { oldText: oldCommand, newText: oldCommand + '\n        cmd.Parameters.AddWithValue("@AccountId", request.AccountId);\n        cmd.Parameters.AddWithValue("@Amount", request.Amount);' }
        ] });
        const structuredDiff = patchFromExactEdits(root, structured, target);
        assert.throws(() => patchFromExactEdits(root, JSON.stringify({ edits: [{ oldText: oldQuery,
            newText: oldQuery + '\n' + oldCommand }] }), target), /DUPLICATE_LOCAL_DECLARATION/);
        applyExactPatch(root, structuredDiff);
        const updatedSource = fs.readFileSync(path.join(root, target), 'utf8');
        assert.strictEqual(updatedSource.split(oldCommand).length - 1, 1, 'Preserve the existing command exactly once');
        fs.writeFileSync(path.join(root, target), source);
        const omittedCommand = source.slice(source.indexOf('public class PaymentController')).replace(oldCommand + '\n', '');
        assert.throws(() => patchFromExactEdits(root, JSON.stringify({ edits: [{ oldText: omittedCommand, newText: 'replacement' }] }), target), /oldText is absent/);
        assert.throws(() => patchFromExactEdits(root, JSON.stringify({ edits: [{ oldText: oldQuery, newText: 'x' }, { oldText: oldQuery, newText: 'y' }] }), target), /overlap/);
        const body = '     public void Process(PaymentRequest request)\n     {\n-        string query = "SELECT * FROM Payments WHERE AccountId = \'" + request.AccountId + "\' AND Amount = " + request.Amount;\n+        string query = "SELECT * FROM Payments WHERE AccountId = @AccountId AND Amount = @Amount";\n         using var cmd = new SqlCommand(query);\n+        cmd.Parameters.AddWithValue("@AccountId", request.AccountId);\n+        cmd.Parameters.AddWithValue("@Amount", request.Amount);\n     }\n }\n';
        const prefix = `--- a/${target}\n+++ b/${target}\n@@ -10,7 +10,7 @@\n`;
        // Reproduce all three real rejected proposals: wrong counts, wrong
        // positions, and absent EOF metadata on a source with no final newline.
        const proposals = [prefix + body, prefix + ' public class PaymentController\n {\n' + body,
            prefix + ' public class PaymentController\n {\n' + body];
        for (const proposal of proposals) {
            assert.throws(() => applyExactPatch(root, proposal, true), /MALFORMED_DIFF/);
            const canonical = canonicalizeProposedPatch(root, proposal, target);
            assert.notStrictEqual(canonical, proposal);
            applyExactPatch(root, canonical, true);
            assert.strictEqual(fs.readFileSync(path.join(root, target), 'utf8'), source, 'Proposal construction must leave source untouched');
            applyExactPatch(root, canonical);
            const actual = fs.readFileSync(path.join(root, target), 'utf8');
            assert(actual.includes('cmd.Parameters.AddWithValue("@Amount", request.Amount);'));
            assert(actual.includes('AccountId = @AccountId AND Amount = @Amount'));
            assert(!actual.endsWith('\n'), 'Preserve original EOF convention');
            fs.writeFileSync(path.join(root, target), source);
        }
        assert.throws(() => canonicalizeProposedPatch(root, proposals[0].replace('-        string query', '-        wrong query'), target), /absent/);
        assert.throws(() => canonicalizeProposedPatch(root, proposals[0] + '\n--- a/other.cs\n+++ b/other.cs\n@@ -1 +1 @@\n-old\n+new\n', target), /one unchanged target/);
        fs.writeFileSync(path.join(root, target), 'same\nsame\n');
        assert.throws(() => canonicalizeProposedPatch(root, `--- a/${target}\n+++ b/${target}\n@@ -77,99 +77,99 @@\n-same\n+new\n`, target), /ambiguous/);
        assert.throws(() => canonicalizeProposedPatch(root, `--- a/${target}\n+++ b/${target}\n@@ -77,99 +77,99 @@\n+new\n`, target), /exact source context/);
        fs.writeFileSync(path.join(root, target), 'first\r\nold\r\nlast\r\n');
        const crlf = canonicalizeProposedPatch(root, `--- a/${target}\n+++ b/${target}\n@@ -77,99 +77,99 @@\n first\n-old\n+new\n last\n`, target);
        applyExactPatch(root, crlf);
        assert.strictEqual(fs.readFileSync(path.join(root, target), 'utf8'), 'first\r\nnew\r\nlast\r\n');
        for (const [cwe, rule, expected] of [
            ['CWE-022', 'cs/path-injection', 'PATH_TRAVERSAL'],
            ['CWE-078', 'cs/command-line-injection', 'COMMAND_INJECTION']
        ]) {
            assert.strictEqual(inferVulnerabilityType({ CVE_ID: cwe }), expected);
            assert.strictEqual(inferVulnerabilityType({ Rule_ID: rule }), expected);
        }
        const cryptoDecision = evaluateRemediationStrategy({ finding: { Vulnerability_ID: 'CRYPTO', Title: 'Use of Broken Cryptographic Algorithm (DES/MD5)', Location_Path: 'src/LegacyCrypto.cs' },
            sourceCode: 'public byte[] Encrypt(byte[] data, byte[] key, byte[] iv) { using var des = DES.Create(); }' });
        assert.strictEqual(cryptoDecision.automatedExecutionAllowed, false);
        assert(cryptoDecision.blockingReason.includes('compatibility contract'));
        assert.strictEqual(cryptoDecision.manualReviewPlan.length, 5);
        assert.notStrictEqual(inferVulnerabilityType({ Title: 'Unsafe deserialization' }), 'WEAK_CRYPTO_MIGRATION', 'The substring des must not classify unrelated code as crypto');
        console.log('Exact reconstruction: all three malformed real-world proposal shapes pass Git validation; mismatches, ambiguity and out-of-scope edits remain blocked.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
