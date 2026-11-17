'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { dotnetRepairProposal } = require('../../extension/dotnetRepairRecipes');
const { patchFromExactEdits, applyExactPatch } = require('../../extension/patchApplication');
async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-recipe-tests-'));
    try {
        const sourceCode = `class C { void Process(Request request) {
        string query = "SELECT * FROM Payments WHERE AccountId = '" + request.AccountId + "' AND Amount = " + request.Amount;
        using var cmd = new SqlCommand(query);
    } }`;
        fs.writeFileSync(path.join(root, 'Code.cs'), sourceCode);
        const response = dotnetRepairProposal({ sourceCode });
        const patch = patchFromExactEdits(root, response, 'Code.cs'); applyExactPatch(root, patch);
        const updated = fs.readFileSync(path.join(root, 'Code.cs'), 'utf8');
        assert.strictEqual((updated.match(/using var cmd/g) || []).length, 1);
        assert(updated.includes('cmd.Parameters.AddWithValue("@Amount", request.Amount)'));
        const des = `public class LegacyCrypto {
    public byte[] Encrypt(byte[] data, byte[] key, byte[] iv) {
        using var des = DES.Create();
        using var encryptor = des.CreateEncryptor(key, iv);
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }
}`;
        assert.strictEqual(dotnetRepairProposal({ sourceCode: des }), null, 'Crypto migration cannot bypass contract review');
        const crypto = JSON.parse(dotnetRepairProposal({ sourceCode: des, cryptoMigrationContract: { acknowledged: true, legacyData: 'NONE' } }));
        assert(crypto.edits[0].newText.includes('new System.Security.Cryptography.AesGcm(key, 16)'));
        assert(!crypto.edits[0].newText.includes('CipherMode.GCM'));
        const receipt = '        Process.Start("cmd.exe", $"/c generate-receipt.bat {receiptId}");';
        const command = JSON.parse(dotnetRepairProposal({ sourceCode: receipt })).edits[0];
        assert(command.newText.includes('@"\\A[A-Za-z0-9_-]{1,64}\\z"'));
        assert(command.newText.includes('ArgumentList.Add(receiptId)'));
        assert(!command.newText.includes('SanitizeReceiptId'));
        assert.strictEqual(dotnetRepairProposal({ sourceCode: 'Process.Start(command, input);' }), null);
        console.log('Verified .NET recipes: exact SQL binding, consent-bound AES-GCM and validated batch arguments; unrecognized source remains unsupported.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
