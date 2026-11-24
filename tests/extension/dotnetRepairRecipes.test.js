'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { dotnetRepairProposal, nugetRepairProposal } = require('../../extension/dotnetRepairRecipes');
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
        const pingSource = String.raw`        process.StartInfo.FileName = "sh";
        process.StartInfo.Arguments = "-c \"ping -c 1 " + host + "\"";`;
        const ping = JSON.parse(dotnetRepairProposal({ sourceCode: pingSource })).edits[0];
        assert(pingSource.includes(ping.oldText));
        assert(ping.newText.includes('StartInfo.ArgumentList.Add(host)'));
        assert(ping.newText.includes('StartInfo.FileName = "ping"'));
        assert(ping.newText.split('\n').length > 1);
        const receipt = '        Process.Start("cmd.exe", $"/c generate-receipt.bat {receiptId}");';
        const command = JSON.parse(dotnetRepairProposal({ sourceCode: receipt })).edits[0];
        assert(command.newText.includes('@"\\A[A-Za-z0-9_-]{1,64}\\z"'));
        assert(command.newText.includes('ArgumentList.Add(receiptId)'));
        assert(!command.newText.includes('SanitizeReceiptId'));
        assert.strictEqual(dotnetRepairProposal({ sourceCode: 'Process.Start(command, input);' }), null);
        for (const eol of ['\n', '\r\n']) {
            const comment = '    <!-- <PackageReference Include="SQLitePCLRaw.lib.e_sqlite3" Version="1.0.0" /> -->';
            const sourceCode = ['<Project Sdk="Microsoft.NET.Sdk">', '  <PropertyGroup>', '    <TargetFramework>net9.0</TargetFramework>', '  </PropertyGroup>', '  <ItemGroup>', comment, '    <ProjectReference Include="../../src/App.csproj" />', '  </ItemGroup>', '</Project>'].join(eol);
            const args = { sourceCode, packageName: 'SQLitePCLRaw.lib.e_sqlite3', currentVersion: '2.1.10', upgrade: { version: '2.1.13', transitive: true } };
            fs.writeFileSync(path.join(root, 'Test.csproj'), sourceCode);
            const proposal = nugetRepairProposal(args);
            const patch = patchFromExactEdits(root, proposal, 'Test.csproj');
            applyExactPatch(root, patch);
            const updated = fs.readFileSync(path.join(root, 'Test.csproj'), 'utf8');
            assert(updated.includes('<PackageReference Include="SQLitePCLRaw.lib.e_sqlite3" Version="2.1.13" />'));
            assert(updated.includes('<ProjectReference Include="../../src/App.csproj" />'));
            assert(updated.includes(comment));
            if (eol === '\r\n') assert(!updated.replace(/\r\n/g, '').includes('\n'));
            assert.strictEqual(nugetRepairProposal({ ...args, upgrade: null }), null);
            assert.strictEqual(nugetRepairProposal({ ...args, sourceCode: updated }), null);
            const direct = { ...args, sourceCode: '<Project><PackageReference Include="SQLitePCLRaw.lib.e_sqlite3" Version="2.1.10" /></Project>', upgrade: { version: '2.1.13', transitive: false } };
            assert(JSON.parse(nugetRepairProposal(direct)).edits[0].newText.includes('Version="2.1.13"'));
            assert.strictEqual(nugetRepairProposal({ ...direct, currentVersion: '1.0.0' }), null);
            assert.strictEqual(nugetRepairProposal({ ...args, sourceCode: sourceCode.replace('<PropertyGroup>', '<PropertyGroup Condition="x">') }), null);
        }
        console.log('Verified .NET recipes: exact SQL binding, consent-bound AES-GCM and validated batch arguments; unrecognized source remains unsupported.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
