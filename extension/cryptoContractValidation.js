'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { inspectDotnetProjects } = require('./testRunner');
async function validateCryptoContract({ repository, targetRelPath, finding, runTests, testOptions, artifactDir, minimumTests = 3 }) {
    const unavailable = reason => ({ executed: false, passed: false, machineStatus: 'UNTESTED', status: 'UNTESTED',
        countsKnown: false, testsTotal: 0, testsPassed: 0, testsFailed: 0, exitCode: null,
        failureCategory: 'CRYPTO_CONTRACT_TESTS_UNAVAILABLE', summary: reason, rootError: reason });
    const target = typeof targetRelPath === 'string' ? path.resolve(repository, targetRelPath) : '';
    if (!target.startsWith(path.resolve(repository) + path.sep)) return unavailable('Crypto contract target is outside the candidate repository.');
    const source = fs.readFileSync(target, 'utf8');
    const namespace = source.match(/\bnamespace\s+([A-Za-z_][\w.]*)/)?.[1];
    const type = source.match(/\bpublic\s+(?:sealed\s+)?class\s+([A-Za-z_]\w*)/)?.[1];
    const testProject = inspectDotnetProjects(repository).testProjects.find(project => /\bxunit\b/i.test(fs.readFileSync(path.join(repository, project), 'utf8')));
    if (!type || !testProject) return unavailable('Reviewed crypto migration requires an accessible public class and an xUnit test project for contract validation.');
    const className = `global::${namespace ? namespace + '.' : ''}${type}`;
    const harness = `using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
public class GcacReviewedCryptoContractTests {
    static byte[] Encrypt(out byte[] key, out byte[] nonce, out byte[] data) {
        key = RandomNumberGenerator.GetBytes(32); nonce = RandomNumberGenerator.GetBytes(12);
        data = Encoding.UTF8.GetBytes("GCAC authenticated-encryption contract");
        return new ${className}().Encrypt(data, key, nonce);
    }
    [Fact] public void Contract_RoundTripAndVersionedEnvelope() {
        var payload = Encrypt(out var key, out var nonce, out var data);
        Assert.Equal(29 + data.Length, payload.Length); Assert.Equal((byte)1, payload[0]);
        Assert.Equal(nonce, payload[1..13]);
        var restored = new byte[data.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(payload[1..13], payload[29..], payload[13..29], restored);
        Assert.Equal(data, restored);
    }
    [Fact] public void Contract_TamperingAndWrongKeyRejected() {
        var payload = Encrypt(out var key, out var nonce, out var data);
        using var aes = new AesGcm(key, 16); var restored = new byte[data.Length];
        payload[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => aes.Decrypt(payload[1..13], payload[29..], payload[13..29], restored));
        payload[^1] ^= 1;
        using var wrong = new AesGcm(RandomNumberGenerator.GetBytes(32), 16);
        Assert.ThrowsAny<CryptographicException>(() => wrong.Decrypt(payload[1..13], payload[29..], payload[13..29], restored));
    }
    [Fact] public void Contract_InvalidKeyAndNonceRejected() {
        var cipher = new ${className}(); var data = Encoding.UTF8.GetBytes("test");
        Assert.NotNull(Record.Exception(() => cipher.Encrypt(data, new byte[8], new byte[12])));
        Assert.NotNull(Record.Exception(() => cipher.Encrypt(data, new byte[32], new byte[8])));
    }
}`;
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-crypto-contract-'));
    try {
        fs.cpSync(repository, temp, { recursive: true, filter: source => !fs.lstatSync(source).isSymbolicLink() && !['.git', 'bin', 'TestResults'].includes(path.basename(source)) });
        fs.writeFileSync(path.join(temp, path.dirname(testProject), 'GcacReviewedCryptoContractTests.cs'), harness);
        fs.mkdirSync(artifactDir, { recursive: true });
        fs.writeFileSync(path.join(artifactDir, 'crypto-contract-tests.cs'), harness);
        const result = await runTests({ ...finding, Repository_Root: temp }, temp, { ...testOptions, workingDirectory: temp });
        // A passing old smoke suite alone cannot satisfy this contract.
        if (result.passed && (!result.countsKnown || result.testsTotal < minimumTests)) return unavailable('Crypto contract tests were not discovered; no verified crypto migration can be claimed.');
        const evidence = { ...result, cryptoContractValidation: { harness: 'crypto-contract-tests.cs', algorithm: 'AES-256-GCM',
            payload: 'VERSION1_NONCE12_TAG16_CIPHERTEXT', realExecution: result.executed === true } };
        fs.writeFileSync(path.join(artifactDir, 'crypto-contract-validation.json'), JSON.stringify(evidence, null, 2));
        return evidence;
    } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
module.exports = { validateCryptoContract };
