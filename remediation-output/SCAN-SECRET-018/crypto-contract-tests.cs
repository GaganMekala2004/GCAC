using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
public class GcacReviewedCryptoContractTests {
    static byte[] Encrypt(out byte[] key, out byte[] nonce, out byte[] data) {
        key = RandomNumberGenerator.GetBytes(32); nonce = RandomNumberGenerator.GetBytes(12);
        data = Encoding.UTF8.GetBytes("GCAC authenticated-encryption contract");
        return new global::PaymentsAPI.LegacyCrypto().Encrypt(data, key, nonce);
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
        var cipher = new global::PaymentsAPI.LegacyCrypto(); var data = Encoding.UTF8.GetBytes("test");
        Assert.NotNull(Record.Exception(() => cipher.Encrypt(data, new byte[8], new byte[12])));
        Assert.NotNull(Record.Exception(() => cipher.Encrypt(data, new byte[32], new byte[8])));
    }
}