using System.Security.Cryptography;
using PaymentsAPI;
using Xunit;

namespace PaymentsAPI.Tests;

public class LegacyCryptoSecurityTests
{
    [Fact]
    public void EncryptionSupportsAes256AndAuthenticatedRoundTrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        byte[] input = [1, 2, 3, 4, 5];
        var encrypted = new LegacyCrypto().Encrypt(input, key, nonce);
        Assert.Equal(input.Length + 16, encrypted.Length);
        var plaintext = new byte[input.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, encrypted.AsSpan(0, input.Length), encrypted.AsSpan(input.Length, 16), plaintext);
        Assert.Equal(input, plaintext);
    }

    [Fact]
    public void ModifiedCiphertextFailsAuthentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        byte[] input = [1, 2, 3];
        var encrypted = new LegacyCrypto().Encrypt(input, key, nonce);
        encrypted[0] ^= 1;
        using var aes = new AesGcm(key, 16);
        Assert.Throws<AuthenticationTagMismatchException>(() => aes.Decrypt(nonce,
            encrypted.AsSpan(0, input.Length), encrypted.AsSpan(input.Length, 16), new byte[input.Length]));
    }
}
