using System.Numerics;
using Nine.Tests.Support;
using Nine.Tokens;

namespace Nine.Tests;

/// <summary>The managed Ed25519 verifier against RFC 8032 §7.1 and the edge cases a verifier must refuse.</summary>
public class Ed25519Tests
{
    public static TheoryData<string, string, string, string> Rfc8032 => new()
    {
        // TEST 1, 2, 3 and SHA(abc) of RFC 8032 §7.1: secret key, public key, message, signature.
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        },
        {
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        },
    };

    [Theory]
    [MemberData(nameof(Rfc8032))]
    public void VerifiesTheRfc8032Vectors(string secret, string publicKey, string message, string signature)
    {
        var pk = Convert.FromHexString(publicKey);
        var msg = Convert.FromHexString(message);
        var sig = Convert.FromHexString(signature);
        Assert.True(Ed25519.Verify(pk, msg, sig));
        // The test signer derives the same public key and signature (Ed25519 is deterministic).
        Assert.Equal(pk, Ed25519Signer.PublicKey(Convert.FromHexString(secret)));
        Assert.Equal(sig, Ed25519Signer.Sign(Convert.FromHexString(secret), msg));
    }

    [Theory]
    [MemberData(nameof(Rfc8032))]
    public void RefusesAlteredMessagesAndSignatures(string secret, string publicKey, string message, string signature)
    {
        _ = secret;
        var pk = Convert.FromHexString(publicKey);
        var msg = Convert.FromHexString(message);
        var sig = Convert.FromHexString(signature);
        Assert.False(Ed25519.Verify(pk, [.. msg, 0], sig));
        for (var i = 0; i < 64; i += 7)
        {
            var bad = (byte[])sig.Clone();
            bad[i] ^= 0x01;
            Assert.False(Ed25519.Verify(pk, msg, bad), $"flipped byte {i}");
        }
        var otherKey = (byte[])pk.Clone();
        otherKey[0] ^= 0x01;
        Assert.False(Ed25519.Verify(otherKey, msg, sig));
    }

    [Fact]
    public void RefusesANonReducedS()
    {
        // S + L verifies the same group equation; RFC 8032 requires S < L (no malleable signatures).
        var pk = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        var sig = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        var s = new BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: false) + Ed25519.L;
        var malleable = (byte[])sig.Clone();
        Array.Clear(malleable, 32, 32);
        s.TryWriteBytes(malleable.AsSpan(32), out _, isUnsigned: true, isBigEndian: false);
        Assert.False(Ed25519.Verify(pk, [], malleable));
    }

    [Fact]
    public void RefusesNonCanonicalAndInvalidPublicKeys()
    {
        // y = p (encoded): not canonical.
        var p = new byte[32];
        Ed25519.P.TryWriteBytes(p, out _, isUnsigned: true, isBigEndian: false);
        Assert.Null(Ed25519.Decode(p));
        // A y with no matching x on the curve.
        var y = BigInteger.One;
        byte[] invalid;
        do
        {
            y += 1;
            invalid = new byte[32];
            y.TryWriteBytes(invalid, out _, isUnsigned: true, isBigEndian: false);
        }
        while (Ed25519.Decode(invalid) is not null);
        Assert.False(Ed25519.Verify(invalid, [], new byte[64]));
        // Wrong lengths.
        Assert.False(Ed25519.Verify(new byte[31], [], new byte[64]));
        Assert.False(Ed25519.Verify(new byte[32], [], new byte[63]));
    }

    [Fact]
    public void RefusesANonCanonicalR()
    {
        // With the identity point as public key and S = 0, R' = [0]B - [k]A is the identity, whose
        // canonical encoding is y = 1. The same point encoded as y = p + 1 must be refused: R is
        // compared as canonical bytes, not decoded leniently.
        var identity = new byte[32];
        identity[0] = 1;
        var nonCanonical = new byte[32];
        (Ed25519.P + 1).TryWriteBytes(nonCanonical, out _, isUnsigned: true, isBigEndian: false);
        Assert.True(Ed25519.Verify(identity, "m"u8, [.. identity, .. new byte[32]]));
        Assert.False(Ed25519.Verify(identity, "m"u8, [.. nonCanonical, .. new byte[32]]));
    }

    [Fact]
    public void RoundTripsRandomKeysAndMessages()
    {
        var random = new Random(8032);
        for (var i = 0; i < 20; i++)
        {
            var seed = new byte[32];
            random.NextBytes(seed);
            var message = new byte[random.Next(0, 300)];
            random.NextBytes(message);
            var signature = Ed25519Signer.Sign(seed, message);
            Assert.True(Ed25519.Verify(Ed25519Signer.PublicKey(seed), message, signature));
        }
    }
}
