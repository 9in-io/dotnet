using System.Numerics;
using System.Security.Cryptography;
using Nine.Tokens;

namespace Nine.Tests.Support;

/// <summary>Ed25519 signing for tests (RFC 8032 §5.1.6), on the SDK's point arithmetic. Not constant-time: tests only.</summary>
public static class Ed25519Signer
{
    public static byte[] PublicKey(byte[] seed)
    {
        var (a, _) = Expand(seed);
        return Ed25519.Encode(Ed25519.Multiply(a, Ed25519.B));
    }

    public static byte[] Sign(byte[] seed, byte[] message)
    {
        var (a, prefix) = Expand(seed);
        var publicKey = Ed25519.Encode(Ed25519.Multiply(a, Ed25519.B));
        var r = Scalar(SHA512.HashData([.. prefix, .. message]));
        var rPoint = Ed25519.Encode(Ed25519.Multiply(r, Ed25519.B));
        var k = Scalar(SHA512.HashData([.. rPoint, .. publicKey, .. message]));
        var s = (r + k * a) % Ed25519.L;
        var sBytes = new byte[32];
        s.TryWriteBytes(sBytes, out _, isUnsigned: true, isBigEndian: false);
        return [.. rPoint, .. sBytes];
    }

    private static (BigInteger A, byte[] Prefix) Expand(byte[] seed)
    {
        var h = SHA512.HashData(seed);
        var a = h[..32];
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        return (new BigInteger(a, isUnsigned: true, isBigEndian: false), h[32..]);
    }

    private static BigInteger Scalar(byte[] hash) => new BigInteger(hash, isUnsigned: true, isBigEndian: false) % Ed25519.L;
}
