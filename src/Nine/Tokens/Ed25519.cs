using System.Collections.Concurrent;
using System.Numerics;
using System.Security.Cryptography;

namespace Nine.Tokens;

/// <summary>
/// Ed25519 signature verification (RFC 8032 §5.1.7) in managed code, because the .NET base class
/// library has no Ed25519. Verification only: it handles nothing secret (public key, message and
/// signature are all public), so it doesn't need to run in constant time, and it uses
/// <see cref="BigInteger"/> arithmetic for clarity over speed. Strict: a non-canonical public key
/// or <c>R</c> encoding, or <c>S ≥ L</c>, is refused. Tested against the RFC 8032 vectors and
/// WebCrypto-signed tokens.
/// </summary>
internal static class Ed25519
{
    internal static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    internal static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);
    private static readonly BigInteger D = Mod(-121665 * Inverse(121666));
    private static readonly BigInteger D2 = Mod(2 * D);
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
    internal static readonly Point B = BasePoint();

    private static readonly ConcurrentDictionary<string, Point> PublicKeys = new(StringComparer.Ordinal);

    /// <summary>A point in extended coordinates: x = X/Z, y = Y/Z, x·y = T/Z.</summary>
    internal readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)
    {
        public static readonly Point Identity = new(0, 1, 1, 0);

        public Point Negate() => new(Mod(-X), Y, Z, Mod(-T));
    }

    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
        {
            return false;
        }
        var s = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: false);
        if (s >= L)
        {
            return false; // malleability: S must be reduced (RFC 8032 §5.1.7 step 1)
        }
        var cacheKey = Convert.ToBase64String(publicKey);
        if (!PublicKeys.TryGetValue(cacheKey, out var a))
        {
            if (Decode(publicKey) is not { } decoded)
            {
                return false;
            }
            if (PublicKeys.Count > 256)
            {
                PublicKeys.Clear();
            }
            a = PublicKeys[cacheKey] = decoded;
        }
        var buffer = new byte[64 + message.Length];
        signature[..32].CopyTo(buffer);
        publicKey.CopyTo(buffer.AsSpan(32));
        message.CopyTo(buffer.AsSpan(64));
        var k = new BigInteger(SHA512.HashData(buffer), isUnsigned: true, isBigEndian: false) % L;

        // R' = [S]B - [k]A, then compare its canonical encoding with R. That's the cofactorless
        // check [S]B = R + [k]A, and it refuses any R that isn't a canonical point encoding.
        var expected = Encode(DoubleScalarMultiply(s, B, k, a.Negate()));
        return CryptographicOperations.FixedTimeEquals(expected, signature[..32]);
    }

    /// <summary>[s]P + [k]Q with one shared doubling chain (Straus–Shamir).</summary>
    internal static Point DoubleScalarMultiply(BigInteger s, Point p, BigInteger k, Point q)
    {
        var both = Add(p, q);
        var result = Point.Identity;
        var bits = (int)Math.Max(s.GetBitLength(), k.GetBitLength());
        for (var i = bits - 1; i >= 0; i--)
        {
            result = Double(result);
            var sBit = !(s >> i).IsEven;
            var kBit = !(k >> i).IsEven;
            if (sBit && kBit)
            {
                result = Add(result, both);
            }
            else if (sBit)
            {
                result = Add(result, p);
            }
            else if (kBit)
            {
                result = Add(result, q);
            }
        }
        return result;
    }

    internal static Point Multiply(BigInteger scalar, Point point) => DoubleScalarMultiply(scalar, point, BigInteger.Zero, Point.Identity);

    // RFC 8032 §5.1.4, a = -1.
    internal static Point Add(Point p, Point q)
    {
        var a = Mod((p.Y - p.X) * (q.Y - q.X));
        var b = Mod((p.Y + p.X) * (q.Y + q.X));
        var c = Mod(p.T * D2 % P * q.T);
        var d = Mod(2 * p.Z * q.Z);
        var e = b - a;
        var f = d - c;
        var g = d + c;
        var h = b + a;
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    internal static Point Double(Point p)
    {
        var a = Mod(p.X * p.X);
        var b = Mod(p.Y * p.Y);
        var c = Mod(2 * p.Z * p.Z);
        var h = a + b;
        var sum = p.X + p.Y;
        var e = h - Mod(sum * sum);
        var g = a - b;
        var f = c + g;
        return new Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    internal static byte[] Encode(Point p)
    {
        var zInverse = Inverse(p.Z);
        var x = Mod(p.X * zInverse);
        var y = Mod(p.Y * zInverse);
        var bytes = new byte[32];
        y.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false);
        if (!x.IsEven)
        {
            bytes[31] |= 0x80;
        }
        return bytes;
    }

    /// <summary>RFC 8032 §5.1.3. Null for a non-canonical or invalid encoding.</summary>
    internal static Point? Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 32)
        {
            return null;
        }
        Span<byte> copy = stackalloc byte[32];
        encoded.CopyTo(copy);
        var sign = copy[31] >> 7;
        copy[31] &= 0x7f;
        var y = new BigInteger(copy, isUnsigned: true, isBigEndian: false);
        if (y >= P)
        {
            return null;
        }
        var y2 = Mod(y * y);
        var u = Mod(y2 - 1);
        var v = Mod(D * y2 + 1);
        var v3 = Mod(v * v % P * v);
        var x = Mod(u * v3 % P * BigInteger.ModPow(Mod(u * v3 % P * v3 % P * v), (P - 5) / 8, P));
        var vx2 = Mod(v * x % P * x);
        if (vx2 == u)
        {
            // x is a square root
        }
        else if (vx2 == Mod(-u))
        {
            x = Mod(x * SqrtM1);
        }
        else
        {
            return null;
        }
        if (x.IsZero && sign == 1)
        {
            return null;
        }
        if ((int)(x % 2) != sign)
        {
            x = P - x;
        }
        return new Point(x, y, 1, Mod(x * y));
    }

    internal static BigInteger Mod(BigInteger value)
    {
        var r = value % P;
        return r.Sign < 0 ? r + P : r;
    }

    private static BigInteger Inverse(BigInteger value) => BigInteger.ModPow(Mod(value), P - 2, P);

    private static Point BasePoint()
    {
        var y = Mod(4 * Inverse(5));
        Span<byte> encoded = stackalloc byte[32];
        y.TryWriteBytes(encoded, out _, isUnsigned: true, isBigEndian: false);
        return Decode(encoded) ?? throw new InvalidOperationException("Ed25519 base point");
    }
}
