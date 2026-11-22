using System.Security.Cryptography;
using System.Text;

namespace Nine.Tokens;

/// <summary>Signature checks for every JWS algorithm 9in signs with.</summary>
internal static class Jws
{
    public static readonly IReadOnlySet<string> Asymmetric = new HashSet<string>(StringComparer.Ordinal)
    {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
    };

    public static readonly IReadOnlySet<string> Hmac = new HashSet<string>(StringComparer.Ordinal) { "HS256", "HS384", "HS512" };

    private static HashAlgorithmName Hash(string alg) => alg[2..] switch
    {
        "256" => HashAlgorithmName.SHA256,
        "384" => HashAlgorithmName.SHA384,
        "512" => HashAlgorithmName.SHA512,
        _ => throw new InvalidTokenException("unsupported algorithm"),
    };

    public static bool VerifyHmac(string alg, string secret, byte[] input, byte[] signature)
    {
        var key = Encoding.UTF8.GetBytes(secret);
        byte[] expected = alg switch
        {
            "HS256" => HMACSHA256.HashData(key, input),
            "HS384" => HMACSHA384.HashData(key, input),
            "HS512" => HMACSHA512.HashData(key, input),
            _ => throw new InvalidTokenException("unsupported algorithm"),
        };
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    /// <summary>Verifies with a key that already <see cref="JsonWebKey.Fits"/> the algorithm.</summary>
    public static bool VerifyAsymmetric(string alg, JsonWebKey jwk, byte[] input, byte[] signature)
    {
        try
        {
            switch (alg[0])
            {
                case 'R':
                case 'P':
                {
                    using var rsa = RSA.Create(new RSAParameters { Modulus = JsonWebKey.Bytes(jwk.N, "n"), Exponent = JsonWebKey.Bytes(jwk.E, "e") });
                    // RSASSA-PSS with the salt as long as the hash, as JWS requires (RFC 7518 §3.5).
                    var padding = alg[0] == 'P' ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                    return signature.Length == rsa.KeySize / 8 && rsa.VerifyData(input, signature, Hash(alg), padding);
                }
                case 'E' when alg == "EdDSA":
                    return Ed25519.Verify(JsonWebKey.Bytes(jwk.X, "x"), input, signature);
                case 'E':
                {
                    var size = alg == "ES256" ? 32 : 48;
                    var x = JsonWebKey.Bytes(jwk.X, "x");
                    var y = JsonWebKey.Bytes(jwk.Y, "y");
                    if (x.Length != size || y.Length != size)
                    {
                        throw new InvalidTokenException("unusable signing key (EC coordinates have the wrong length)");
                    }
                    using var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Curve = size == 32 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384,
                        Q = new ECPoint { X = x, Y = y },
                    });
                    // JWS carries r‖s (IEEE P1363), not DER.
                    return signature.Length == 2 * size && ecdsa.VerifyData(input, signature, Hash(alg), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                }
                default:
                    throw new InvalidTokenException("unsupported algorithm");
            }
        }
        catch (CryptographicException e)
        {
            throw new InvalidTokenException("unusable signing key", e);
        }
    }
}
