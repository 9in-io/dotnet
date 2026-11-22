using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Nine.Tests.Support;

/// <summary>A signing key for one JWS algorithm, with its public JWK.</summary>
public sealed class TestKey
{
    private readonly Func<byte[], byte[]> _sign;

    private TestKey(string alg, string kid, JsonObject? jwk, Func<byte[], byte[]> sign, string? secret = null)
    {
        Alg = alg;
        Kid = kid;
        Jwk = jwk;
        _sign = sign;
        Secret = secret;
    }

    public string Alg { get; }
    public string Kid { get; }
    /// <summary>The public JWK (null for HMAC keys, which are never published).</summary>
    public JsonObject? Jwk { get; }
    public string? Secret { get; }

    public byte[] Sign(byte[] input) => _sign(input);

    public static readonly string[] AllAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"];
    public static readonly string[] AsymmetricAlgorithms = AllAlgorithms.Where(a => a[0] != 'H').ToArray();

    private static readonly ConcurrentDictionary<string, RSA> RsaKeys = new();

    /// <summary>A key for <paramref name="alg"/>. RSA keys are generated once per test run (slow).</summary>
    public static TestKey Create(string alg, string? kid = null, bool includeAlg = true)
    {
        kid ??= "k-" + alg;
        static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        JsonObject Jwk(JsonObject material)
        {
            material["kid"] = kid;
            material["use"] = "sig";
            if (includeAlg)
            {
                material["alg"] = alg;
            }
            return material;
        }
        HashAlgorithmName Hash() => alg[2..] switch { "256" => HashAlgorithmName.SHA256, "384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };

        switch (alg[..2])
        {
            case "RS":
            case "PS":
            {
                var rsa = RsaKeys.GetOrAdd(kid + alg, _ => RSA.Create(2048));
                var p = rsa.ExportParameters(false);
                var padding = alg[0] == 'P' ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return new TestKey(alg, kid, Jwk(new JsonObject { ["kty"] = "RSA", ["n"] = B64(p.Modulus!), ["e"] = B64(p.Exponent!) }), input => rsa.SignData(input, Hash(), padding));
            }
            case "ES":
            {
                var ecdsa = ECDsa.Create(alg == "ES256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
                var p = ecdsa.ExportParameters(false);
                return new TestKey(alg, kid, Jwk(new JsonObject { ["kty"] = "EC", ["crv"] = alg == "ES256" ? "P-256" : "P-384", ["x"] = B64(p.Q.X!), ["y"] = B64(p.Q.Y!) }),
                    input => ecdsa.SignData(input, Hash(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            }
            case "Ed":
            {
                var seed = RandomNumberGenerator.GetBytes(32);
                return new TestKey(alg, kid, Jwk(new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = B64(Ed25519Signer.PublicKey(seed)) }), input => Ed25519Signer.Sign(seed, input));
            }
            case "HS":
            {
                var secret = "hmac-secret-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                var key = Encoding.UTF8.GetBytes(secret);
                return new TestKey(alg, kid, null, input => alg switch
                {
                    "HS256" => HMACSHA256.HashData(key, input),
                    "HS384" => HMACSHA384.HashData(key, input),
                    _ => HMACSHA512.HashData(key, input),
                }, secret);
            }
            default:
                throw new ArgumentException(alg);
        }
    }
}

/// <summary>Builds compact JWS tokens.</summary>
public static class TestJwt
{
    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string B64(string text) => B64(Encoding.UTF8.GetBytes(text));

    public static string Sign(TestKey key, JsonObject claims, string typ = "at+jwt", Action<JsonObject>? header = null)
    {
        var h = new JsonObject { ["alg"] = key.Alg, ["typ"] = typ, ["kid"] = key.Kid };
        header?.Invoke(h);
        var input = B64(h.ToJsonString()) + "." + B64(claims.ToJsonString());
        return input + "." + B64(key.Sign(Encoding.ASCII.GetBytes(input)));
    }

    /// <summary>A token with an arbitrary header and signature bytes.</summary>
    public static string Raw(JsonObject header, JsonObject claims, byte[] signature) =>
        B64(header.ToJsonString()) + "." + B64(claims.ToJsonString()) + "." + B64(signature);

    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}
