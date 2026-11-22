using System.Text.Json;
using Nine.Internal;

namespace Nine.Tokens;

/// <summary>A public key from a JWKS (RSA, EC P-256/P-384 or OKP Ed25519).</summary>
internal sealed record JsonWebKey(string? Kty, string? Kid, string? Alg, string? Crv, string? N, string? E, string? X, string? Y)
{
    public static JsonWebKey From(JsonElement key)
    {
        string? Read(string name) => key.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        return new JsonWebKey(Read("kty"), Read("kid"), Read("alg"), Read("crv"), Read("n"), Read("e"), Read("x"), Read("y"));
    }

    /// <summary>Whether this key can verify <paramref name="alg"/> (key type and curve), whatever its <c>alg</c> member says.</summary>
    public bool Fits(string alg) => alg switch
    {
        "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512" => Kty == "RSA",
        "ES256" => Kty == "EC" && Crv == "P-256",
        "ES384" => Kty == "EC" && Crv == "P-384",
        "EdDSA" => Kty == "OKP" && Crv == "Ed25519",
        _ => false,
    };

    public static byte[] Bytes(string? value, string name) =>
        value is not null && Base64Url.TryDecode(value, out var bytes) && bytes.Length > 0
            ? bytes
            : throw new InvalidTokenException($"unusable signing key (no {name})");
}
