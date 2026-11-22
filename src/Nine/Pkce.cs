using System.Security.Cryptography;
using System.Text;
using Nine.Internal;

namespace Nine;

/// <summary>Proof Key for Code Exchange (RFC 7636), S256 only.</summary>
public static class Pkce
{
    /// <summary>A new code verifier: 64 URL-safe characters (48 random bytes).</summary>
    public static string CreateVerifier() => Base64Url.Random(48);

    /// <summary>The S256 code challenge: base64url(SHA-256(verifier)).</summary>
    public static string CreateChallenge(string verifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(verifier);
        return Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
    }
}
