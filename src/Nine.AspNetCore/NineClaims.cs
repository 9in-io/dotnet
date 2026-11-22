using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Nine.AspNetCore;

/// <summary>Claims of 9in tokens as <see cref="Claim"/>s, and the verified claims of the current request.</summary>
public static class NineClaims
{
    private static readonly HashSet<string> TokenOnly = new(StringComparer.Ordinal) { "nonce", "at_hash", "c_hash", "aud", "exp", "iat", "nbf", "azp", "jti", "iss" };

    /// <summary>
    /// <see cref="Claim"/>s with 9in's own names (<c>sub</c>, <c>email</c>, <c>scope</c>, …): strings as they are,
    /// numbers and booleans as text, arrays as one claim per item, objects as JSON.
    /// </summary>
    public static IEnumerable<Claim> From(ClaimSet claims, string? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(claims);
        issuer ??= claims.Issuer ?? ClaimsIdentity.DefaultIssuer;
        foreach (var (name, value) in claims)
        {
            foreach (var claim in Convert(name, value, issuer))
            {
                yield return claim;
            }
        }
    }

    /// <summary>The claims of a signed-in user from an ID token, without the claims that only describe the token.</summary>
    internal static IEnumerable<Claim> User(ClaimSet claims, string issuer) =>
        From(claims, issuer).Where(c => !TokenOnly.Contains(c.Type));

    private static IEnumerable<Claim> Convert(string name, JsonElement value, string issuer)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                yield return new Claim(name, value.GetString()!, ClaimValueTypes.String, issuer);
                break;
            case JsonValueKind.Number:
                yield return new Claim(name, value.GetRawText(), value.TryGetInt64(out _) ? ClaimValueTypes.Integer64 : ClaimValueTypes.Double, issuer);
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                yield return new Claim(name, value.GetBoolean() ? "true" : "false", ClaimValueTypes.Boolean, issuer);
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    foreach (var claim in Convert(name, item, issuer))
                    {
                        yield return claim;
                    }
                }
                break;
            case JsonValueKind.Object:
                yield return new Claim(name, value.GetRawText(), "JSON", issuer);
                break;
        }
    }

    /// <summary>
    /// The verified claims of the bearer token of this request (exactly as 9in sent them), or null when the
    /// request wasn't authenticated by the 9in bearer scheme.
    /// </summary>
    public static ClaimSet? GetNineClaims(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(NineBearerHandler.ClaimsItem, out var claims) ? claims as ClaimSet : null;
    }

    /// <summary>The scopes of the principal's <c>scope</c> claims.</summary>
    public static IReadOnlyList<string> GetScopes(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Distinct(StringComparer.Ordinal).ToArray();
    }

    internal static string ToText(long seconds) => seconds.ToString(CultureInfo.InvariantCulture);
}
