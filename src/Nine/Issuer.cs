using System.Text.RegularExpressions;

namespace Nine;

/// <summary>
/// Issuer URL validation. Issuers must use https, so a typo can't send tokens or credentials in clear
/// text. Plain http is accepted for <c>localhost</c>, <c>*.localhost</c> and loopback addresses, when
/// the caller allows it, or with <c>NINE_ALLOW_INSECURE_ISSUER=true</c>. Issuers with a query, a
/// fragment or credentials are refused.
/// </summary>
public static partial class Issuer
{
    /// <summary>
    /// Validates <paramref name="issuer"/> and returns it without a trailing slash. Throws
    /// <see cref="NineException"/> with <c>invalid_issuer</c> or <c>insecure_issuer</c>.
    /// </summary>
    public static string Normalize(string? issuer, bool allowInsecure = false)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new NineException("invalid_issuer", "an issuer is required (NINE_ISSUER), e.g. https://acme.9in.io");
        }
        issuer = issuer.Trim();
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new NineException("invalid_issuer", $"not a URL: {issuer}");
        }
        if (issuer.Contains('?', StringComparison.Ordinal) || issuer.Contains('#', StringComparison.Ordinal) || uri.UserInfo.Length > 0)
        {
            throw new NineException("invalid_issuer", "an issuer has no query, fragment or credentials");
        }
        var secure = uri.Scheme == Uri.UriSchemeHttps
            || allowInsecure || IsLocalHost(uri.Host) || NineEnvironment.GetBool("ALLOW_INSECURE_ISSUER");
        if (!secure)
        {
            throw new NineException("insecure_issuer", $"issuer must use https (got {uri.Scheme}://{uri.Authority}); plain http is only accepted for localhost");
        }
        return issuer.TrimEnd('/');
    }

    /// <summary>True for <c>localhost</c>, <c>*.localhost</c>, <c>::1</c> and <c>127.x.x.x</c>.</summary>
    public static bool IsLocalHost(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        host = host.Trim('[', ']').ToLowerInvariant();
        return host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal) || host == "::1" || Loopback().IsMatch(host);
    }

    /// <summary>Whether two issuer strings name the same issuer (ignoring one trailing slash).</summary>
    internal static bool Same(string? a, string? b) =>
        a is not null && b is not null && string.Equals(a.TrimEnd('/'), b.TrimEnd('/'), StringComparison.Ordinal);

    [GeneratedRegex(@"^127(\.\d{1,3}){3}$", RegexOptions.CultureInvariant)]
    private static partial Regex Loopback();
}
