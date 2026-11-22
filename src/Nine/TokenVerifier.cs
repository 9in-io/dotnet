using Nine.Internal;
using Nine.Tokens;

namespace Nine;

/// <summary>Verifies bearer tokens for an API: <see cref="TokenVerifier"/> (local) or <see cref="HybridTokenVerifier"/>.</summary>
public interface IAccessTokenVerifier
{
    /// <summary>
    /// Verifies a token (or a whole <c>Authorization: Bearer …</c> header value) and returns its claims.
    /// Throws <see cref="InvalidTokenException"/> (401) or <see cref="InsufficientScopeException"/> (403);
    /// other <see cref="NineException"/>s mean 9in couldn't be reached (answer 503).
    /// </summary>
    /// <param name="token">The token, with or without the <c>Bearer </c> prefix.</param>
    /// <param name="scope">Scopes the token must all have, space-separated.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task<ClaimSet> VerifyAsync(string? token, string? scope = null, CancellationToken cancellationToken = default);
}

/// <summary>Settings of a <see cref="TokenVerifier"/>.</summary>
public class TokenVerifierOptions
{
    /// <summary>Your tenant's issuer, e.g. <c>https://acme.9in.io</c> or your custom login domain.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>Your API's identifier: tokens must be issued for it (<c>aud</c>). Leave empty to skip the check.</summary>
    public string? Audience { get; set; }

    /// <summary>More accepted audiences (any one is enough).</summary>
    public IList<string> Audiences { get; } = [];

    /// <summary>
    /// The shared secret of your API's HMAC key (HS256/384/512), from the console's key library.
    /// Only for APIs that use an HMAC key; keys from the JWKS need nothing.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>Clock skew allowed on <c>exp</c> and <c>nbf</c>. Default 30 seconds.</summary>
    public TimeSpan Leeway { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Accept a plain-http issuer other than localhost (development only).</summary>
    public bool AllowInsecureIssuer { get; set; }

    /// <summary>Timeout of each request to 9in (discovery, JWKS, introspection). Default 10 seconds.</summary>
    public TimeSpan Timeout { get; set; } = NineHttp.DefaultTimeout;

    /// <summary>The clock (tests).</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Settings from the environment: <c>NINE_ISSUER</c>, <c>NINE_API_AUDIENCE</c> (or <c>NINE_AUDIENCE</c>),
    /// <c>NINE_API_SECRET</c> and <c>NINE_ALLOW_INSECURE_ISSUER</c>.
    /// </summary>
    public static TokenVerifierOptions FromEnvironment()
    {
        var options = new TokenVerifierOptions();
        options.ReadEnvironment();
        return options;
    }

    internal void ReadEnvironment()
    {
        Issuer = NineEnvironment.Get("ISSUER") ?? Issuer;
        Audience = NineEnvironment.Get("API_AUDIENCE") ?? NineEnvironment.Get("AUDIENCE") ?? Audience;
        Secret = NineEnvironment.Get("API_SECRET") ?? Secret;
        AllowInsecureIssuer = AllowInsecureIssuer || NineEnvironment.GetBool("ALLOW_INSECURE_ISSUER");
    }

    internal IReadOnlyList<string> AllAudiences()
    {
        var all = new List<string>(Audiences.Where(a => !string.IsNullOrEmpty(a)));
        if (!string.IsNullOrEmpty(Audience))
        {
            all.Insert(0, Audience);
        }
        return all;
    }
}

/// <summary>
/// Verifies 9in JWT access tokens locally: the signature (against your tenant's JWKS, or your API's
/// shared secret for HMAC keys), the token type (<c>at+jwt</c>), issuer, expiry, audience and
/// scopes. Every algorithm of the 9in key library is accepted: RS256/384/512, PS256/384/512, ES256,
/// ES384 and EdDSA from the JWKS, and HS256/384/512 with <see cref="TokenVerifierOptions.Secret"/>.
/// When a JWKS key names its <c>alg</c>, the token must use exactly that algorithm.
/// <para>
/// This is a local check: a token revoked before it expires still passes. Use
/// <see cref="HybridTokenVerifier"/> when revocation must take effect at once.
/// </para>
/// Safe to share: create one per API and keep it for the life of the process.
/// </summary>
public sealed class TokenVerifier : IAccessTokenVerifier
{
    private static readonly HashSet<string> AccessTokenTypes = new(StringComparer.OrdinalIgnoreCase) { "at+jwt", "application/at+jwt" };

    private readonly NineHttp _http;
    private readonly TimeProvider _time;
    private readonly IReadOnlyList<string> _audiences;
    private readonly string? _secret;
    private readonly TimeSpan _leeway;

    /// <summary>Creates a verifier. Pass an <see cref="HttpClient"/> from <c>IHttpClientFactory</c>, or none for a shared default.</summary>
    public TokenVerifier(TokenVerifierOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        Issuer = Nine.Issuer.Normalize(options.Issuer, options.AllowInsecureIssuer);
        _http = new NineHttp(httpClient, options.Timeout);
        _time = options.TimeProvider;
        _audiences = options.AllAudiences();
        _secret = string.IsNullOrEmpty(options.Secret) ? null : options.Secret;
        _leeway = options.Leeway;
    }

    /// <summary>The normalised issuer.</summary>
    public string Issuer { get; }

    internal NineHttp Http => _http;

    internal TimeProvider Time => _time;

    /// <inheritdoc/>
    public async Task<ClaimSet> VerifyAsync(string? token, string? scope = null, CancellationToken cancellationToken = default)
    {
        token = StripBearer(token);
        if (string.IsNullOrEmpty(token))
        {
            throw new InvalidTokenException("missing token");
        }
        var jwt = Jwt.TryDecode(token) ?? throw new InvalidTokenException("malformed token");
        if (jwt.Typ is null || !AccessTokenTypes.Contains(jwt.Typ))
        {
            throw new InvalidTokenException("not an access token");
        }
        await VerifySignatureAsync(jwt, allowHmac: true, cancellationToken).ConfigureAwait(false);
        var claims = ClaimSet.FromJson(jwt.Payload);
        CheckClaims(claims, scope);
        return claims;
    }

    /// <summary>
    /// Verifies an ID token issued to <paramref name="clientId"/>: an asymmetric signature from the JWKS,
    /// issuer, audience (and <c>azp</c> when there are several), expiry and, when given, the nonce.
    /// </summary>
    public async Task<ClaimSet> VerifyIdTokenAsync(string? idToken, string clientId, string? nonce = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        if (string.IsNullOrEmpty(idToken))
        {
            throw new InvalidTokenException("missing ID token");
        }
        var jwt = Jwt.TryDecode(idToken) ?? throw new InvalidTokenException("malformed ID token");
        // An access token is never accepted as an ID token.
        if (jwt.Typ is not null && AccessTokenTypes.Contains(jwt.Typ))
        {
            throw new InvalidTokenException("not an ID token");
        }
        await VerifySignatureAsync(jwt, allowHmac: false, cancellationToken).ConfigureAwait(false);
        var claims = ClaimSet.FromJson(jwt.Payload);
        CheckTimesAndIssuer(claims);
        var audiences = claims.Audiences;
        if (!audiences.Contains(clientId, StringComparer.Ordinal))
        {
            throw new InvalidTokenException("ID token audience mismatch");
        }
        if (audiences.Count > 1 && claims.GetString("azp") != clientId)
        {
            throw new InvalidTokenException("ID token authorized party mismatch");
        }
        if (nonce is not null && !FixedTimeEquals(claims.GetString("nonce"), nonce))
        {
            throw new InvalidTokenException("ID token nonce mismatch");
        }
        if (string.IsNullOrEmpty(claims.Subject))
        {
            throw new InvalidTokenException("ID token without a subject");
        }
        return claims;
    }

    private async Task VerifySignatureAsync(Jwt jwt, bool allowHmac, CancellationToken cancellationToken)
    {
        if (jwt.Header.TryGetProperty("crit", out _))
        {
            throw new InvalidTokenException("unsupported critical header");
        }
        var alg = jwt.Alg ?? "";
        bool valid;
        if (Jws.Hmac.Contains(alg) && allowHmac)
        {
            if (_secret is null)
            {
                throw new InvalidTokenException("HMAC-signed token: set the API's secret (NINE_API_SECRET)");
            }
            valid = Jws.VerifyHmac(alg, _secret, jwt.SigningInput, jwt.Signature);
        }
        else if (Jws.Asymmetric.Contains(alg))
        {
            var jwk = await JwksCache.FindAsync(Issuer, jwt.Kid, _http, _time, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidTokenException("unknown signing key");
            // The key decides the algorithm, never the token alone (no algorithm confusion).
            if ((jwk.Alg is not null && jwk.Alg != alg) || !jwk.Fits(alg))
            {
                throw new InvalidTokenException("algorithm does not match the key");
            }
            valid = Jws.VerifyAsymmetric(alg, jwk, jwt.SigningInput, jwt.Signature);
        }
        else
        {
            throw new InvalidTokenException("unsupported algorithm");
        }
        if (!valid)
        {
            throw new InvalidTokenException("bad signature");
        }
    }

    /// <summary>Issuer, expiry, not-before, audience and scope checks (for a JWT's claims or an introspection answer).</summary>
    internal void CheckClaims(ClaimSet claims, string? scope)
    {
        CheckTimesAndIssuer(claims);
        if (_audiences.Count > 0 && !claims.Audiences.Any(a => _audiences.Contains(a, StringComparer.Ordinal)))
        {
            throw new InvalidTokenException("audience mismatch");
        }
        CheckScope(claims, scope);
    }

    private void CheckTimesAndIssuer(ClaimSet claims)
    {
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;
        var leeway = _leeway.TotalSeconds;
        if (!Nine.Issuer.Same(claims.Issuer, Issuer))
        {
            throw new InvalidTokenException("issuer mismatch");
        }
        if (claims.GetSeconds("exp") is not { } exp || exp + leeway < now)
        {
            throw new InvalidTokenException("token expired");
        }
        if (claims.GetSeconds("nbf") is { } nbf && nbf - leeway > now)
        {
            throw new InvalidTokenException("token not yet valid");
        }
    }

    internal static void CheckScope(ClaimSet claims, string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return;
        }
        var granted = claims.Scopes;
        var missing = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(s => !granted.Contains(s, StringComparer.Ordinal)).ToArray();
        if (missing.Length > 0)
        {
            throw new InsufficientScopeException(missing);
        }
    }

    /// <summary>The token from an <c>Authorization</c> header value (<c>Bearer …</c>), or the value itself.</summary>
    public static string? StripBearer(string? value)
    {
        if (value is null)
        {
            return null;
        }
        value = value.Trim();
        if (value.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }
        return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : value;
    }

    internal static bool FixedTimeEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a), System.Text.Encoding.UTF8.GetBytes(b));
    }

    /// <summary>Forgets the process-wide discovery and signing-key caches (tests, or after moving a tenant to a new domain).</summary>
    public static void ClearCaches()
    {
        DiscoveryCache.Clear();
        JwksCache.Clear();
    }

    /// <summary>Forgets one issuer's cached discovery document and keys (tests).</summary>
    internal static void ClearCaches(string issuer)
    {
        DiscoveryCache.Clear(issuer);
        JwksCache.Clear(issuer);
    }
}
