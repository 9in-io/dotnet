using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Nine.Internal;

namespace Nine;

/// <summary>How a <see cref="HybridTokenVerifier"/> trades speed against revocation.</summary>
public enum VerificationMode
{
    /// <summary>Signature and claims only. No calls to 9in; a revoked token works until it expires.</summary>
    Local,
    /// <summary>The local check, then one introspection per token, cached until a webhook says otherwise or <see cref="HybridTokenVerifierOptions.CacheTtl"/> passes.</summary>
    Hybrid,
    /// <summary>Introspection on every call. Always current; one request to 9in per call.</summary>
    Introspect,
}

/// <summary>Settings of a <see cref="HybridTokenVerifier"/>.</summary>
public sealed class HybridTokenVerifierOptions : TokenVerifierOptions
{
    /// <summary>
    /// <see cref="VerificationMode.Hybrid"/> when <see cref="ClientId"/> and <see cref="ClientSecret"/>
    /// are set, else <see cref="VerificationMode.Local"/>.
    /// </summary>
    public VerificationMode? Mode { get; set; }

    /// <summary>A confidential application of the tenant, for introspection.</summary>
    public string? ClientId { get; set; }

    /// <summary>Its client secret.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Longest time a hybrid answer is trusted without news from 9in. Default 5 minutes.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Where answers and revocation markers are kept. Default: in this process. Pass a shared cache
    /// (Redis, or <c>IDistributedCache</c> through the ASP.NET Core package) so a webhook received by
    /// one server evicts answers on all of them.
    /// </summary>
    public INineCache? Cache { get; set; }

    /// <summary>
    /// Settings from the environment: those of <see cref="TokenVerifierOptions.FromEnvironment"/> plus
    /// <c>NINE_CLIENT_ID</c>, <c>NINE_CLIENT_SECRET</c> and <c>NINE_TOKEN_MODE</c> (<c>local</c>, <c>hybrid</c>, <c>introspect</c>).
    /// </summary>
    public static new HybridTokenVerifierOptions FromEnvironment()
    {
        var options = new HybridTokenVerifierOptions();
        options.ReadEnvironment();
        options.ClientId = NineEnvironment.Get("CLIENT_ID");
        options.ClientSecret = NineEnvironment.Get("CLIENT_SECRET");
        if (NineEnvironment.Get("TOKEN_MODE") is { } mode)
        {
            options.Mode = ParseMode(mode);
        }
        return options;
    }

    /// <summary>Parses <c>local</c>, <c>hybrid</c> or <c>introspect</c>.</summary>
    public static VerificationMode ParseMode(string mode) => mode.Trim().ToLowerInvariant() switch
    {
        "local" => VerificationMode.Local,
        "hybrid" => VerificationMode.Hybrid,
        "introspect" => VerificationMode.Introspect,
        _ => throw new NineException("invalid_options", $"unknown token mode \"{mode}\" (local, hybrid or introspect)"),
    };
}

/// <summary>
/// Access-token verification that also catches revocations: a token revoked through
/// <c>/oauth/revoke</c>, a sign-out, an ended session or a blocked user is refused at once in
/// hybrid mode, not when it expires.
/// <list type="bullet">
/// <item><description><b>Hybrid</b> (default with client credentials): the local check, then one introspection per token. The answer is cached (at most <see cref="HybridTokenVerifierOptions.CacheTtl"/>, never past <c>exp</c>; a refusal until <c>exp</c>) and dropped when <see cref="HandleEventAsync"/> receives a <c>token.revoked</c>, <c>session.revoked</c> or user webhook.</description></item>
/// <item><description><b>Local</b>: signature and claims only.</description></item>
/// <item><description><b>Introspect</b>: ask 9in on every call.</description></item>
/// </list>
/// Opaque access tokens (<c>9in_at_…</c>) are always introspected (cached in hybrid mode; a refusal for a minute).
/// Safe to share: create one per API and keep it for the life of the process.
/// </summary>
public sealed class HybridTokenVerifier : IAccessTokenVerifier
{
    /// <summary>The prefix of opaque access tokens.</summary>
    public const string OpaquePrefix = "9in_at_";

    private static readonly string[] EvictingUserEvents = ["user.sessions_revoked", "user.deleted", "user.updated", "user.password_changed"];

    /// <summary>A marker counts against answers cached up to this long after it (clock differences between servers).</summary>
    private static readonly TimeSpan MarkerSkew = TimeSpan.FromSeconds(5);

    private readonly TokenVerifier _local;
    private readonly ClientAuth? _client;
    private readonly INineCache _cache;
    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<string, Lazy<Task<ClaimSet?>>> _inflight = new(StringComparer.Ordinal);

    /// <summary>Creates a verifier. Pass an <see cref="HttpClient"/> from <c>IHttpClientFactory</c>, or none for a shared default.</summary>
    public HybridTokenVerifier(HybridTokenVerifierOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _local = new TokenVerifier(options, httpClient);
        var hasCredentials = !string.IsNullOrEmpty(options.ClientId) && !string.IsNullOrEmpty(options.ClientSecret);
        Mode = options.Mode ?? (hasCredentials ? VerificationMode.Hybrid : VerificationMode.Local);
        if (Mode != VerificationMode.Local && !hasCredentials)
        {
            throw new NineException("invalid_options", $"{Mode.ToString().ToLowerInvariant()} mode needs ClientId and ClientSecret (a confidential application) for introspection");
        }
        _client = hasCredentials ? new ClientAuth(options.ClientId!, options.ClientSecret) : null;
        _cache = options.Cache ?? new NineMemoryCache(timeProvider: options.TimeProvider);
        _ttl = options.CacheTtl > TimeSpan.Zero ? options.CacheTtl : TimeSpan.FromMinutes(5);
    }

    /// <summary>Creates a verifier from <see cref="HybridTokenVerifierOptions.FromEnvironment"/>.</summary>
    public static HybridTokenVerifier FromEnvironment(HttpClient? httpClient = null) => new(HybridTokenVerifierOptions.FromEnvironment(), httpClient);

    /// <summary>The mode in use.</summary>
    public VerificationMode Mode { get; }

    /// <summary>The normalised issuer.</summary>
    public string Issuer => _local.Issuer;

    /// <summary>The local verifier (same issuer, audience, secret and key cache).</summary>
    public TokenVerifier Local => _local;

    private TimeProvider Time => _local.Time;

    /// <inheritdoc/>
    public async Task<ClaimSet> VerifyAsync(string? token, string? scope = null, CancellationToken cancellationToken = default)
    {
        token = TokenVerifier.StripBearer(token);
        if (string.IsNullOrEmpty(token))
        {
            throw new InvalidTokenException("missing token");
        }
        var opaque = token.StartsWith(OpaquePrefix, StringComparison.Ordinal);
        if (opaque && Mode == VerificationMode.Local)
        {
            throw new InvalidTokenException("opaque tokens need hybrid or introspect mode");
        }
        var local = opaque ? null : await _local.VerifyAsync(token, scope, cancellationToken).ConfigureAwait(false);
        if (Mode == VerificationMode.Local)
        {
            return local!;
        }
        var claims = await LookupAsync(token, local, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidTokenException("token revoked");
        if (local is null)
        {
            _local.CheckClaims(claims, scope);
        }
        return claims;
    }

    /// <summary>
    /// Drops cached answers that a verified webhook event makes stale: <c>token.revoked</c> (access
    /// tokens) by <c>jti</c>, <c>session.revoked</c> by <c>sid</c>, and <c>user.sessions_revoked</c>,
    /// <c>user.deleted</c>, <c>user.updated</c> and <c>user.password_changed</c> by user. Returns true
    /// when the event was one of those. Subscribe your webhook endpoint to them.
    /// </summary>
    public async Task<bool> HandleEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(webhookEvent);
        var data = webhookEvent.Data;
        string? Read(string name) => data.ValueKind == JsonValueKind.Object && data.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        (string Kind, string Value)? target = null;
        if (webhookEvent.EventType == "token.revoked" && Read("token_type") == "access_token" && Read("jti") is { Length: > 0 } jti)
        {
            target = ("jti", jti);
        }
        else if (webhookEvent.EventType == "session.revoked" && Read("sid") is { Length: > 0 } sid)
        {
            target = ("sid", sid);
        }
        else if (EvictingUserEvents.Contains(webhookEvent.EventType) && webhookEvent.UserId is { Length: > 0 } userId)
        {
            target = ("sub", userId);
        }
        if (target is not { } t)
        {
            return false;
        }
        // A marker, not a scan: answers cached before it no longer count (on every server sharing the cache).
        var now = Time.GetUtcNow().ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
        await _cache.SetAsync(MarkerKey(t.Kind, t.Value), now, _ttl + TimeSpan.FromMinutes(1), cancellationToken).ConfigureAwait(false);
        return true;
    }

    private static string AnswerKey(string token) => "nine:answer:" + Base64Url.Sha256Hex(token);

    private static string MarkerKey(string kind, string value) => $"nine:evict:{kind}:{Base64Url.Sha256Hex(value)}";

    /// <summary>The live claims (the token's own for a JWT, once 9in confirms it is active), or null when it is not.</summary>
    private async Task<ClaimSet?> LookupAsync(string token, ClaimSet? local, CancellationToken cancellationToken)
    {
        var key = AnswerKey(token);
        var now = Time.GetUtcNow();
        if (Mode == VerificationMode.Hybrid && await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false) is { } cached
            && CachedAnswer.TryParse(cached) is { } hit && hit.Until > now)
        {
            if (hit.Claims is null || !await IsEvictedAsync(hit, cancellationToken).ConfigureAwait(false))
            {
                return hit.Claims;
            }
        }

        var lazy = _inflight.GetOrAdd(key, _ => new Lazy<Task<ClaimSet?>>(() => IntrospectAsync(token)));
        ClaimSet? answer;
        try
        {
            answer = await lazy.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (lazy.Value.IsCompleted)
            {
                _inflight.TryRemove(new KeyValuePair<string, Lazy<Task<ClaimSet?>>>(key, lazy));
            }
        }
        var claims = answer is not null && local is not null ? local : answer;

        if (Mode == VerificationMode.Hybrid)
        {
            now = Time.GetUtcNow();
            var exp = (claims ?? local)?.ExpiresAt;
            // A revoked token never comes back: remember the refusal until it expires (an opaque one for a minute).
            var until = claims is not null
                ? Min(now + _ttl, exp ?? now)
                : exp ?? now + TimeSpan.FromMinutes(1);
            if (until > now)
            {
                var entry = new CachedAnswer(claims, until, now);
                await _cache.SetAsync(key, entry.Serialize(), until - now, cancellationToken).ConfigureAwait(false);
            }
        }
        return claims;
    }

    private async Task<bool> IsEvictedAsync(CachedAnswer answer, CancellationToken cancellationToken)
    {
        var claims = answer.Claims!;
        foreach (var (kind, value) in new[] { ("jti", claims.TokenId), ("sid", claims.SessionId), ("sub", claims.Subject) })
        {
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }
            var marker = await _cache.GetAsync(MarkerKey(kind, value), cancellationToken).ConfigureAwait(false);
            if (marker is not null && long.TryParse(marker, NumberStyles.Integer, CultureInfo.InvariantCulture, out var at)
                && DateTimeOffset.FromUnixTimeMilliseconds(at) >= answer.CachedAt - MarkerSkew)
            {
                return true;
            }
        }
        return false;
    }

    private async Task<ClaimSet?> IntrospectAsync(string token)
    {
        // Shared by concurrent callers, so not tied to one caller's cancellation (the HTTP timeout still applies).
        var discovery = await DiscoveryCache.GetAsync(Issuer, _local.Http, Time, CancellationToken.None).ConfigureAwait(false);
        var endpoint = discovery.IntrospectionEndpoint ?? Issuer + "/oauth/introspect";
        var result = await _local.Http.PostFormAsync(endpoint, [new("token", token)], _client, CancellationToken.None).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw result.Error("introspection_failed");
        }
        if (result.JsonObject() is not { } body)
        {
            throw new NineException("introspection_failed", "the introspection answer is not JSON");
        }
        if (!body.TryGetProperty("active", out var active) || active.ValueKind != JsonValueKind.True)
        {
            return null;
        }
        if (body.TryGetProperty("token_type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "refresh_token")
        {
            return null;
        }
        return ClaimSet.FromJson(body);
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;

    private sealed record CachedAnswer(ClaimSet? Claims, DateTimeOffset Until, DateTimeOffset CachedAt)
    {
        public string Serialize()
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteNumber("until", Until.ToUnixTimeMilliseconds());
                writer.WriteNumber("at", CachedAt.ToUnixTimeMilliseconds());
                writer.WritePropertyName("claims");
                if (Claims is null)
                {
                    writer.WriteNullValue();
                }
                else
                {
                    Claims.Json.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
        }

        public static CachedAnswer? TryParse(string json)
        {
            try
            {
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                var claims = root.GetProperty("claims");
                return new CachedAnswer(
                    claims.ValueKind == JsonValueKind.Object ? ClaimSet.FromJson(claims) : null,
                    DateTimeOffset.FromUnixTimeMilliseconds(root.GetProperty("until").GetInt64()),
                    DateTimeOffset.FromUnixTimeMilliseconds(root.GetProperty("at").GetInt64()));
            }
            catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return null;
            }
        }
    }
}
