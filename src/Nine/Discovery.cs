using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nine.Internal;

namespace Nine;

/// <summary>A tenant's OpenID Connect discovery document (<c>/.well-known/openid-configuration</c>).</summary>
public sealed record Discovery
{
    /// <summary>The issuer, exactly as in tokens' <c>iss</c>.</summary>
    [JsonPropertyName("issuer")] public string Issuer { get; init; } = "";
    /// <summary>Where sign-ins start.</summary>
    [JsonPropertyName("authorization_endpoint")] public string AuthorizationEndpoint { get; init; } = "";
    /// <summary>Where codes, refresh tokens and client credentials are exchanged.</summary>
    [JsonPropertyName("token_endpoint")] public string TokenEndpoint { get; init; } = "";
    /// <summary>The user's claims for an access token.</summary>
    [JsonPropertyName("userinfo_endpoint")] public string? UserInfoEndpoint { get; init; }
    /// <summary>The public signing keys.</summary>
    [JsonPropertyName("jwks_uri")] public string JwksUri { get; init; } = "";
    /// <summary>RP-initiated logout.</summary>
    [JsonPropertyName("end_session_endpoint")] public string? EndSessionEndpoint { get; init; }
    /// <summary>RFC 7009 revocation.</summary>
    [JsonPropertyName("revocation_endpoint")] public string? RevocationEndpoint { get; init; }
    /// <summary>RFC 7662 introspection.</summary>
    [JsonPropertyName("introspection_endpoint")] public string? IntrospectionEndpoint { get; init; }
    /// <summary>RFC 8628 device authorization.</summary>
    [JsonPropertyName("device_authorization_endpoint")] public string? DeviceAuthorizationEndpoint { get; init; }
    /// <summary>Whether the issuer adds <c>iss</c> to authorization responses (RFC 9207).</summary>
    [JsonPropertyName("authorization_response_iss_parameter_supported")] public bool AuthorizationResponseIssParameterSupported { get; init; }
    /// <summary>The algorithms of the tenant's keys.</summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")] public IReadOnlyList<string>? IdTokenSigningAlgValuesSupported { get; init; }
}

/// <summary>Discovery documents, cached per issuer for an hour in this process (a failed fetch is not cached).</summary>
internal static class DiscoveryCache
{
    private static readonly ConcurrentDictionary<string, (Task<Discovery> Task, long FetchedAt)> Cache = new(StringComparer.Ordinal);
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(1);

    public static async Task<Discovery> GetAsync(string issuer, NineHttp http, TimeProvider time, CancellationToken cancellationToken)
    {
        var now = time.GetTimestamp();
        if (Cache.TryGetValue(issuer, out var hit) && time.GetElapsedTime(hit.FetchedAt, now) < Ttl)
        {
            if (!hit.Task.IsCompleted || hit.Task.IsCompletedSuccessfully)
            {
                return await hit.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        var task = FetchAsync(issuer, http);
        Cache[issuer] = (task, now);
        try
        {
            return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            Cache.TryRemove(new KeyValuePair<string, (Task<Discovery>, long)>(issuer, (task, now)));
            throw;
        }
    }

    private static async Task<Discovery> FetchAsync(string issuer, NineHttp http)
    {
        // Not tied to one caller's cancellation: other callers share this fetch.
        var result = await http.GetAsync(issuer + "/.well-known/openid-configuration", CancellationToken.None).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw new NineException("discovery_failed", $"HTTP {result.Status} from {issuer}/.well-known/openid-configuration", result.Status);
        }
        Discovery? discovery;
        try
        {
            discovery = JsonSerializer.Deserialize(result.Body, NineJsonContext.Default.Discovery);
        }
        catch (JsonException e)
        {
            throw new NineException("discovery_failed", "the discovery document is not JSON", null, e);
        }
        if (discovery is null || string.IsNullOrEmpty(discovery.TokenEndpoint) || string.IsNullOrEmpty(discovery.JwksUri) || string.IsNullOrEmpty(discovery.AuthorizationEndpoint))
        {
            throw new NineException("discovery_failed", "incomplete discovery document");
        }
        // OpenID Connect Discovery 1.0 §4.3: the document must name the issuer it was fetched from.
        if (!Issuer.Same(discovery.Issuer, issuer))
        {
            throw new NineException("discovery_failed", $"the discovery document is for {discovery.Issuer}, not {issuer}");
        }
        return discovery;
    }

    public static void Clear() => Cache.Clear();

    public static void Clear(string issuer) => Cache.TryRemove(issuer, out _);
}
