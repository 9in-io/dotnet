using System.Collections.Concurrent;
using System.Text.Json;
using Nine.Internal;

namespace Nine.Tokens;

/// <summary>
/// Signing keys per issuer, shared by every verifier in the process: cached ten minutes, fetched
/// again once when a token names an unknown <c>kid</c> (key rotation), and an unknown kid is then
/// ignored for a minute so junk tokens can't make you hammer the JWKS endpoint.
/// </summary>
internal static class JwksCache
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MissThrottle = TimeSpan.FromSeconds(60);

    private static readonly ConcurrentDictionary<string, (IReadOnlyList<JsonWebKey> Keys, DateTimeOffset FetchedAt)> Keys = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, Task<IReadOnlyList<JsonWebKey>>> Fetches = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, DateTimeOffset> MissingKids = new(StringComparer.Ordinal);

    public static async Task<JsonWebKey?> FindAsync(string issuer, string? kid, NineHttp http, TimeProvider time, CancellationToken cancellationToken)
    {
        var known = Match(await GetAsync(issuer, force: false, http, time, cancellationToken).ConfigureAwait(false), kid);
        if (known is not null)
        {
            return known;
        }
        var missKey = issuer + "|" + kid;
        if (MissingKids.TryGetValue(missKey, out var missedAt) && time.GetUtcNow() - missedAt < MissThrottle)
        {
            return null;
        }
        var refreshed = Match(await GetAsync(issuer, force: true, http, time, cancellationToken).ConfigureAwait(false), kid);
        if (refreshed is null)
        {
            if (MissingKids.Count > 1000)
            {
                MissingKids.Clear();
            }
            MissingKids[missKey] = time.GetUtcNow();
        }
        return refreshed;
    }

    private static JsonWebKey? Match(IReadOnlyList<JsonWebKey> keys, string? kid) =>
        keys.FirstOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));

    private static async Task<IReadOnlyList<JsonWebKey>> GetAsync(string issuer, bool force, NineHttp http, TimeProvider time, CancellationToken cancellationToken)
    {
        if (!force && Keys.TryGetValue(issuer, out var hit) && time.GetUtcNow() - hit.FetchedAt < Ttl)
        {
            return hit.Keys;
        }
        // Concurrent callers share one fetch.
        var fetch = Fetches.GetOrAdd(issuer, _ => FetchAsync(issuer, http, time));
        try
        {
            return await fetch.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (fetch.IsCompleted)
            {
                Fetches.TryRemove(new KeyValuePair<string, Task<IReadOnlyList<JsonWebKey>>>(issuer, fetch));
            }
        }
    }

    private static async Task<IReadOnlyList<JsonWebKey>> FetchAsync(string issuer, NineHttp http, TimeProvider time)
    {
        {
            var discovery = await DiscoveryCache.GetAsync(issuer, http, time, CancellationToken.None).ConfigureAwait(false);
            var result = await http.GetAsync(discovery.JwksUri, CancellationToken.None).ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                throw new NineException("jwks_unavailable", $"HTTP {result.Status} from {discovery.JwksUri}", result.Status);
            }
            var keys = new List<JsonWebKey>();
            if (result.JsonObject() is { } body && body.TryGetProperty("keys", out var array) && array.ValueKind == JsonValueKind.Array)
            {
                foreach (var key in array.EnumerateArray())
                {
                    if (key.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }
                    var jwk = JsonWebKey.From(key);
                    // Encryption keys never verify signatures.
                    if (key.TryGetProperty("use", out var use) && use.ValueKind == JsonValueKind.String && use.GetString() != "sig")
                    {
                        continue;
                    }
                    keys.Add(jwk);
                }
            }
            else
            {
                throw new NineException("jwks_unavailable", "the JWKS is not a JSON key set");
            }
            Keys[issuer] = (keys, time.GetUtcNow());
            return keys;
        }
    }

    public static void Clear()
    {
        Keys.Clear();
        MissingKids.Clear();
    }

    public static void Clear(string issuer)
    {
        Keys.TryRemove(issuer, out _);
        foreach (var key in MissingKids.Keys.Where(k => k.StartsWith(issuer + "|", StringComparison.Ordinal)))
        {
            MissingKids.TryRemove(key, out _);
        }
    }
}
