namespace Nine;

/// <summary>
/// A small key-value store with expiry, for state the SDK shares across requests (and, with a
/// shared implementation, across servers): hybrid verification answers and revocation markers,
/// processed webhook ids, used sign-in states. Keys are short ASCII strings; values are strings.
/// </summary>
public interface INineCache
{
    /// <summary>The value, or null when it is missing or expired.</summary>
    ValueTask<string?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Stores a value for <paramref name="ttl"/>.</summary>
    ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>Stores a value only if the key is missing or expired; true when it was stored. Must be atomic.</summary>
    ValueTask<bool> AddAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>Removes a value.</summary>
    ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default);
}
