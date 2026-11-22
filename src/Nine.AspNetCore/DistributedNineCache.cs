using Microsoft.Extensions.Caching.Distributed;

namespace Nine.AspNetCore;

/// <summary>
/// <see cref="INineCache"/> over ASP.NET Core's <see cref="IDistributedCache"/> (Redis, SQL Server, …), so
/// hybrid verification answers, revocation markers and processed webhook ids are shared by every server.
/// <para>
/// <see cref="IDistributedCache"/> has no atomic "add if absent", so <see cref="AddAsync"/> is atomic within
/// this process and a get-then-set across processes: two servers receiving the same webhook in the same
/// millisecond could both process it. When that matters, register your own <see cref="INineCache"/> whose
/// <c>AddAsync</c> is atomic (Redis <c>SET NX PX</c>, a SQL unique key).
/// </para>
/// </summary>
public sealed class DistributedNineCache : INineCache
{
    private readonly IDistributedCache _cache;
    private readonly SemaphoreSlim[] _locks = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    /// <summary>Wraps a distributed cache.</summary>
    public DistributedNineCache(IDistributedCache cache) => _cache = cache ?? throw new ArgumentNullException(nameof(cache));

    /// <inheritdoc/>
    public async ValueTask<string?> GetAsync(string key, CancellationToken cancellationToken = default) =>
        await _cache.GetStringAsync(key, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc/>
    public async ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default) =>
        await _cache.SetStringAsync(key, value, Expiry(ttl), cancellationToken).ConfigureAwait(false);

    /// <inheritdoc/>
    public async ValueTask<bool> AddAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        var gate = _locks[(int)((uint)StringComparer.Ordinal.GetHashCode(key) % _locks.Length)];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (await _cache.GetStringAsync(key, cancellationToken).ConfigureAwait(false) is not null)
            {
                return false;
            }
            await _cache.SetStringAsync(key, value, Expiry(ttl), cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default) =>
        await _cache.RemoveAsync(key, cancellationToken).ConfigureAwait(false);

    private static DistributedCacheEntryOptions Expiry(TimeSpan ttl) =>
        new() { AbsoluteExpirationRelativeToNow = ttl > TimeSpan.Zero ? ttl : TimeSpan.FromSeconds(1) };
}
