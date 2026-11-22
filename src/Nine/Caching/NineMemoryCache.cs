using System.Collections.Concurrent;

namespace Nine;

/// <summary>
/// An in-process <see cref="INineCache"/> (thread-safe, atomic <see cref="AddAsync"/>). Right for one
/// server; with several, use a shared store (the ASP.NET Core package adapts <c>IDistributedCache</c>).
/// </summary>
public sealed class NineMemoryCache : INineCache
{
    private readonly ConcurrentDictionary<string, Entry> _items = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly int _maxEntries;
    private readonly object _addLock = new();

    private sealed record Entry(string Value, DateTimeOffset ExpiresAt);

    /// <summary>Creates a cache holding at most <paramref name="maxEntries"/> items (the soonest to expire go first).</summary>
    public NineMemoryCache(int maxEntries = 10_000, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _maxEntries = maxEntries;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>How many items are held (expired ones included until they are swept).</summary>
    public int Count => _items.Count;

    /// <inheritdoc/>
    public ValueTask<string?> GetAsync(string key, CancellationToken cancellationToken = default) => new(Live(key)?.Value);

    /// <inheritdoc/>
    public ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        _items[key] = new Entry(value, _time.GetUtcNow() + ttl);
        Trim();
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<bool> AddAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        bool added;
        lock (_addLock)
        {
            added = Live(key) is null;
            if (added)
            {
                _items[key] = new Entry(value, _time.GetUtcNow() + ttl);
            }
        }
        if (added)
        {
            Trim();
        }
        return new ValueTask<bool>(added);
    }

    /// <inheritdoc/>
    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        _items.TryRemove(key, out _);
        return ValueTask.CompletedTask;
    }

    private Entry? Live(string key)
    {
        if (!_items.TryGetValue(key, out var entry))
        {
            return null;
        }
        if (entry.ExpiresAt <= _time.GetUtcNow())
        {
            _items.TryRemove(new KeyValuePair<string, Entry>(key, entry));
            return null;
        }
        return entry;
    }

    private void Trim()
    {
        if (_items.Count <= _maxEntries)
        {
            return;
        }
        lock (_addLock)
        {
            var now = _time.GetUtcNow();
            foreach (var (key, entry) in _items)
            {
                if (entry.ExpiresAt <= now)
                {
                    _items.TryRemove(new KeyValuePair<string, Entry>(key, entry));
                }
            }
            var excess = _items.Count - _maxEntries;
            if (excess > 0)
            {
                foreach (var (key, _) in _items.OrderBy(i => i.Value.ExpiresAt).Take(excess + _maxEntries / 10))
                {
                    _items.TryRemove(key, out _);
                }
            }
        }
    }
}
