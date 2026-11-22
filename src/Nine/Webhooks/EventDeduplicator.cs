namespace Nine;

/// <summary>What <see cref="EventDeduplicator.ProcessAsync"/> did.</summary>
public enum EventOutcome
{
    /// <summary>First delivery; the handler succeeded. Answer 2xx.</summary>
    Processed,
    /// <summary>Already processed. Answer 2xx so 9in stops retrying.</summary>
    Duplicate,
    /// <summary>Another delivery of the same event is still running. Answer 409 so 9in tries again later.</summary>
    InProgress,
}

/// <summary>
/// Runs a webhook handler at most once per event id. 9in keeps the id on every retry and redelivery
/// and retries until it gets a 2xx (for about a day), and a retry can arrive while a slow first attempt
/// is still running. The id is claimed atomically (<see cref="INineCache.AddAsync"/>), marked done when
/// the handler succeeds, and released when it throws, so 9in's next retry processes the event.
/// </summary>
public sealed class EventDeduplicator
{
    private readonly INineCache _cache;
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _lock;
    private readonly string _prefix;

    /// <summary>Creates a deduplicator over a cache whose <see cref="INineCache.AddAsync"/> is atomic across your servers.</summary>
    /// <param name="cache">Where ids are kept.</param>
    /// <param name="ttl">How long a processed id is remembered. Default 3 days.</param>
    /// <param name="lockTime">How long a running handler holds the id before another delivery may take over. Default 5 minutes.</param>
    /// <param name="prefix">Key prefix. Default <c>nine:event:</c>.</param>
    public EventDeduplicator(INineCache cache, TimeSpan? ttl = null, TimeSpan? lockTime = null, string prefix = "nine:event:")
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _ttl = ttl ?? TimeSpan.FromDays(3);
        _lock = lockTime ?? TimeSpan.FromMinutes(5);
        _prefix = prefix;
    }

    /// <summary>Runs <paramref name="handler"/> unless the event was already processed or is being processed.</summary>
    /// <exception cref="Exception">Whatever the handler throws, after the id was released.</exception>
    public async Task<EventOutcome> ProcessAsync(string eventId, Func<CancellationToken, Task> handler, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventId);
        ArgumentNullException.ThrowIfNull(handler);
        var key = _prefix + eventId;
        if (!await _cache.AddAsync(key, "processing", _lock, cancellationToken).ConfigureAwait(false))
        {
            return await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false) == "done" ? EventOutcome.Duplicate : EventOutcome.InProgress;
        }
        try
        {
            await handler(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await _cache.RemoveAsync(key, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        await _cache.SetAsync(key, "done", _ttl, CancellationToken.None).ConfigureAwait(false);
        return EventOutcome.Processed;
    }
}
