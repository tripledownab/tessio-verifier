using System.Collections.Concurrent;

namespace Tessio.Verifier.Core;

/// <summary>
/// Validated status lists, each until the instant <see cref="StatusListValues.CacheUntil"/> gave it. Only
/// successes are stored, so a list that could not be resolved stays fail-closed on every attempt. Expired
/// entries are evicted whenever a new one is stored, which keeps the cache bounded to the lists still live.
/// </summary>
/// <typeparam name="T">What validation produced and later checks need.</typeparam>
internal sealed class StatusListCache<T>
    where T : class
{
    private sealed record Entry(T Value, DateTimeOffset Until);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    public T? Get(string key, DateTimeOffset now) =>
        _entries.TryGetValue(key, out var entry) && entry.Until > now ? entry.Value : null;

    public void Set(string key, T value, DateTimeOffset until, DateTimeOffset now)
    {
        if (until <= now)
        {
            return;
        }

        foreach (var (existing, entry) in _entries)
        {
            if (entry.Until <= now)
            {
                _entries.TryRemove(existing, out _);
            }
        }

        _entries[key] = new Entry(value, until);
    }
}
