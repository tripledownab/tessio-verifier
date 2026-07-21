using System.Collections.Concurrent;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Holds signed request objects (JARs) for by-reference delivery: the wallet fetches them from
/// <c>{prefix}/request/{id}</c> until the request expires. Entries are evicted opportunistically.
/// </summary>
// SPEC: RFC 9101 / OpenID4VP 1.0 — with request_uri delivery the verifier must serve the signed
// request object at the referenced URL for the lifetime of the request.
internal sealed class RequestObjectStore
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public RequestObjectStore(TimeProvider clock) => _clock = clock;

    public void Put(string id, string requestObject, DateTimeOffset expiresAt)
    {
        EvictExpired();
        _entries[id] = new Entry(requestObject, expiresAt);
    }

    public string? Get(string id) =>
        _entries.TryGetValue(id, out var entry) && _clock.GetUtcNow() < entry.ExpiresAt
            ? entry.RequestObject
            : null;

    private void EvictExpired()
    {
        var now = _clock.GetUtcNow();
        foreach (var (id, entry) in _entries)
        {
            if (entry.ExpiresAt < now)
            {
                _entries.TryRemove(id, out _);
            }
        }
    }

    private sealed record Entry(string RequestObject, DateTimeOffset ExpiresAt);
}
