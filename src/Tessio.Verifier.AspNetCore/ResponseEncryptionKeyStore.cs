using System.Collections.Concurrent;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Holds one response-encryption key pair per session, for the lifetime of that session.
/// </summary>
/// <remarks>
/// <para>
/// The key must be ephemeral per authorization request: OpenID4VP 1.0 §8.3 and HAIP 1.0 §5 require it,
/// and the conformance suite fails a verifier that reuses one. The reasons are real rather than
/// procedural. A single long-lived key means its compromise retrospectively exposes every response
/// ever encrypted against it, and a stable advertised public key is a correlation handle that ties
/// separate presentations to one verifier.
/// </para>
/// <para>
/// The private half never leaves memory and never reaches disk. It exists from
/// <c>{prefix}/start</c> until the wallet responds or the session expires, typically minutes. This
/// mirrors <see cref="RequestObjectStore"/>, which holds the signed request the same way and for the
/// same span.
/// </para>
/// <para>
/// <b>Single process only.</b> A second instance cannot decrypt a response encrypted against a key it
/// never generated. Multi-instance deployments need one of the options in <c>docs/going-live.md</c>;
/// the recommended one derives the key per session from a single master secret so nothing per-session
/// is stored anywhere. Failing loudly is deliberate: a silent fallback to a shared key would quietly
/// reintroduce exactly the defect this type exists to remove.
/// </para>
/// </remarks>
public sealed class ResponseEncryptionKeyStore : IDisposable
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public ResponseEncryptionKeyStore(TimeProvider clock) => _clock = clock;

    /// <summary>
    /// Creates a fresh key pair for one authorization request, held until <paramref name="expiresAt"/>.
    /// </summary>
    /// <remarks>
    /// Keyed by the key's own <c>kid</c> (RFC 7638 thumbprint) rather than by session id, because for
    /// <c>direct_post.jwt</c> the session correlation handle (<c>state</c>) is inside the encrypted
    /// payload: at decryption time the only identifier available is the <c>kid</c> the wallet echoes
    /// back in the JWE header.
    /// </remarks>
    public ResponseEncryptionKeyProvider CreateForRequest(DateTimeOffset expiresAt)
    {
        EvictExpired();
        var keys = new ResponseEncryptionKeyProvider();

        if (!_entries.TryAdd(keys.KeyId, new Entry(keys, expiresAt)))
        {
            // Two fresh P-256 keys sharing a thumbprint does not happen by chance.
            keys.Dispose();
            throw new InvalidOperationException(
                $"A response-encryption key with kid '{keys.KeyId}' already exists.");
        }

        return keys;
    }

    /// <summary>The key with this <c>kid</c>, or null when it is unknown or expired.</summary>
    public ResponseEncryptionKeyProvider? Get(string? keyId) =>
        keyId is not null && _entries.TryGetValue(keyId, out var entry) && _clock.GetUtcNow() < entry.ExpiresAt
            ? entry.Keys
            : null;

    private void EvictExpired()
    {
        var now = _clock.GetUtcNow();
        foreach (var (id, entry) in _entries)
        {
            if (entry.ExpiresAt < now && _entries.TryRemove(id, out var removed))
            {
                removed.Keys.Dispose();
            }
        }
    }

    public void Dispose()
    {
        foreach (var entry in _entries.Values)
        {
            entry.Keys.Dispose();
        }

        _entries.Clear();
    }

    private sealed record Entry(ResponseEncryptionKeyProvider Keys, DateTimeOffset ExpiresAt);
}
