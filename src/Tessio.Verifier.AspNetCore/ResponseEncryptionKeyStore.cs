using System.Collections.Concurrent;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Holds one response-encryption key pair per session, for the lifetime of that session.
/// </summary>
/// <remarks>
/// <para>
/// The key must be ephemeral per authorization request: SPEC: HAIP 1.0 §5 requires it ("Verifiers MUST
/// supply ephemeral encryption public keys specific to each Authorization Request"), which OpenID4VP 1.0
/// §5.1 allows, and the conformance suite fails a verifier that reuses one. The reasons are real rather than
/// procedural. A single long-lived key means its compromise retrospectively exposes every response
/// ever encrypted against it, and a stable advertised public key is a correlation handle that ties
/// separate presentations to one verifier.
/// </para>
/// <para>
/// By default the private half never leaves memory and never reaches disk. It exists from
/// <c>{prefix}/start</c> until the wallet responds or the session expires, typically minutes. This
/// mirrors <see cref="RequestObjectStore"/>, which holds the signed request the same way and for the
/// same span.
/// </para>
/// <para>
/// <b>Built with <see cref="ResponseKeyDerivationOptions"/></b>, the store derives each key from a master
/// secret and a fresh salt (<see cref="ResponseKeyDerivation"/>) and saves only the salt, so another
/// instance, or this one after a restart, derives the same key from it. That gives up part of the reason
/// above: while a salt is kept, the master derives its key again and decrypts a response to it that
/// someone captured, so the salt store should delete salts once they expire. Without them it is
/// <b>single process only</b>: a second instance cannot decrypt a response encrypted against a key it
/// never generated. Failing loudly is deliberate: a silent fallback to a shared key would quietly
/// reintroduce exactly the defect this type exists to remove.
/// </para>
/// </remarks>
public sealed class ResponseEncryptionKeyStore : IDisposable
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;
    private readonly DerivedResponseKeys? _derived;

    /// <summary>A store that generates each key and holds it in this process only.</summary>
    public ResponseEncryptionKeyStore(TimeProvider clock) => _clock = clock;

    /// <summary>A store that derives each key, so every instance sharing the master and the salts finds it.</summary>
    /// <exception cref="ArgumentNullException">The options, their master or their salt store is null.</exception>
    /// <exception cref="ArgumentException">
    /// The master is shorter than <see cref="ResponseKeyDerivation.MinimumMasterLength"/> bytes or all zeros.
    /// </exception>
    public ResponseEncryptionKeyStore(TimeProvider clock, ResponseKeyDerivationOptions derivation)
    {
        _clock = clock;
        _derived = new DerivedResponseKeys(derivation);
    }

    /// <summary>
    /// Creates a fresh key pair for one authorization request, held until <paramref name="expiresAt"/>.
    /// </summary>
    /// <remarks>
    /// Keyed by the key's own <c>kid</c> (RFC 7638 thumbprint) rather than by session id, because for
    /// <c>direct_post.jwt</c> the session correlation handle (<c>state</c>) is inside the encrypted
    /// payload: at decryption time the only identifier available is the <c>kid</c> the wallet echoes
    /// back in the JWE header. SPEC: OpenID4VP 1.0 §5 requires every advertised JWK to carry a
    /// <c>kid</c> and §8.3 then requires the wallet to echo it, so requiring it here (no fallback) only
    /// rejects a non-conformant response; <see cref="Get"/> returns null for an absent or unknown kid.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The store derives keys and has been disposed.</exception>
    public ResponseEncryptionKeyProvider CreateForRequest(DateTimeOffset expiresAt)
    {
        EvictExpired();
        var keys = _derived is null ? new ResponseEncryptionKeyProvider() : _derived.Create(expiresAt);

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
    /// <remarks>
    /// A derived key this process does not hold is derived again from its stored salt and kept until it
    /// expires.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The salt stored for this <c>kid</c> is too short or derives a different key, so the master differs
    /// from the one that created it, or the salt is corrupt.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The store derives keys and has been disposed.</exception>
    public ResponseEncryptionKeyProvider? Get(string? keyId)
    {
        if (keyId is null)
        {
            return null;
        }

        if (_entries.TryGetValue(keyId, out var entry))
        {
            return _clock.GetUtcNow() < entry.ExpiresAt ? entry.Keys : null;
        }

        return _derived is null ? null : Rederive(_derived, keyId);
    }

    private ResponseEncryptionKeyProvider? Rederive(DerivedResponseKeys derived, string keyId)
    {
        // Eviction otherwise runs only when a request is created, which an instance that only answers
        // callbacks never does.
        EvictExpired();
        if (derived.Find(keyId, _clock.GetUtcNow()) is not { } found)
        {
            return null;
        }

        if (_entries.TryAdd(keyId, new Entry(found.Keys, found.ExpiresAt)))
        {
            return found.Keys;
        }

        // Another thread derived it first; answer with its copy.
        found.Keys.Dispose();
        return Get(keyId);
    }

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
        // First, so no derivation adds a key while the held ones are released.
        _derived?.Dispose();
        foreach (var entry in _entries.Values)
        {
            entry.Keys.Dispose();
        }

        _entries.Clear();
    }

    private sealed record Entry(ResponseEncryptionKeyProvider Keys, DateTimeOffset ExpiresAt);
}
