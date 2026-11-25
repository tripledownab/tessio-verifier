// What belongs here: creating a derived response key and finding it again from its stored salt, with the
// checks a stored salt and a wallet's kid must pass, for one fixed master or for master generations. Holding the
// keys is ResponseEncryptionKeyStore's job.
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The master (or master generations) and the salt store behind a <see cref="ResponseEncryptionKeyStore"/> built
/// with <see cref="ResponseKeyDerivationOptions"/> or <see cref="ResponseKeyGenerationOptions"/>.
/// </summary>
internal sealed class DerivedResponseKeys : IDisposable
{
    // The salt drawn per request: twice the minimum, as RFC 5869 section 3.1 favours a salt as long as the
    // hash output.
    private const int SaltLength = 32;

    // Every kid a store issues is an RFC 7638 SHA-256 thumbprint: 43 base64url characters.
    private const int KeyIdLength = 43;

    // One fixed master, copied here and zeroed on dispose; or masters by generation, which the consumer holds.
    private readonly byte[]? _master;
    private readonly IResponseKeySaltStore? _salts;
    private readonly IResponseKeyMasters? _masters;
    private readonly IResponseKeyGenerationSaltStore? _generationSalts;

    // Held while a master is read and while the fixed one is zeroed, so no derivation reads a master half zeroed:
    // a zero master derives keys anyone holding the salt can compute. Salt store calls stay outside it.
    private readonly object _gate = new();
    private bool _disposed;

    public DerivedResponseKeys(ResponseKeyDerivationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Master);
        ArgumentNullException.ThrowIfNull(options.Salts);

        // Here as well as in Derive, so a bad master stops the host at boot rather than at the first request.
        ResponseKeyDerivation.ThrowIfUnusable(options.Master, nameof(options));

        _master = (byte[])options.Master.Clone();
        _salts = options.Salts;
    }

    public DerivedResponseKeys(ResponseKeyGenerationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Masters);
        ArgumentNullException.ThrowIfNull(options.Salts);

        _masters = options.Masters;
        _generationSalts = options.Salts;

        // Read once here, so masters that cannot derive stop the host at boot rather than at the first request.
        Newest();
    }

    /// <summary>A key from a fresh salt, which is saved before the key is returned.</summary>
    public ResponseEncryptionKeyProvider Create(DateTimeOffset expiresAt)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var (generation, master) = _masters is null ? (null, null) : Newest();
        var keys = new ResponseEncryptionKeyProvider(Derive(master, salt));
        try
        {
            if (_generationSalts is null)
            {
                _salts!.Save(keys.KeyId, salt, expiresAt);
            }
            else
            {
                _generationSalts.Save(keys.KeyId, salt, generation!, expiresAt);
            }
        }
        catch
        {
            keys.Dispose();
            throw;
        }

        return keys;
    }

    /// <summary>The key a live stored salt derives for <paramref name="keyId"/>, or null when there is none.</summary>
    /// <exception cref="ResponseKeyGenerationUnavailableException">The live salt names a generation not held here.</exception>
    public (ResponseEncryptionKeyProvider Keys, DateTimeOffset ExpiresAt)? Find(string keyId, DateTimeOffset now)
    {
        // Before anything else, so a disposed store answers the same whatever the kid. Derive checks again
        // under the lock, which is the check that keeps the master whole.
        ObjectDisposedException.ThrowIf(_disposed, typeof(ResponseEncryptionKeyStore));

        // The kid is the wallet's, unchecked. One that cannot be a kid a store issued never reaches the salt
        // store, so a wallet cannot send it a lookup of any length or shape.
        if (keyId.Length != KeyIdLength || !IsBase64Url(keyId) || FindSalt(keyId) is not { } stored || now >= stored.ExpiresAt)
        {
            return null;
        }

        // Nobody outside writes the salt store, so a stored salt that does not derive the kid it was found
        // under is not an unknown key: answering null would pass misconfiguration off as an expired session
        // or a replay. The one exception is a store that matches kids regardless of case, below.
        if (stored.Salt is null || stored.Salt.Length < ResponseKeyDerivation.MinimumSaltLength)
        {
            throw new InvalidOperationException("The salt stored for this response-encryption key is missing or too short to derive it.");
        }

        // Only for a live salt: an expired one was answered null above, whatever its generation. Nobody outside writes
        // the salt store, so a generation that is not an id is a corrupt row, not a miss.
        if (stored.Generation is not null && !ResponseKeyGenerationOptions.IsGenerationId(stored.Generation))
        {
            throw new InvalidOperationException("The generation stored for this response-encryption key is not a generation id.");
        }

        var master = stored.Generation is null
            ? null
            : _masters!.Find(stored.Generation) ?? throw new ResponseKeyGenerationUnavailableException(stored.Generation);

        var keys = new ResponseEncryptionKeyProvider(Derive(master, stored.Salt));
        if (string.Equals(keys.KeyId, keyId, StringComparison.Ordinal))
        {
            return (keys, stored.ExpiresAt);
        }

        keys.Dispose();

        // A store whose lookup ignores case found an issued key's salt for a kid the wallet changed the case
        // of. That kid was never issued, so it names no key, and it says nothing about the master.
        return string.Equals(keys.KeyId, keyId, StringComparison.OrdinalIgnoreCase)
            ? null
            : throw new InvalidOperationException(
                "The salt stored for this response-encryption key derives a different key: the master is not the one that created it.");
    }

    // The stored salt for a kid, with the generation that made it when masters come in generations.
    private (byte[]? Salt, string? Generation, DateTimeOffset ExpiresAt)? FindSalt(string keyId)
    {
        if (_generationSalts is null)
        {
            return _salts!.Find(keyId) is { } row ? (row.Salt, null, row.ExpiresAt) : null;
        }

        if (_generationSalts.Find(keyId) is not { } stored)
        {
            return null;
        }

        return (stored.Salt, stored.Generation, stored.ExpiresAt);
    }

    private (string Generation, byte[] Master) Newest()
    {
        var (generation, master) = _masters!.Newest();
        if (!ResponseKeyGenerationOptions.IsGenerationId(generation))
        {
            throw new InvalidOperationException("The newest response-key master generation id is not a generation id.");
        }

        ResponseKeyDerivation.ThrowIfUnusable(master, nameof(master));
        return (generation, master);
    }

    // With generations the master is the consumer's array, read here and not kept; without, it is this store's copy.
    private ECDsa Derive(byte[]? generationMaster, byte[] salt)
    {
        lock (_gate)
        {
            // Inside the lock, never before it: checked outside, Dispose could zero the master between the
            // check and the derivation.
            ObjectDisposedException.ThrowIf(_disposed, typeof(ResponseEncryptionKeyStore));
            return ResponseKeyDerivation.Derive(generationMaster ?? _master!, salt);
        }
    }

    private static bool IsBase64Url(string value) =>
        value.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            if (_master is not null)
            {
                CryptographicOperations.ZeroMemory(_master);
            }
        }
    }
}
