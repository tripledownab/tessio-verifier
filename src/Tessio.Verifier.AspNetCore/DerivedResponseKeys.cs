// What belongs here: creating a derived response key and finding it again from its stored salt, with the
// checks a stored salt and a wallet's kid must pass. Holding the keys is ResponseEncryptionKeyStore's job.
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The master and the salt store behind a <see cref="ResponseEncryptionKeyStore"/> built with
/// <see cref="ResponseKeyDerivationOptions"/>.
/// </summary>
internal sealed class DerivedResponseKeys : IDisposable
{
    // The salt drawn per request: twice the minimum, as RFC 5869 section 3.1 favours a salt as long as the
    // hash output.
    private const int SaltLength = 32;

    // Every kid a store issues is an RFC 7638 SHA-256 thumbprint: 43 base64url characters.
    private const int KeyIdLength = 43;

    private readonly byte[] _master;
    private readonly IResponseKeySaltStore _salts;

    // Held while the master is read and while it is zeroed, so no derivation reads a master half zeroed: a
    // zero master derives keys anyone holding the salt can compute. Salt store calls stay outside it.
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

    /// <summary>A key from a fresh salt, which is saved before the key is returned.</summary>
    public ResponseEncryptionKeyProvider Create(DateTimeOffset expiresAt)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var keys = new ResponseEncryptionKeyProvider(Derive(salt));
        try
        {
            _salts.Save(keys.KeyId, salt, expiresAt);
        }
        catch
        {
            keys.Dispose();
            throw;
        }

        return keys;
    }

    /// <summary>The key a live stored salt derives for <paramref name="keyId"/>, or null when there is none.</summary>
    public (ResponseEncryptionKeyProvider Keys, DateTimeOffset ExpiresAt)? Find(string keyId, DateTimeOffset now)
    {
        // Before anything else, so a disposed store answers the same whatever the kid. Derive checks again
        // under the lock, which is the check that keeps the master whole.
        ObjectDisposedException.ThrowIf(_disposed, typeof(ResponseEncryptionKeyStore));

        // The kid is the wallet's, unchecked. One that cannot be a kid a store issued never reaches the salt
        // store, so a wallet cannot send it a lookup of any length or shape.
        if (keyId.Length != KeyIdLength || !IsBase64Url(keyId)
            || _salts.Find(keyId) is not { } stored || now >= stored.ExpiresAt)
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

        var keys = new ResponseEncryptionKeyProvider(Derive(stored.Salt));
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

    private ECDsa Derive(byte[] salt)
    {
        lock (_gate)
        {
            // Inside the lock, never before it: checked outside, Dispose could zero the master between the
            // check and the derivation.
            ObjectDisposedException.ThrowIf(_disposed, typeof(ResponseEncryptionKeyStore));
            return ResponseKeyDerivation.Derive(_master, salt);
        }
    }

    private static bool IsBase64Url(string value) =>
        value.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            CryptographicOperations.ZeroMemory(_master);
        }
    }
}
