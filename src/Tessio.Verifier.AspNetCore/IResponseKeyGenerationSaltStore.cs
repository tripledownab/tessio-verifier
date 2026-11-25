// What belongs here: the storage contract for derived response-key salts together with the master generation that
// made each one, which the consumer implements over storage every instance shares.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Keeps the salt each request's response-encryption key was derived from and the generation of the master it was
/// derived with (<see cref="IResponseKeyMasters"/>), keyed by that key's <c>kid</c>, so whichever instance receives
/// the wallet's response can derive the key again with the right master.
/// </summary>
/// <remarks>
/// The same contract as <see cref="IResponseKeySaltStore"/> with the generation added: the salt is not secret, the
/// members are synchronous and a saved row must be visible to every instance when <see cref="Save"/> returns. The
/// <c>kid</c> passed to <see cref="Find"/> is the wallet's, so the lookup must be parameterised and exact.
/// </remarks>
public interface IResponseKeyGenerationSaltStore
{
    /// <summary>Stores <paramref name="salt"/> and <paramref name="generation"/> for <paramref name="kid"/> until <paramref name="expiresAt"/>.</summary>
    void Save(string kid, byte[] salt, string generation, DateTimeOffset expiresAt);

    /// <summary>
    /// The salt, generation and expiry stored for <paramref name="kid"/>; null when there is none. The store
    /// treats an expired salt as absent, so returning one is allowed.
    /// </summary>
    (byte[] Salt, string Generation, DateTimeOffset ExpiresAt)? Find(string kid);
}
