// What belongs here: the storage contract for derived response-key salts, which the consumer implements
// over storage every instance shares.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Keeps the salt each request's response-encryption key was derived from, keyed by that key's <c>kid</c>,
/// so whichever instance receives the wallet's response can derive the key again.
/// </summary>
/// <remarks>
/// A salt is not secret: without the master it derives nothing. Both members are synchronous because the
/// library resolves the key through a synchronous callback inside response decryption.
/// </remarks>
public interface IResponseKeySaltStore
{
    /// <summary>
    /// Stores <paramref name="salt"/> for <paramref name="kid"/> until <paramref name="expiresAt"/>. It must be
    /// visible to every instance when this returns, because the request naming the key is sent right after.
    /// </summary>
    void Save(string kid, byte[] salt, DateTimeOffset expiresAt);

    /// <summary>
    /// The salt stored for <paramref name="kid"/> and its expiry, or null when there is none. The store
    /// treats an expired salt as absent, so returning one is allowed.
    /// </summary>
    /// <remarks>
    /// <paramref name="kid"/> is the value the wallet's response names. It has the shape of a kid the store
    /// issues, 43 base64url characters, and is otherwise unchecked: parameterise the lookup and never build a
    /// query from it. Match it exactly; a lookup that ignores case is tolerated, and finds no key for a kid
    /// whose case was changed.
    /// </remarks>
    (byte[] Salt, DateTimeOffset ExpiresAt)? Find(string kid);
}
