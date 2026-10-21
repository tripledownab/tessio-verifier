// What belongs here: what ResponseEncryptionKeyStore needs to derive response keys instead of holding them.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Makes <see cref="ResponseEncryptionKeyStore"/> derive each request's key from <see cref="Master"/> and a
/// fresh salt kept in <see cref="Salts"/>, so the key outlives the process that created it.
/// </summary>
public sealed class ResponseKeyDerivationOptions
{
    /// <summary>
    /// The master secret, at least <see cref="ResponseKeyDerivation.MinimumMasterLength"/> bytes, the same in
    /// every instance that shares <see cref="Salts"/>. The store copies it at construction.
    /// </summary>
    public required byte[] Master { get; init; }

    /// <summary>Where the salts are kept, shared by every instance.</summary>
    public required IResponseKeySaltStore Salts { get; init; }
}
