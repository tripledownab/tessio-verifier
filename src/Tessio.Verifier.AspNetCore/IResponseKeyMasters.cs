// What belongs here: the contract for a response-key master that is replaced over time, which the consumer
// implements over wherever its masters live.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The masters a <see cref="ResponseEncryptionKeyStore"/> built with <see cref="ResponseKeyGenerationOptions"/>
/// derives from, one per generation. New keys derive from the newest generation; a stored salt names the generation
/// it was made with. Only that generation's master derives its key again.
/// </summary>
/// <remarks>
/// Replacing the master on a schedule bounds how long a copied master stays useful. Keep an old generation until
/// every salt made with it has expired, then delete it: a key whose generation is gone cannot be derived again.
/// The store reads a returned master during the call that asked for it and keeps no reference to the array, so
/// the implementation may keep and reuse it. Never clear an array another thread may still be deriving with,
/// including at shutdown, when a request can still be running. Both members are synchronous because the store
/// resolves keys inside a synchronous callback during response decryption.
/// </remarks>
public interface IResponseKeyMasters
{
    /// <summary>
    /// The newest generation's id and master. The id is 1 to <see cref="ResponseKeyGenerationOptions.MaximumGenerationLength"/>
    /// characters of letters, digits, <c>.</c>, <c>_</c> and <c>-</c>; the master is at least
    /// <see cref="ResponseKeyDerivation.MinimumMasterLength"/> bytes and not all zeros.
    /// </summary>
    (string Generation, byte[] Master) Newest();

    /// <summary>
    /// The master of <paramref name="generation"/> (the same shape <see cref="Newest"/> promises); null when this
    /// instance does not hold it because it is not yet loaded or was deleted. Another instance may already derive with
    /// a generation this one has not read, so look again before answering null.
    /// </summary>
    byte[]? Find(string generation);
}
