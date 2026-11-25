// What belongs here: the failure raised when a live stored salt names a master generation this instance does not hold.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// A response-encryption key's stored salt is still live, but names a master generation that
/// <see cref="IResponseKeyMasters.Find"/> does not hold. The key cannot be derived, so the response cannot be opened.
/// </summary>
/// <remarks>
/// It is not an unknown or expired key: the salt says the key was issued and is still valid. Either the generation
/// was deleted before every salt made with it expired or this instance has not loaded it. Both are faults in how the
/// masters are kept, so it is raised rather than answered as a missing key.
/// </remarks>
public sealed class ResponseKeyGenerationUnavailableException : InvalidOperationException
{
    public ResponseKeyGenerationUnavailableException(string generation)
        : base($"The response-key master generation '{generation}' that a live stored salt names is not held by this instance.")
    {
        Generation = generation;
    }

    /// <summary>The generation the stored salt names.</summary>
    public string Generation { get; }
}
