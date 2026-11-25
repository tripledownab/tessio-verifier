// What belongs here: what ResponseEncryptionKeyStore needs to derive response keys from a master that is replaced
// over time. Also the rule a generation id must meet.
namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Makes <see cref="ResponseEncryptionKeyStore"/> derive each request's key from the newest generation in
/// <see cref="Masters"/> and a fresh salt kept with that generation in <see cref="Salts"/>. The same derivation as
/// <see cref="ResponseKeyDerivationOptions"/>, with a master that can be replaced while requests are in flight.
/// </summary>
public sealed class ResponseKeyGenerationOptions
{
    /// <summary>
    /// The longest generation id, in characters. Long enough for a timestamp with a counter; short, so it fits a
    /// narrow column and a log line.
    /// </summary>
    public static readonly int MaximumGenerationLength = 64;

    /// <summary>The masters, by generation, the same in every instance that shares <see cref="Salts"/>.</summary>
    public required IResponseKeyMasters Masters { get; init; }

    /// <summary>Where the salts and their generations are kept, shared by every instance.</summary>
    public required IResponseKeyGenerationSaltStore Salts { get; init; }

    /// <summary>Whether <paramref name="generation"/> has the shape <see cref="IResponseKeyMasters.Newest"/> promises.</summary>
    public static bool IsGenerationId(string? generation) =>
        generation is { Length: > 0 } && generation.Length <= MaximumGenerationLength
        && generation.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-');
}
