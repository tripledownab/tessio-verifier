namespace Tessio.Verifier.Core;

/// <summary>
/// A single credential extracted from a presentation, in its serialized wire form.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record PresentedCredential
{
    /// <summary>
    /// Credential format identifier. For v0.1 this is <c>"dc+sd-jwt"</c>.
    /// </summary>
    // SPEC: dc+sd-jwt, not vc+sd-jwt (SD-JWT VC media-type change, late 2024).
    public required string Format { get; init; }

    /// <summary>
    /// The credential as received on the wire (e.g., the SD-JWT VC string including disclosures
    /// and the optional Key Binding JWT, tilde-separated).
    /// </summary>
    public required string RawValue { get; init; }
}
