namespace Tessio.Verifier.Core;

/// <summary>
/// Information about the credential's issuer as observed during verification.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record IssuerInfo
{
    /// <summary>The issuer identifier from the credential (e.g., HTTPS URI or X.509 subject).</summary>
    public required string Identifier { get; init; }

    /// <summary>
    /// Whether the issuer chains to a trusted root. See <see cref="VerificationResult.IsValid"/> for the overall verdict.
    /// </summary>
    public required bool Trusted { get; init; }

    /// <summary>
    /// How the issuer's signing key was resolved. Canonical values:
    /// <c>"jwt-vc-issuer-metadata"</c> (web resolution via the <c>iss</c> HTTPS URI) or
    /// <c>"x5c"</c> (X.509 chain carried in the credential header).
    /// </summary>
    // SPEC: SD-JWT VC issuer key resolution — two mechanisms (JWT VC Issuer Metadata + X.509).
    public required string KeyResolutionMethod { get; init; }
}
