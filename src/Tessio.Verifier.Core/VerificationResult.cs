namespace Tessio.Verifier.Core;

/// <summary>
/// Outcome of credential verification. Carries the disclosed claims, issuer info, and any failure reasons.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record VerificationResult
{
    /// <summary>True when signature, disclosures, key binding, and trust checks all pass.</summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// The claims the holder elected to disclose, keyed by claim name. Empty when <see cref="IsValid"/> is false.
    /// Values are dynamic JSON values represented as <see cref="object"/> (string, number, bool, list, dict, or null).
    /// </summary>
    public required IReadOnlyDictionary<string, object> DisclosedClaims { get; init; }

    /// <summary>Information about the credential issuer and how its key was resolved.</summary>
    public required IssuerInfo Issuer { get; init; }

    /// <summary>Verification failures; empty when <see cref="IsValid"/> is true.</summary>
    public required IReadOnlyList<VerificationError> Errors { get; init; }
}
