namespace Tessio.Verifier.Core;

/// <summary>
/// Outcome of credential verification. Carries the disclosed claims, issuer info, and any failure reasons.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs may be added as init-only
/// properties, which is how <see cref="CredentialType"/> arrived. No existing member changes.
/// </remarks>
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

    /// <summary>
    /// The credential type that was actually presented: the <c>vct</c> for SD-JWT VC, the
    /// <c>docType</c> for mdoc. Null when verification failed before the type could be read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What was PRESENTED, not what was requested. The caller already knows what it asked for. Once a
    /// request names several types, which one arrived is a fact only the verifier holds, and without
    /// this the only way to learn it is to read a mismatch message, which exists only when the type was
    /// wrong. A caller recording what a holder presented, or choosing which claim path to read an answer
    /// from, needs it on the passing path too.
    /// </para>
    /// <para>
    /// Null means "not established", never "the credential declared none". A signature that fails before
    /// the payload is parsed leaves nothing to report, and an empty string there would be the stronger
    /// and false claim.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves
    /// as it did. Additive in the sense the frozen contract permits: no existing member changes.
    /// </para>
    /// </remarks>
    public string? CredentialType { get; init; }

    /// <summary>
    /// A passing result carrying the disclosed claims and resolved issuer. Convenience for tests and
    /// self-driving hosts that synthesize results rather than fully initializing every required member.
    /// </summary>
    public static VerificationResult Valid(IReadOnlyDictionary<string, object> disclosedClaims, IssuerInfo issuer)
    {
        ArgumentNullException.ThrowIfNull(disclosedClaims);
        ArgumentNullException.ThrowIfNull(issuer);
        return new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = disclosedClaims,
            Issuer = issuer,
            Errors = [],
        };
    }

    /// <summary>A failing result carrying one error and, optionally, the issuer that was resolved.</summary>
    public static VerificationResult Invalid(VerificationError error, IssuerInfo? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        return Invalid([error], issuer);
    }

    /// <summary>
    /// A failing result carrying every accumulated error and, optionally, the resolved issuer. Falls back
    /// to <see cref="IssuerInfo.Unknown"/> when no issuer was reached.
    /// </summary>
    public static VerificationResult Invalid(IReadOnlyList<VerificationError> errors, IssuerInfo? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(errors);
        return new VerificationResult
        {
            IsValid = false,
            DisclosedClaims = new Dictionary<string, object>(StringComparer.Ordinal),
            Issuer = issuer ?? IssuerInfo.Unknown,
            Errors = errors,
        };
    }
}
