namespace Tessio.Verifier.Core;

/// <summary>
/// Per-verification context the verifier needs to validate freshness, audience, and credential type.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record VerificationContext
{
    /// <summary>The nonce the verifier issued for this presentation; must match the KB-JWT nonce.</summary>
    public required string Nonce { get; init; }

    /// <summary>The verifier's identifier; must match the KB-JWT audience.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// Optional expected credential type (SD-JWT VC <c>vct</c> claim). When null, the type check is skipped.
    /// </summary>
    public string? ExpectedVct { get; init; }
}
