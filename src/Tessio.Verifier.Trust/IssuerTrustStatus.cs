namespace Tessio.Verifier.Trust;

/// <summary>
/// Outcome of trust-list resolution for a credential issuer.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record IssuerTrustStatus
{
    /// <summary>True when the issuer chains to a trusted root.</summary>
    public required bool Trusted { get; init; }

    /// <summary>Identifier of the trust list that produced the verdict (URI, file path, or implementation-defined).</summary>
    public string? TrustListSource { get; init; }

    /// <summary>Human-readable reason when <see cref="Trusted"/> is false; null when trusted.</summary>
    public string? Reason { get; init; }
}
