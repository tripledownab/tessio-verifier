namespace Tessio.Verifier.Core;

/// <summary>
/// A single verification failure.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record VerificationError
{
    /// <summary>Machine-readable failure code (stable identifier used for log/metric grouping).</summary>
    public required string Code { get; init; }

    /// <summary>Human-readable failure message.</summary>
    public required string Message { get; init; }
}
