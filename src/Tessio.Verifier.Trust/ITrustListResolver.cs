namespace Tessio.Verifier.Trust;

/// <summary>
/// Resolves an issuer's trust status against an EU trust list (LOTL → national list → TSP → cert).
/// The open-source build ships a basic file/URL resolver; production callers swap in a managed resolver.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Do not modify.
/// </remarks>
public interface ITrustListResolver
{
    /// <param name="issuer">Issuer identifier from the credential (e.g., an HTTPS URI for JWT VC Issuer Metadata).</param>
    /// <param name="x5c">Optional X.509 chain from the credential header (DER-encoded, leaf first).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<IssuerTrustStatus> ResolveAsync(
        string issuer,
        ReadOnlyMemory<byte>[] x5c,
        CancellationToken ct = default);
}
