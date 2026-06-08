using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Pluggable storage for verification sessions. The default implementation is in-memory;
/// production deployments may swap in distributed stores (Redis, SQL, etc.).
/// </summary>
/// <remarks>FROZEN contract (contracts-v0). Do not modify.</remarks>
public interface ISessionStore
{
    Task<VerificationSession> CreateAsync(
        PresentationRequestOptions options,
        CancellationToken ct = default);

    Task<VerificationSession?> GetAsync(
        string sessionId,
        CancellationToken ct = default);

    Task CompleteAsync(
        string sessionId,
        VerificationResult result,
        CancellationToken ct = default);
}
