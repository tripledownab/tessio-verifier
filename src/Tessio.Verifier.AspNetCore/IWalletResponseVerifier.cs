using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Parses and verifies a wallet authorization response against the session it answers, using the
/// expectations carried by that session's own request. This is the public multi-tenant seam: one process
/// verifies callbacks for any number of tenants without reading the process-wide <see cref="VerifierOptions"/>,
/// because each session's request already pins the audience (<c>client_id</c>), nonce, response mode and
/// the requested format / <c>vct</c> / docType.
/// </summary>
/// <remarks>
/// Register your own <see cref="IStateCorrelatingSessionStore"/>, correlate the incoming response to a
/// session yourself (by <c>state</c>), then hand both here. The implementation is stateless and safe to
/// resolve as a singleton and call concurrently. It does not complete the session: the host records the
/// returned <see cref="VerificationResult"/>.
/// </remarks>
public interface IWalletResponseVerifier
{
    /// <summary>
    /// Parses <paramref name="response"/> (picking SD-JWT vs mdoc from the session's request, so mixed-format
    /// tenants share one process) and verifies every presented credential against <paramref name="session"/>.
    /// A malformed or undecryptable response yields an invalid result (error code <c>response_invalid</c>)
    /// rather than throwing, so the caller can always complete the session with the outcome.
    /// </summary>
    Task<VerificationResult> VerifyAsync(
        VerificationSession session,
        WalletResponseData response,
        CancellationToken ct = default);
}
