using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Parses an OpenID4VP wallet response (<c>direct_post</c> or <c>direct_post.jwt</c>) and extracts the presented credentials.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public interface IPresentationResponseParser
{
    /// <summary>Parses the wallet response and returns the credentials it presented.</summary>
    /// <param name="response">The wallet response as captured by the hosting layer.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<IReadOnlyList<PresentedCredential>> ParseAsync(
        WalletResponseData response,
        CancellationToken ct = default);
}
