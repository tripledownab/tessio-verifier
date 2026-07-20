using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// A fully parsed wallet authorization response: the presented credentials plus the response
/// metadata the hosting layer needs for session correlation.
/// </summary>
/// <remarks>
/// <see cref="IPresentationResponseParser.ParseAsync"/> (contracts-v0) returns only the credentials;
/// this richer shape is exposed on the concrete <see cref="WalletResponseParser"/> because the
/// <c>state</c> value travels inside the JWE for <c>direct_post.jwt</c> responses and would
/// otherwise be unreachable.
/// </remarks>
public sealed record ParsedWalletResponse
{
    /// <summary>The presented credentials extracted from <c>vp_token</c>.</summary>
    public required IReadOnlyList<PresentedCredential> Credentials { get; init; }

    /// <summary>The OpenID4VP <c>state</c> echoed by the wallet, when present.</summary>
    public string? State { get; init; }
}
