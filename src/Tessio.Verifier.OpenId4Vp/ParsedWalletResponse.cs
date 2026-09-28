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

    /// <summary>
    /// Whether the response arrived encrypted, as a <c>direct_post.jwt</c> <c>response</c> parameter holding
    /// a JWE, rather than as plain <c>vp_token</c> and <c>state</c> form fields. A <c>response</c> parameter
    /// that is not a JWE is refused by the parser, so true here means it really was encrypted.
    /// </summary>
    /// <remarks>
    /// The parser accepts either shape, because only the session knows which one it asked for. The
    /// built-in callback compares this with the <c>response_mode</c> its request asked for and refuses a
    /// mismatch before completing. A host with its own callback should do the same, since a plaintext
    /// response to a request that asked for encryption does not answer that request.
    /// </remarks>
    public bool Encrypted { get; init; }
}
