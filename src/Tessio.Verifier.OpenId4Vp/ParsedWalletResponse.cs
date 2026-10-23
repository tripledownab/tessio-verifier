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

    /// <summary>
    /// The wallet's <c>error</c> code when it answered with an Authorization Error Response instead of a
    /// presentation, for example because the holder declined; null for a presentation. When it is set,
    /// <see cref="Credentials"/> is empty. Set only by a parser with
    /// <see cref="WalletResponseParserOptions.ReadErrorResponses"/> on; any other parser throws for such a form.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 8.5: "The error response follows the rules as defined in [RFC6749]". RFC 6749
    /// section 4.1.2.1 limits the code to printable ASCII without <c>"</c> or <c>\</c>, which the parser
    /// enforces. Only the code is kept: <c>error_description</c> and <c>error_uri</c> are text the sender chose.
    /// </para>
    /// <para>
    /// The cleartext form only. Section 8.3.1 lets a wallet that is unable to encrypt send it unencrypted even
    /// when the request asked for encryption; an error sealed inside an encrypted <c>response</c> is still refused
    /// as malformed.
    /// </para>
    /// <para>
    /// It proves nothing about the holder: anyone holding the request's <c>state</c> can send one.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves as it did.
    /// </para>
    /// </remarks>
    public string? Error { get; init; }
}
