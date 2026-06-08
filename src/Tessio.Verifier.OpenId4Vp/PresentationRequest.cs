namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// A built, JAR-signed OpenID4VP authorization request ready to be delivered to the wallet.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). This is a sealed hierarchy with exactly two concrete shapes —
/// <see cref="ByValue"/> and <see cref="ByReference"/> — corresponding to the two OpenID4VP request
/// delivery modes. Consumers must handle both via pattern matching.
/// </remarks>
// SPEC: OpenID4VP 1.0 §5.10 (Passing a Request Object by Reference) — request can be embedded (`request`)
// or referenced (`request_uri`). The two shapes below make that choice explicit at the type level.
public abstract record PresentationRequest
{
    private protected PresentationRequest() { }

    /// <summary>
    /// Verifier identifier echoed from <see cref="PresentationRequestOptions.ClientId"/>.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Per-request nonce echoed from <see cref="PresentationRequestOptions.Nonce"/>. Verifiers retain this
    /// to validate the matching nonce in the wallet's KB-JWT response.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// Optional state echoed from <see cref="PresentationRequestOptions.State"/>.
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// Wallet-facing URI carrying (by-value) or referencing (by-reference) the signed request.
    /// Encode this as a QR code or deep link.
    /// </summary>
    public required Uri AuthorizationRequestUri { get; init; }

    /// <summary>
    /// The signed JAR (RFC 9101) request object as a compact JWT. In <see cref="ByValue"/> mode this is
    /// also embedded in <see cref="AuthorizationRequestUri"/>; in <see cref="ByReference"/> mode the
    /// verifier serves this content at <see cref="ByReference.RequestUri"/>.
    /// </summary>
    public required string SignedRequestObject { get; init; }

    /// <summary>
    /// Absolute expiration of this request (UTC). Wallets reject requests with elapsed JAR <c>exp</c>;
    /// verifiers use this for session cleanup and to refuse stale wallet callbacks.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Request delivered by value: the signed JAR is embedded inline in <see cref="PresentationRequest.AuthorizationRequestUri"/>'s
    /// query string. Suitable for small requests; some wallets and transports cap inline length.
    /// </summary>
    public sealed record ByValue : PresentationRequest;

    /// <summary>
    /// Request delivered by reference: the wallet fetches the signed JAR from <see cref="RequestUri"/>.
    /// The hosting layer must serve <see cref="PresentationRequest.SignedRequestObject"/> at that URL until
    /// <see cref="PresentationRequest.ExpiresAt"/>.
    /// </summary>
    public sealed record ByReference : PresentationRequest
    {
        /// <summary>
        /// HTTPS URL where the wallet fetches the signed JAR (OpenID4VP <c>request_uri</c>).
        /// </summary>
        public required Uri RequestUri { get; init; }
    }
}
