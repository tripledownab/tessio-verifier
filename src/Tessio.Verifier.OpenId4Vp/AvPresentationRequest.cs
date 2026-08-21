namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// A built EU Age Verification authorization request, ready to be delivered to the Age Verification App.
/// Its parameters ride directly in <see cref="AuthorizationRequestUri"/>; there is no request object.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a sibling of <see cref="PresentationRequest"/> rather than a third shape within it.
/// <see cref="PresentationRequest"/> is a frozen contract (contracts-v0) describing "a sealed hierarchy
/// with exactly two concrete shapes", and every one of its shapes carries a required
/// <c>SignedRequestObject</c>. An AV request has none, so it cannot be expressed there without either
/// breaking exhaustive pattern matching for existing consumers or storing an empty string in a property
/// the next reader would trust.
/// </para>
/// <para>
/// The overlap with <see cref="PresentationRequest"/> is therefore structural, not accidental: this type
/// is what remains once the JAR is removed. Keep it that way. If a future profile needs a third variation,
/// that is the signal to design a common abstraction, not to widen this one.
/// </para>
/// </remarks>
// SPEC: EU AV Profile, Annex A A.6 — "RP MUST send the request by value (i.e., support for JAR is not
// required)", and the A.11 example carries plain query parameters with no `request` parameter at all.
public sealed record AvPresentationRequest
{
    /// <summary>
    /// Verifier identifier echoed from <see cref="PresentationRequestOptions.ClientId"/>. Under this
    /// profile it takes the form <c>redirect_uri:&lt;response_uri&gt;</c>.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Per-request nonce echoed from <see cref="PresentationRequestOptions.Nonce"/>. The verifier retains
    /// this to check the nonce the wallet commits to in its device signature.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>Optional state echoed from <see cref="PresentationRequestOptions.State"/>.</summary>
    /// <remarks>
    /// Optional in the profile, but it is how a verifier with a fixed <c>response_uri</c> correlates the
    /// response to its session. Omit it only if correlation is carried some other way.
    /// </remarks>
    public string? State { get; init; }

    /// <summary>
    /// Wallet-facing URI carrying every request parameter in its query string. Encode as a QR code or
    /// deep link.
    /// </summary>
    public required Uri AuthorizationRequestUri { get; init; }

    /// <summary>
    /// Absolute expiration of this request (UTC), for session cleanup.
    /// </summary>
    /// <remarks>
    /// <b>Advisory, and more so than under the JAR profiles.</b> A signed request carries an <c>exp</c>
    /// claim, so a conformant wallet declines to answer a stale one. This profile has no request object
    /// and therefore no <c>exp</c>, so nothing on the wallet side prevents a late answer. Whether one is
    /// accepted is entirely the consuming verifier's decision, and this type does not make it: a verifier
    /// that grants access on a completed check should compare this value against arrival time itself.
    /// </remarks>
    public required DateTimeOffset ExpiresAt { get; init; }
}
