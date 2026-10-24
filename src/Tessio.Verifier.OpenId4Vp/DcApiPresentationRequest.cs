namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// One OpenID4VP request for the Digital Credentials API: the <see cref="Protocol"/> and <see cref="DataJson"/>
/// a page passes as one entry of <c>navigator.credentials.get({ digital: { requests: [...] } })</c>, with what the
/// verifier checks the response against. A host that stores requests stores all of it.
/// </summary>
public sealed record DcApiPresentationRequest
{
    /// <summary><c>openid4vp-v1-unsigned</c> or <c>openid4vp-v1-signed</c>.</summary>
    public required string Protocol { get; init; }

    /// <summary>
    /// The request's <c>data</c> object as JSON: the request parameters themselves when unsigned, or
    /// <c>{"request": "&lt;JWS&gt;"}</c> when signed.
    /// </summary>
    public required string DataJson { get; init; }

    /// <summary>The nonce the request carries, which verification of the response checks.</summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The origins of the pages that may make the request. The verifier refuses a response that came through any
    /// other. A signed request also carries them as <c>expected_origins</c>; an unsigned one carries them only here.
    /// </summary>
    public required IReadOnlyList<string> ExpectedOrigins { get; init; }

    /// <summary>When the request stops being answerable. The verifier refuses a response after it.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
