namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Host-agnostic representation of an inbound wallet response to the verifier's <c>response_uri</c>.
/// Decouples the protocol parser from any specific HTTP framework.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Exactly one of <see cref="Form"/> (for <c>direct_post</c>) or
/// <see cref="Body"/> (for <c>direct_post.jwt</c>) is populated, per the request's
/// <see cref="ResponseMode"/>.
/// </remarks>
// SPEC: OpenID4VP 1.0 §8 (Response). Cleartext form POST or JWE-wrapped JWT body.
public sealed record WalletResponseData
{
    /// <summary>
    /// Request content-type. Canonical values: <c>application/x-www-form-urlencoded</c>
    /// (for <see cref="ResponseMode.DirectPost"/>) or <c>application/jwt</c>
    /// (for <see cref="ResponseMode.DirectPostJwt"/>).
    /// </summary>
    public required string ContentType { get; init; }

    /// <summary>
    /// URL-decoded form fields for <c>direct_post</c> responses. Multi-valued because HTTP form encoding
    /// permits repeated keys; OpenID4VP responses use single values per key in practice. Empty for
    /// non-form content-types.
    /// </summary>
    public required IReadOnlyDictionary<string, IReadOnlyList<string>> Form { get; init; }

    /// <summary>
    /// Raw request body bytes for <c>direct_post.jwt</c> responses (the JWE payload).
    /// Empty for form-urlencoded content-types.
    /// </summary>
    public required ReadOnlyMemory<byte> Body { get; init; }
}
