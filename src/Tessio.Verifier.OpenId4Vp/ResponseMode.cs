namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// OpenID4VP 1.0 response delivery modes supported by this library.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Wire-value mapping is an implementation concern;
/// values map to the OpenID4VP <c>response_mode</c> parameter as <c>direct_post</c> / <c>direct_post.jwt</c>.
/// </remarks>
// SPEC: OpenID4VP 1.0 §6.2 (Response Modes "direct_post" and "direct_post.jwt"). HAIP defaults to "direct_post.jwt" (JWE).
public enum ResponseMode
{
    /// <summary>
    /// Cleartext form POST to <c>response_uri</c> (<c>direct_post</c>).
    /// </summary>
    DirectPost = 0,

    /// <summary>
    /// JWE-encrypted JWT POST to <c>response_uri</c> (<c>direct_post.jwt</c>). HAIP default.
    /// </summary>
    DirectPostJwt = 1,
}
