using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Configuration for <see cref="WalletResponseParser"/>.</summary>
public sealed class WalletResponseParserOptions
{
    /// <summary>
    /// Private key used to decrypt <c>direct_post.jwt</c> (JWE) responses. The matching public key is
    /// advertised to wallets via <c>client_metadata.jwks</c>. Required to parse encrypted responses;
    /// plain <c>direct_post</c> responses need no key.
    /// </summary>
    public SecurityKey? ResponseDecryptionKey { get; set; }

    /// <summary>
    /// Credential format assigned to string presentations extracted from <c>vp_token</c>.
    /// Defaults to <c>dc+sd-jwt</c>, the SD-JWT VC format identifier.
    /// </summary>
    // SPEC: dc+sd-jwt presentations appear as strings in vp_token; mdoc (v0.2) would be
    // base64url-encoded and carry the mso_mdoc format identifier.
    public string PresentationFormat { get; set; } = "dc+sd-jwt";
}
