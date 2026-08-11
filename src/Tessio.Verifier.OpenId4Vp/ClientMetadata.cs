using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builder for the OpenID4VP <c>client_metadata</c> object, producing the JSON string expected by
/// <see cref="PresentationRequestOptions.ClientMetadataJson"/>.
/// </summary>
/// <remarks>
/// One builder, deliberately. This object used to be assembled independently by the library and by
/// a consuming application, which is invisible to a duplicate detector because the two versions were structurally
/// different while meaning the same thing. They drifted, and the OpenID Foundation conformance suite
/// found the product advertising values HAIP rejects long after the library had been fixed. Anything
/// that sends a presentation request should call this rather than hand-rolling the object.
/// </remarks>
// SPEC: OpenID4VP 1.0 §5.1, narrowed by openid/OpenID4VP#233 to exactly three members. HAIP 1.0 §5
// constrains the encryption values further.
public static class ClientMetadata
{
    // SPEC: RFC 7518 — ES256 is the signature algorithm EUDI issuers and wallets use; -7 is its COSE
    // identifier (RFC 9053 §2.1), which is how mdoc names algorithms.
    private const string Es256 = "ES256";
    private const int CoseEs256 = -7;

    // Relaxed escaping keeps '+' literal in "dc+sd-jwt"; these are JWT payloads, not HTML.
    private static readonly JsonSerializerOptions Relaxed = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Builds <c>client_metadata</c> for a request in the given credential format.
    /// </summary>
    /// <param name="credentialFormat"><c>dc+sd-jwt</c> or <c>mso_mdoc</c>.</param>
    /// <param name="responseEncryptionJwk">
    /// The public half of the response-encryption key, for <c>direct_post.jwt</c>. Null for
    /// <c>direct_post</c>, where there is nothing for the wallet to encrypt to. HAIP requires
    /// encrypted responses, so in practice this is supplied.
    /// </param>
    /// <returns>The <c>client_metadata</c> JSON.</returns>
    public static string Build(string credentialFormat, JsonObject? responseEncryptionJwk = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialFormat);

        // Neither client_id nor client_name belongs here, and both used to. client_id is an
        // authorization request parameter. client_name was a display name for the consent screen, and
        // dropping it is the safer behaviour rather than a loss: under an x509 client identifier the
        // wallet takes the verifier's identity from the certificate, which is authenticated, whereas a
        // name asserted in metadata is not and would let anyone put someone else's brand on a consent
        // screen.
        var metadata = new JsonObject
        {
            // SPEC: OpenID4VP 1.0 Appendix B.2.2 (mdoc) and B.3.4 (SD-JWT VC) — REQUIRED, keyed by
            // credential format. Without it a wallet cannot learn which signature algorithms we accept,
            // and the EC reference wallet refuses the request outright.
            ["vp_formats_supported"] = VpFormatsSupported(credentialFormat),
        };

        if (responseEncryptionJwk is not null)
        {
            // SPEC: OpenID4VP 1.0 §8.3 — the wallet encrypts a direct_post.jwt response to a key from
            // client_metadata.jwks (use=enc).
            metadata["jwks"] = new JsonObject { ["keys"] = new JsonArray(responseEncryptionJwk.DeepClone()) };

            // SPEC: HAIP 1.0 §5 requires BOTH of these. Advertising only A128CBC-HS256, as both copies
            // of this code once did, offers neither required value.
            metadata["encrypted_response_enc_values_supported"] = new JsonArray("A128GCM", "A256GCM");
        }

        return metadata.ToJsonString(Relaxed);
    }

    /// <summary>The signature algorithms we accept, keyed by credential format.</summary>
    private static JsonObject VpFormatsSupported(string credentialFormat) =>
        credentialFormat == "mso_mdoc"
            ? new JsonObject
            {
                ["mso_mdoc"] = new JsonObject
                {
                    ["issuerauth_alg_values"] = new JsonArray(CoseEs256),
                    ["deviceauth_alg_values"] = new JsonArray(CoseEs256),
                },
            }
            : new JsonObject
            {
                ["dc+sd-jwt"] = new JsonObject
                {
                    ["sd-jwt_alg_values"] = new JsonArray(Es256),
                    ["kb-jwt_alg_values"] = new JsonArray(Es256),
                },
            };
}
