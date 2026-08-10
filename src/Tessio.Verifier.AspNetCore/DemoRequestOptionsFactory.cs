using System.Text.Json.Nodes;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Turns high-level <see cref="VerifierOptions"/> into a per-request <see cref="PresentationRequestOptions"/>,
/// generating the nonce/state and the DCQL query from the requested claims.
/// </summary>
internal static class DemoRequestOptionsFactory
{
    /// <summary>Credential type used when <see cref="VerifierOptions.ExpectedVct"/> is unset.</summary>
    internal const string DefaultVct = "https://demo-issuer.tessio.dev/vct/identity";

    public static PresentationRequestOptions Create(
        VerifierOptions options, Uri responseUri, JsonObject? responseEncryptionJwk = null)
    {
        var claims = options.RequestedClaims is { Count: > 0 }
            ? options.RequestedClaims
            : new[] { "age_over_18" };

        return new PresentationRequestOptions
        {
            ClientId = options.ClientId,
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = options.CredentialFormat == "mso_mdoc"
                ? BuildMdocDcqlQuery(claims, options.ExpectedDocType, options.MdocNamespace)
                : BuildDcqlQuery(claims, options.ExpectedVct),
            ResponseUri = responseUri,
            ResponseMode = options.ResponseMode,
            RequestLifetime = options.SessionLifetime,
            ClientMetadataJson = BuildClientMetadata(options, responseEncryptionJwk),
            TransactionDataJson = BuildTransactionData(options),
        };
    }

    // The DCQL query shapes live in the public Dcql helper so hosts building their own requests share
    // exactly the query the verifier expects.
    private static string BuildDcqlQuery(IEnumerable<string> claims, string? expectedVct) =>
        Dcql.SdJwtVc(expectedVct ?? DefaultVct, claims.ToArray());

    private static string BuildMdocDcqlQuery(IEnumerable<string> claims, string docType, string mdocNamespace) =>
        Dcql.Mdoc(docType, mdocNamespace, claims.ToArray());

    // SPEC: OpenID4VP 1.0 §5.1/Annex B.3.3 — transaction_data is an array of base64url-encoded JSON
    // objects; each needs type and credential_ids. The KB-JWT hashes are computed over these exact strings.
    private static string? BuildTransactionData(VerifierOptions options)
    {
        if (options.TransactionData.Count == 0)
        {
            return null;
        }

        // Serialized via JsonSerializer, not a JsonArray of strings: on net8, implicitly converted
        // JsonValues fail to serialize under custom JsonSerializerOptions.
        var entries = new List<string>();
        foreach (var entry in options.TransactionData)
        {
            var node = (JsonObject)JsonNode.Parse(entry)!;
            node["credential_ids"] ??= JsonNode.Parse("""["credential"]""");
            entries.Add(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(node.ToJsonString(JsonDefaults.Relaxed)));
        }

        return System.Text.Json.JsonSerializer.Serialize(entries);
    }

    private static string BuildClientMetadata(VerifierOptions options, JsonObject? responseEncryptionJwk)
    {
        // HAIP verifier display metadata (OpenID4VP client_metadata) shown on the wallet consent screen.
        //
        // client_id deliberately does NOT appear here. It is an authorization request parameter, not
        // verifier metadata, and OpenID4VP 1.0 §5.1 enumerates what client_metadata may carry.
        var metadata = new JsonObject
        {
            ["client_name"] = "Tessio Demo Verifier",

            // SPEC: OpenID4VP 1.0 Appendix B.2.2 (mdoc) and B.3.4 (SD-JWT VC) — vp_formats_supported is
            // REQUIRED, keyed by credential format. Omitting it is what the conformance suite fails on,
            // and a wallet cannot otherwise learn which signature algorithms we accept.
            ["vp_formats_supported"] = BuildVpFormatsSupported(options.CredentialFormat),
        };

        if (responseEncryptionJwk is not null)
        {
            // SPEC: OpenID4VP 1.0 §8.3 — the wallet encrypts direct_post.jwt responses to a key from
            // client_metadata.jwks (use=enc); the verifier lists its supported content encryptions.
            metadata["jwks"] = new JsonObject { ["keys"] = new JsonArray(responseEncryptionJwk.DeepClone()) };

            // SPEC: HAIP 1.0 §5 requires BOTH A128GCM and A256GCM. This previously advertised only
            // A128CBC-HS256, which is legal OpenID4VP and fails HAIP: it offers neither required value.
            // Nothing else had to change, because decryption dispatches on the wallet's chosen enc and
            // Microsoft.IdentityModel already provides AES-GCM (see EcdhEsJweDecryptor).
            metadata["encrypted_response_enc_values_supported"] = new JsonArray("A128GCM", "A256GCM");
        }

        return metadata.ToJsonString(JsonDefaults.Relaxed);
    }

    /// <summary>
    /// The signature algorithms we accept, keyed by credential format, for <c>vp_formats_supported</c>.
    /// </summary>
    // SD-JWT VC names JWS algorithms as strings; mdoc names COSE algorithms as integers, where -7 is
    // ES256 (RFC 9053 §2.1). We verify ES256 on both paths, so each list has exactly one entry.
    private static JsonObject BuildVpFormatsSupported(string credentialFormat) =>
        credentialFormat == "mso_mdoc"
            ? new JsonObject
            {
                ["mso_mdoc"] = new JsonObject
                {
                    ["issuerauth_alg_values"] = new JsonArray(-7),
                    ["deviceauth_alg_values"] = new JsonArray(-7),
                },
            }
            : new JsonObject
            {
                ["dc+sd-jwt"] = new JsonObject
                {
                    ["sd-jwt_alg_values"] = new JsonArray("ES256"),
                    ["kb-jwt_alg_values"] = new JsonArray("ES256"),
                },
            };
}
