using System.Text.Json.Nodes;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Turns high-level <see cref="VerifierOptions"/> into a per-request <see cref="PresentationRequestOptions"/>,
/// generating the nonce/state and the DCQL query from the requested claims.
/// </summary>
internal static class DemoRequestOptionsFactory
{
    // SPEC: SD-JWT VC credential format identifier is "dc+sd-jwt" (not the legacy "vc+sd-jwt");
    // media type application/dc+sd-jwt, per draft-ietf-oauth-sd-jwt-vc.
    private const string SdJwtVcFormat = "dc+sd-jwt";

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
            DcqlQueryJson = BuildDcqlQuery(claims, options.ExpectedVct),
            ResponseUri = responseUri,
            ResponseMode = options.ResponseMode,
            RequestLifetime = options.SessionLifetime,
            ClientMetadataJson = BuildClientMetadata(options, responseEncryptionJwk),
        };
    }

    // SPEC: OpenID4VP 1.0 uses DCQL (Digital Credentials Query Language), not Presentation Exchange.
    private static string BuildDcqlQuery(IEnumerable<string> claims, string? expectedVct)
    {
        var claimsArray = new JsonArray();
        foreach (var claim in claims)
        {
            claimsArray.Add(new JsonObject { ["path"] = new JsonArray(claim) });
        }

        var query = new JsonObject
        {
            ["credentials"] = new JsonArray(
                new JsonObject
                {
                    ["id"] = "credential",
                    ["format"] = SdJwtVcFormat,
                    ["meta"] = new JsonObject
                    {
                        ["vct_values"] = new JsonArray(expectedVct ?? DefaultVct),
                    },
                    ["claims"] = claimsArray,
                }),
        };

        return query.ToJsonString(JsonDefaults.Relaxed);
    }

    private static string BuildClientMetadata(VerifierOptions options, JsonObject? responseEncryptionJwk)
    {
        // HAIP verifier display metadata (OpenID4VP client_metadata) shown on the wallet consent screen.
        var metadata = new JsonObject
        {
            ["client_name"] = "Tessio Demo Verifier",
            ["client_id"] = options.ClientId,
        };

        if (responseEncryptionJwk is not null)
        {
            // SPEC: OpenID4VP 1.0 §8.3 — the wallet encrypts direct_post.jwt responses to a key from
            // client_metadata.jwks (use=enc); the verifier lists its supported content encryptions.
            metadata["jwks"] = new JsonObject { ["keys"] = new JsonArray(responseEncryptionJwk.DeepClone()) };
            metadata["encrypted_response_enc_values_supported"] = new JsonArray("A128CBC-HS256");
        }

        return metadata.ToJsonString(JsonDefaults.Relaxed);
    }
}
