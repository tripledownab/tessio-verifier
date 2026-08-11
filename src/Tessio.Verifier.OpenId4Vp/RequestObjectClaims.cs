using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Assembles the claims of an OpenID4VP authorization request object, shared by the signed builder and
/// the demo builder.
/// </summary>
/// <remarks>
/// One assembler, deliberately. Both builders used to construct these claims independently, in
/// different order, and a duplicate detector cannot see that they are the same object. The risk is not
/// abstract: a protocol member added to the signed path and missed in the demo path makes Mock mode
/// stop resembling Live, which is precisely how this library advertised a content encryption no wallet
/// would choose for months without a single test noticing.
/// </remarks>
// SPEC: OpenID4VP 1.0 §5 (Authorization Request), §5.8 (aud), RFC 9101 (JAR).
internal static class RequestObjectClaims
{
    /// <summary>Builds the request object claims for the given options and validity window.</summary>
    public static JsonObject Build(
        PresentationRequestOptions options, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var payload = new JsonObject
        {
            ["client_id"] = options.ClientId,
            ["response_type"] = "vp_token",
            ["response_mode"] = options.ResponseMode == ResponseMode.DirectPostJwt
                ? "direct_post.jwt"
                : "direct_post",
            ["response_uri"] = options.ResponseUri.ToString(),
            ["nonce"] = options.Nonce,
            ["dcql_query"] = JsonNode.Parse(options.DcqlQueryJson),
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),

            // SPEC: OpenID4VP 1.0 §5.8 — aud is "https://self-issued.me/v2" under static wallet
            // discovery. The demo builder omitted this, which is one of the divergences that made a
            // demo request subtly unlike a real one.
            ["aud"] = "https://self-issued.me/v2",
        };

        if (options.State is not null)
        {
            payload["state"] = options.State;
        }

        if (options.ClientMetadataJson is not null)
        {
            payload["client_metadata"] = JsonNode.Parse(options.ClientMetadataJson);
        }

        // SPEC: OpenID4VP 1.0 §5.1 / Annex B.3.3 — transaction_data is an array of base64url-encoded
        // JSON objects, and the KB-JWT hashes are computed over these exact strings.
        if (options.TransactionDataJson is not null)
        {
            payload["transaction_data"] = JsonNode.Parse(options.TransactionDataJson);
        }

        return payload;
    }
}
