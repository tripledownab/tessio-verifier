using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Default <see cref="IPresentationRequestBuilder"/> for DEMO / MOCK / TEST modes. It produces a
/// well-formed, by-value OpenID4VP authorization request whose request object is an <b>unsigned</b>
/// placeholder (<c>alg=none</c>).
/// </summary>
/// <remarks>
/// This is deliberately NOT a production JAR signer — real request-object signing (RFC 9101, HSM/Key Vault)
/// is the job of <c>Tessio.Verifier.OpenId4Vp</c>. When that package registers a real
/// <see cref="IPresentationRequestBuilder"/>, it supersedes this one (registered via <c>TryAdd</c>).
/// </remarks>
internal sealed class DemoPresentationRequestBuilder : IPresentationRequestBuilder
{
    private readonly TimeProvider _clock;

    public DemoPresentationRequestBuilder(TimeProvider clock) => _clock = clock;

    public Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var now = _clock.GetUtcNow();
        var expiresAt = now + (options.RequestLifetime ?? TimeSpan.FromMinutes(5));
        var requestObject = BuildUnsignedRequestObject(options, now, expiresAt);

        // By-value delivery: the request object rides inline in the authorization request URI's `request`.
        var query = new StringBuilder()
            .Append("client_id=").Append(Uri.EscapeDataString(options.ClientId))
            .Append("&request=").Append(Uri.EscapeDataString(requestObject));
        var authorizationRequestUri = new Uri($"openid4vp://authorize?{query}");

        PresentationRequest request = new PresentationRequest.ByValue
        {
            ClientId = options.ClientId,
            Nonce = options.Nonce,
            State = options.State,
            AuthorizationRequestUri = authorizationRequestUri,
            SignedRequestObject = requestObject,
            ExpiresAt = expiresAt,
        };

        return Task.FromResult(request);
    }

    private static string BuildUnsignedRequestObject(PresentationRequestOptions options, DateTimeOffset iat, DateTimeOffset exp)
    {
        // SPEC: RFC 9101 request object; the request-object media type per OpenID4VP is "oauth-authz-req+jwt".
        // DEMO ONLY: alg=none with an empty signature — a real signer lives in Tessio.Verifier.OpenId4Vp.
        var header = new JsonObject
        {
            ["alg"] = "none",
            ["typ"] = "oauth-authz-req+jwt",
        };

        var payload = new JsonObject
        {
            ["client_id"] = options.ClientId,
            ["response_type"] = "vp_token",
            ["response_mode"] = options.ResponseMode == ResponseMode.DirectPostJwt ? "direct_post.jwt" : "direct_post",
            ["response_uri"] = options.ResponseUri.ToString(),
            ["nonce"] = options.Nonce,
            ["dcql_query"] = JsonNode.Parse(options.DcqlQueryJson),
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (options.State is not null)
        {
            payload["state"] = options.State;
        }

        if (options.ClientMetadataJson is not null)
        {
            payload["client_metadata"] = JsonNode.Parse(options.ClientMetadataJson);
        }

        var headerSegment = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header.ToJsonString(JsonDefaults.Relaxed)));
        var payloadSegment = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload.ToJsonString(JsonDefaults.Relaxed)));
        return $"{headerSegment}.{payloadSegment}.";
    }
}
