using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds JAR-signed OpenID4VP 1.0 presentation requests (RFC 9101), delivered by value or by
/// reference per <see cref="PresentationRequestBuilderOptions.RequestUriBase"/>.
/// </summary>
public sealed class SignedPresentationRequestBuilder : IPresentationRequestBuilder
{
    private static readonly JsonSerializerOptions RelaxedJson = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly PresentationRequestBuilderOptions _options;
    private readonly TimeProvider _clock;

    /// <summary>Creates the builder.</summary>
    public SignedPresentationRequestBuilder(PresentationRequestBuilderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _clock = options.Clock ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var now = _clock.GetUtcNow();
        var expiresAt = now + (options.RequestLifetime ?? _options.DefaultRequestLifetime);
        var requestObject = SignRequestObject(options, now, expiresAt);

        PresentationRequest request = _options.RequestUriBase is { } requestUriBase
            ? BuildByReference(options, requestObject, expiresAt, requestUriBase)
            : BuildByValue(options, requestObject, expiresAt);

        return Task.FromResult(request);
    }

    private string SignRequestObject(PresentationRequestOptions options, DateTimeOffset iat, DateTimeOffset exp)
    {
        // SPEC: OpenID4VP 1.0 §5.2 — authorization request parameters for the vp_token flow.
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
            // SPEC: OpenID4VP 1.0 §5.8 — aud is "https://self-issued.me/v2" under static wallet discovery.
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

        if (options.TransactionDataJson is not null)
        {
            payload["transaction_data"] = JsonNode.Parse(options.TransactionDataJson);
        }

        // SPEC: OpenID4VP 1.0 §5.2 / RFC 9101 — the request object typ MUST be "oauth-authz-req+jwt".
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(
            payload.ToJsonString(RelaxedJson),
            _options.SigningCredentials,
            new Dictionary<string, object> { ["typ"] = "oauth-authz-req+jwt" });
    }

    private PresentationRequest.ByValue BuildByValue(
        PresentationRequestOptions options, string requestObject, DateTimeOffset expiresAt) => new()
    {
        ClientId = options.ClientId,
        Nonce = options.Nonce,
        State = options.State,
        // SPEC: RFC 9101 §5 — by-value delivery embeds the signed JAR in the `request` parameter.
        AuthorizationRequestUri = new Uri(
            $"{_options.AuthorizationEndpoint}?client_id={Uri.EscapeDataString(options.ClientId)}&request={Uri.EscapeDataString(requestObject)}"),
        SignedRequestObject = requestObject,
        ExpiresAt = expiresAt,
    };

    private PresentationRequest.ByReference BuildByReference(
        PresentationRequestOptions options, string requestObject, DateTimeOffset expiresAt, Uri requestUriBase)
    {
        var id = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));
        var requestUri = new Uri($"{requestUriBase.ToString().TrimEnd('/')}/{id}");

        return new PresentationRequest.ByReference
        {
            ClientId = options.ClientId,
            Nonce = options.Nonce,
            State = options.State,
            // SPEC: OpenID4VP 1.0 §5 / RFC 9101 — by-reference delivery points the wallet at `request_uri`.
            AuthorizationRequestUri = new Uri(
                $"{_options.AuthorizationEndpoint}?client_id={Uri.EscapeDataString(options.ClientId)}&request_uri={Uri.EscapeDataString(requestUri.ToString())}"),
            SignedRequestObject = requestObject,
            ExpiresAt = expiresAt,
            RequestUri = requestUri,
        };
    }
}
