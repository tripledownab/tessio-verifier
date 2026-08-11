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
        var payload = RequestObjectClaims.Build(options, iat, exp);

        // SPEC: OpenID4VP 1.0 §5.2 / RFC 9101 — the request object typ MUST be "oauth-authz-req+jwt".
        var headers = new Dictionary<string, object> { ["typ"] = "oauth-authz-req+jwt" };

        // SPEC: RFC 7515 §4.1.6 — x5c is base64 (not base64url) DER, leaf certificate first.
        // Required in practice: a wallet using the x509_san_dns client_id scheme has no other way to
        // obtain the certificate whose SAN it must match, so it rejects a signed request that omits this
        // as a malformed JAR, before any trust decision is reached. Observed with the EC reference wallet
        // as "InvalidJarJwt(cause=Missing x5c)".
        if (_options.SigningCertificateChain is { Count: > 0 } chain)
        {
            headers["x5c"] = chain.Select(c => Convert.ToBase64String(c.RawData)).ToArray();
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload.ToJsonString(RelaxedJson), _options.SigningCredentials, headers);
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
