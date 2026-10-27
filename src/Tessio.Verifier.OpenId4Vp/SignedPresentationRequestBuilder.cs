using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds JAR-signed OpenID4VP 1.0 presentation requests (RFC 9101), delivered by value or by
/// reference per <see cref="PresentationRequestBuilderOptions.RequestUriBase"/>.
/// </summary>
public sealed class SignedPresentationRequestBuilder : IPresentationRequestBuilder
{
    private readonly PresentationRequestBuilderOptions _options;
    private readonly TimeProvider _clock;

    // Taken from the options once, in the constructor, so the credentials and chain that were checked are
    // the ones every request uses, whatever is assigned to the options afterwards.
    private readonly RequestObjectSigner _signer;

    /// <summary>Creates the builder, checking the signing certificate chain when one is configured.</summary>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="options"/> or its <see cref="PresentationRequestBuilderOptions.SigningCredentials"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <see cref="PresentationRequestBuilderOptions.SigningCertificateChain"/> breaks a rule its remarks
    /// list, or a certificate in it, or the signing key, cannot be read.
    /// </exception>
    public SignedPresentationRequestBuilder(PresentationRequestBuilderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.SigningCredentials);
        _options = options;
        _clock = options.Clock ?? TimeProvider.System;
        _signer = new RequestObjectSigner(
            options.SigningCredentials,
            options.SigningCertificateChain,
            $"{nameof(options)}.{nameof(options.SigningCertificateChain)}",
            options.AllowSelfSignedSigningCertificate);
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

    private string SignRequestObject(PresentationRequestOptions options, DateTimeOffset iat, DateTimeOffset exp) =>
        // SPEC: OpenID4VP 1.0 §5.2 — authorization request parameters for the vp_token flow.
        _signer.Sign(RequestObjectClaims.Build(options, iat, exp), iat);

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
