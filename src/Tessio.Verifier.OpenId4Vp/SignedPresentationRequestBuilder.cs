using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
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

    // Taken from the options once, here, so the credentials and chain that were checked are the ones
    // every request uses, whatever is assigned to the options afterwards. The chain is kept as its
    // encoded x5c values, so a certificate the caller disposes later cannot break signing.
    private readonly SigningCredentials _signingCredentials;
    private readonly string[]? _x5c;

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
        _signingCredentials = options.SigningCredentials;
        _x5c = options.SigningCertificateChain is { } chain
            ? CheckChain(chain, options.SigningCredentials.Key, $"{nameof(options)}.{nameof(options.SigningCertificateChain)}")
            : null;
    }

    /// <summary>The path rules, then that the leaf holds the signing key; returns the x5c values to send.</summary>
    // SPEC: RFC 7515 §4.1.6 — x5c is base64 (not base64url) DER, leaf certificate first.
    private static string[] CheckChain(IReadOnlyList<X509Certificate2> chain, SecurityKey key, string parameterName)
    {
        var path = chain.ToArray();
        try
        {
            ReaderCertificatePath.Check(path, parameterName, "x5c");

            // Only an ECDsaSecurityKey's public half can be read here. With the remote-signing pattern of
            // going-live.md that is the public half the caller declared, not the key that actually signs;
            // any other SecurityKey type is not compared at all. The options' remarks say both.
            if (key is ECDsaSecurityKey { ECDsa: { } ecdsa })
            {
                using var leafKey = path[0].GetECDsaPublicKey();
                if (leafKey is null
                    || !leafKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(ecdsa.ExportSubjectPublicKeyInfo()))
                {
                    throw new ArgumentException(
                        "The first certificate in SigningCertificateChain does not hold the public half of the signing "
                        + "key. The wallet verifies the request object against that certificate, so this pair would "
                        + "sign requests no wallet can verify.",
                        parameterName);
                }
            }
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or InvalidOperationException)
        {
            // A disposed or malformed certificate, or a key provider that will not export, surfaces as
            // whatever the platform throws; a caller handles one documented type instead.
            throw new ArgumentException(
                $"The signing key or a certificate in SigningCertificateChain cannot be read: {e.Message}", parameterName, e);
        }

        return path.Select(c => Convert.ToBase64String(c.RawData)).ToArray();
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

        // SPEC: ETSI TS 119 472-2 V1.3.1 §6.4.2 OIDFVP-HAIP-REDIRECTS_RO-03 — "The JWS Protected Header of
        // the JWS signature on the RO shall incorporate the iat header parameter." Same instant as the
        // payload's iat, so the two cannot disagree.
        headers["iat"] = iat.ToUnixTimeSeconds();

        // Required in practice: a wallet using the x509_san_dns client_id scheme has no other way to
        // obtain the certificate whose SAN it must match, so it rejects a signed request that omits this
        // as a malformed JAR, before any trust decision is reached. Observed with the EC reference wallet
        // as "InvalidJarJwt(cause=Missing x5c)". The chain was checked and encoded when the builder was
        // created.
        if (_x5c is { } x5c)
        {
            headers["x5c"] = x5c;
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload.ToJsonString(JsonDefaults.Relaxed), _signingCredentials, headers);
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
