using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Configuration for <see cref="SignedPresentationRequestBuilder"/>.</summary>
public sealed class PresentationRequestBuilderOptions
{
    /// <summary>
    /// Key and algorithm used to sign the JAR request object. In production this key belongs to the
    /// verifier's access certificate (WRPAC); any <see cref="SigningCredentials"/> works, including
    /// keys held in Azure Key Vault or an HSM via a custom <see cref="CryptoProviderFactory"/>.
    /// </summary>
    public required SigningCredentials SigningCredentials { get; set; }

    /// <summary>
    /// When set, requests are delivered by reference: the wallet fetches the signed JAR from
    /// <c>{RequestUriBase}/{id}</c> and the hosting layer must serve it there. When null (default),
    /// requests are delivered by value inside the authorization request URI.
    /// </summary>
    public Uri? RequestUriBase { get; set; }

    /// <summary>
    /// Scheme-and-authority part of the wallet-facing authorization request URI.
    /// Defaults to the OpenID4VP universal scheme.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = "openid4vp://authorize";

    /// <summary>Request lifetime applied when the per-request options carry none. Default: 5 minutes.</summary>
    public TimeSpan DefaultRequestLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Time source for iat/exp; system clock when null.</summary>
    public TimeProvider? Clock { get; set; }
}
