using System.Security.Cryptography.X509Certificates;
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

    /// <summary>Certificate chain to advertise in the JAR <c>x5c</c> header, leaf certificate first.</summary>
    /// <remarks>
    /// Required in practice for the <c>x509_san_dns</c> client_id scheme: the wallet matches the client_id
    /// against this certificate's SAN and has no other way to obtain it, so a signed request without x5c
    /// is rejected as a malformed JAR before any trust decision is reached.
    /// <para>
    /// Kept separate from <see cref="SigningCredentials"/> rather than read off an
    /// <c>X509SecurityKey</c>, because Microsoft.IdentityModel has no ES256 signature provider for that
    /// key type: an EC certificate can be advertised but not signed with in that form.
    /// </para>
    /// </remarks>
    public IReadOnlyList<X509Certificate2>? SigningCertificateChain { get; set; }

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
