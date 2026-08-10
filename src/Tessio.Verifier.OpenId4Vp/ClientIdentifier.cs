using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds OpenID4VP <c>client_id</c> values that carry a Client Identifier Prefix.
/// </summary>
/// <remarks>
/// Additive: <see cref="PresentationRequestOptions.ClientId"/> stays a caller-supplied string, so this
/// is a convenience for producing a correct value rather than a change to the frozen contract.
/// </remarks>
public static class ClientIdentifier
{
    /// <summary>
    /// Builds an <c>x509_hash</c> client identifier from the leaf certificate the request is signed with.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate, which must be first in the <c>x5c</c> chain.</param>
    /// <returns>A client_id of the form <c>x509_hash:&lt;base64url SHA-256 of the DER certificate&gt;</c>.</returns>
    // SPEC: OpenID4VP 1.0, x509_hash Client Identifier Prefix. The identifier is the base64url-encoded
    // SHA-256 hash of the DER-encoded leaf certificate, for example
    // x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk
    //
    // Why this exists: HAIP pins the client identifier prefix to x509_hash, and the HAIP plan is the only
    // OpenID4VP 1.0 verifier plan in the OpenID Foundation's certification programme (the others are
    // published as alpha). x509_san_dns alone cannot be certified.
    //
    // The caller must still sign the request object with the private key matching this certificate and
    // emit the chain in the x5c header, which SignedPresentationRequestBuilder already does from
    // PresentationRequestBuilderOptions.SigningCertificateChain. The wallet recomputes this hash over the
    // leaf it received in x5c and rejects the request if it differs, so the certificate used here and the
    // first entry of that chain have to be the same certificate.
    public static string X509Hash(X509Certificate2 leafCertificate)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);

        var digest = SHA256.HashData(leafCertificate.RawData);
        return $"x509_hash:{Base64UrlEncoder.Encode(digest)}";
    }
}
