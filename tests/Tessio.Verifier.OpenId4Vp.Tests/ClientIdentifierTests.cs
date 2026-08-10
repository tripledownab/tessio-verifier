using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The <c>x509_hash</c> client identifier. HAIP pins the client identifier prefix to this, and the HAIP
/// plan is the only OpenID4VP 1.0 verifier plan in the OpenID Foundation's certification programme, so
/// getting it wrong is the difference between certifiable and not.
/// </summary>
/// <remarks>
/// The failure worth guarding is not the hash arithmetic, it is hashing the wrong certificate: a wallet
/// recomputes the digest over the leaf it received in <c>x5c</c> and rejects the request when it differs.
/// So the first test goes through the real builder and compares against what the wallet would actually see.
/// </remarks>
public sealed class ClientIdentifierTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _certificate;

    public ClientIdentifierTests()
    {
        var request = new CertificateRequest("CN=verifier.example", _key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("verifier.example");
        request.CertificateExtensions.Add(san.Build());
        _certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>Base64url by hand, so the test does not simply mirror the encoder the code under test uses.</summary>
    private static string Base64UrlIndependently(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task X509Hash_matches_the_leaf_certificate_the_wallet_receives_in_x5c()
    {
        var builder = new SignedPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_key), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = [_certificate],
        });

        var request = await builder.BuildAsync(new PresentationRequestOptions
        {
            ClientId = ClientIdentifier.X509Hash(_certificate),
            Nonce = "nonce-123",
            DcqlQueryJson = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["age_over_18"]}]}]}""",
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
        });

        // Do what a wallet does: take the leaf out of x5c and hash the DER it was actually given.
        var header = JsonDocument.Parse(
            Base64UrlEncoder.DecodeBytes(request.SignedRequestObject.Split('.')[0])).RootElement;
        var leafDer = Convert.FromBase64String(header.GetProperty("x5c")[0].GetString()!);
        var expected = $"x509_hash:{Base64UrlIndependently(SHA256.HashData(leafDer))}";

        Assert.Equal(expected, request.ClientId);
    }

    [Fact]
    public void X509Hash_is_base64url_of_a_sha256_digest_without_padding()
    {
        var value = ClientIdentifier.X509Hash(_certificate)["x509_hash:".Length..];

        // 32 bytes base64url encoded is 43 characters once the padding is stripped.
        Assert.Equal(43, value.Length);
        Assert.DoesNotContain('=', value);
        Assert.DoesNotContain('+', value);
        Assert.DoesNotContain('/', value);
    }

    [Fact]
    public void X509Hash_differs_between_certificates()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = new CertificateRequest("CN=other.example", otherKey, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        Assert.NotEqual(ClientIdentifier.X509Hash(_certificate), ClientIdentifier.X509Hash(other));
    }

    [Fact]
    public void X509Hash_rejects_a_missing_certificate() =>
        Assert.Throws<ArgumentNullException>(() => ClientIdentifier.X509Hash(null!));

    public void Dispose()
    {
        _key.Dispose();
        _certificate.Dispose();
    }
}
