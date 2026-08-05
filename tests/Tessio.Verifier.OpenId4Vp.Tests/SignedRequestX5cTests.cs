using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The JAR x5c header. A wallet using the <c>x509_san_dns</c> client_id scheme has no other way to get
/// the certificate whose SAN it must match, so omitting x5c makes the whole signed path unusable: the
/// EC reference wallet rejects such a request as <c>InvalidJarJwt(cause=Missing x5c)</c> before it ever
/// reaches a trust decision, which is easy to misread as a trust-list problem.
/// </summary>
public sealed class SignedRequestX5cTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _certificate;

    public SignedRequestX5cTests()
    {
        var request = new CertificateRequest("CN=verifier.example", _key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("verifier.example");
        request.CertificateExtensions.Add(san.Build());
        _certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static PresentationRequestOptions Options() => new()
    {
        ClientId = "x509_san_dns:verifier.example",
        Nonce = "nonce-123",
        State = "state-456",
        DcqlQueryJson = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["age_over_18"]}]}]}""",
        ResponseUri = new Uri("https://verifier.example/verify/callback"),
    };

    private static JsonElement Header(string jwt)
    {
        var segment = jwt.Split('.')[0];
        return JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segment)).RootElement.Clone();
    }

    [Fact]
    public async Task Header_carries_the_configured_certificate_chain()
    {
        var builder = new SignedPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_key), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = [_certificate],
        });

        var request = await builder.BuildAsync(Options());
        var header = Header(request.SignedRequestObject);

        Assert.Equal("oauth-authz-req+jwt", header.GetProperty("typ").GetString());

        var x5c = header.GetProperty("x5c");
        Assert.Equal(1, x5c.GetArrayLength());

        // SPEC: RFC 7515 4.1.6 says base64, not base64url, and the leaf certificate comes first.
        var der = Convert.FromBase64String(x5c[0].GetString()!);
        using var presented = X509CertificateLoader.LoadCertificate(der);
        Assert.Equal(_certificate.Thumbprint, presented.Thumbprint);
    }

    [Fact]
    public async Task Header_omits_x5c_when_no_chain_is_configured()
    {
        // No chain configured, so emitting an empty or bogus x5c would be worse than omitting it.
        var builder = new SignedPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_key), SecurityAlgorithms.EcdsaSha256),
        });

        var request = await builder.BuildAsync(Options());

        Assert.False(Header(request.SignedRequestObject).TryGetProperty("x5c", out _));
    }

    public void Dispose()
    {
        _key.Dispose();
        _certificate.Dispose();
    }
}
