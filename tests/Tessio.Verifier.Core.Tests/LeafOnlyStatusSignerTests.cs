using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// A Token Status List signer may send its own certificate alone (HAIP 1.0 Final section 6.1). It is
/// accepted when the deployment has configured the certificate that issued it, and nothing is fetched to
/// find that certificate.
/// </summary>
/// <remarks>
/// What belongs here: status signers whose x5c stops below the anchor. The signer's certificate names
/// where its issuer's certificate is published, and the intermediate is served there through the
/// injected client, so verifier code that fetched it would show in the handler's log. The platform's own
/// certificate downloads bypass that client, and <c>ChainBuildingTests</c> is what pins them off.
/// </remarks>
public sealed class LeafOnlyStatusSignerTests : IDisposable
{
    private const string StatusUri = "https://issuer.example/statuslists/1";
    private const string IntermediateUrl = "http://pki.example/intermediate.cer";

    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _intermediate;
    private readonly X509Certificate2 _signer;

    public LeafOnlyStatusSignerTests()
    {
        var rootRequest = new CertificateRequest("CN=Status Root", _rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        _root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var intermediateRequest = new CertificateRequest("CN=Status Intermediate", _intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        _intermediate = intermediateRequest.Create(
            _root, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(6), Guid.NewGuid().ToByteArray());

        var signerRequest = new CertificateRequest("CN=Status Signer", _leafKey, HashAlgorithmName.SHA256);
        signerRequest.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(ocspUris: null, caIssuersUris: [IntermediateUrl]));
        using var intermediateWithKey = _intermediate.CopyWithPrivateKey(_intermediateKey);
        using var signerPublic = signerRequest.Create(
            intermediateWithKey, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(3), Guid.NewGuid().ToByteArray());
        _signer = signerPublic.CopyWithPrivateKey(_leafKey);
    }

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    /// <summary>A credential trusted by identifier, whose status list is signed by the leaf-only signer.</summary>
    private async Task<(VerificationResult Result, FakeHttpHandler Http)> VerifyWithAnchors(params X509Certificate2[] anchors)
    {
        using var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: _signer))
            .MapBytes(IntermediateUrl, _intermediate.RawData);
        var verifier = new SdJwtVcVerifier(
            new StaticTrustListResolver([TestCredentialBuilder.DefaultIssuer], "test", anchors), options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());
        return (result, http);
    }

    [Fact]
    public async Task ALeafOnlyStatusSigner_IsAccepted_WhenItsIntermediateIsConfigured()
    {
        var (result, http) = await VerifyWithAnchors(_root, _intermediate);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.DoesNotContain(IntermediateUrl, http.Requested);
    }

    /// <summary>
    /// The control: with only the root configured the same signer is refused, the intermediate is still
    /// not fetched, and the reason says where the presented chain stops.
    /// </summary>
    [Fact]
    public async Task ALeafOnlyStatusSigner_IsRefused_WithoutItsIntermediate_AndNothingIsFetched()
    {
        var (result, http) = await VerifyWithAnchors(_root);

        var error = Assert.Single(result.Errors, e => e.Code == "status_invalid");
        Assert.Contains(
            "carries no certificate above 'CN=Status Signer', whose issuer is 'CN=Status Intermediate'",
            error.Message,
            StringComparison.Ordinal);
        Assert.DoesNotContain(IntermediateUrl, http.Requested);
    }

    public void Dispose()
    {
        _signer.Dispose();
        _intermediate.Dispose();
        _root.Dispose();
        _rootKey.Dispose();
        _intermediateKey.Dispose();
        _leafKey.Dispose();
    }
}
