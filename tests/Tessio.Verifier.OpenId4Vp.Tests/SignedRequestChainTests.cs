// What belongs in this file: what SignedPresentationRequestBuilder refuses, accepts and keeps when it is
// given a signing certificate chain.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc.Tests;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The chain a signed request carries in <c>x5c</c>: the access certificate first, then intermediates,
/// never the trust anchor, and never a self-signed signer (ETSI TS 119 472-2 OIDFVP-HAIP-REDIRECTS_RO-02,
/// HAIP 1.0 section 5). Each refusal names the option, so a misconfigured deployment fails at start-up
/// rather than at the first wallet.
/// </summary>
public sealed class SignedRequestChainTests : IDisposable
{
    private const string ParameterName = "options.SigningCertificateChain";

    private readonly TestReaderCertificates _certificates = new();

    private SignedPresentationRequestBuilder Builder(IReadOnlyList<X509Certificate2>? chain, ECDsa? key = null) => new(
        new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(key ?? _certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = chain,
        });

    private static PresentationRequestOptions Options() => new()
    {
        ClientId = "x509_san_dns:verifier.example",
        Nonce = "nonce-123",
        DcqlQueryJson = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["age_over_18"]}]}]}""",
        ResponseUri = new Uri("https://verifier.example/verify/callback"),
    };

    private static string[] X5c(string jwt) =>
        JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[0])).RootElement
            .GetProperty("x5c").EnumerateArray().Select(e => e.GetString()!).ToArray();

    private void Refused(IReadOnlyList<X509Certificate2> chain, string because, ECDsa? key = null)
    {
        var ex = Assert.Throws<ArgumentException>(() => Builder(chain, key));
        Assert.Equal(ParameterName, ex.ParamName);
        Assert.Contains(because, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_an_empty_chain() => Refused([], "at least the reader certificate");

    [Fact]
    public void Refuses_a_null_entry() => Refused([_certificates.Reader, null!], "null entry");

    [Fact]
    public void Refuses_the_trust_anchor_in_the_chain() =>
        Refused([_certificates.Reader, _certificates.Root], "self-issued certificate (CN=Test Reader Root)");

    [Fact]
    public void Refuses_a_self_signed_signer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var selfSigned = new CertificateRequest("CN=verifier.example", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        Refused([selfSigned], "self-issued certificate (CN=verifier.example)", key);
    }

    [Fact]
    public void Refuses_a_chain_whose_next_certificate_is_not_the_issuer()
    {
        using var otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherRoot = TestReaderCertificates.CreateCa("CN=Other Root", otherRootKey, issuer: null, issuerKey: null);
        using var unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var unrelated = TestReaderCertificates.CreateCa("CN=Unrelated CA", unrelatedKey, otherRoot, otherRootKey);

        Refused([_certificates.Reader, unrelated], "is not issued by the one after it");
    }

    [Fact]
    public void Refuses_a_ca_as_the_signing_certificate()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var intermediate = TestReaderCertificates.CreateCa("CN=Test Intermediate", caKey, _certificates.Root, _certificates.RootKey);

        Refused([intermediate], "is a CA certificate", caKey);
    }

    [Fact]
    public void Refuses_a_signing_certificate_that_does_not_hold_the_signing_key()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Refused([_certificates.Reader], "does not hold the public half of the signing key", otherKey);
    }

    [Fact]
    public void Refuses_a_certificate_it_cannot_read_as_an_argument_error()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var disposed = TestReaderCertificates.CreateLeaf("CN=Disposed", key, _certificates.Root, _certificates.RootKey);
        disposed.Dispose();

        var ex = Assert.Throws<ArgumentException>(() => Builder([disposed], key));
        Assert.Equal(ParameterName, ex.ParamName);
    }

    [Fact]
    public async Task Sends_a_leaf_and_its_intermediate_in_order()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var intermediate = TestReaderCertificates.CreateCa("CN=Test Intermediate", caKey, _certificates.Root, _certificates.RootKey);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = TestReaderCertificates.CreateLeaf("CN=Test Leaf", leafKey, intermediate, caKey);

        var request = await Builder([leaf, intermediate], leafKey).BuildAsync(Options());

        Assert.Equal(
            [Convert.ToBase64String(leaf.RawData), Convert.ToBase64String(intermediate.RawData)],
            X5c(request.SignedRequestObject));
    }

    [Fact]
    public async Task Keeps_the_chain_it_checked_when_the_options_change_afterwards()
    {
        var chain = new List<X509Certificate2> { _certificates.Reader };
        var options = new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = chain,
        };
        var builder = new SignedPresentationRequestBuilder(options);

        // Both ways a caller could slip an unchecked certificate in after the check.
        chain.Add(_certificates.Root);
        options.SigningCertificateChain = [_certificates.Root];

        var request = await builder.BuildAsync(Options());

        Assert.Equal([Convert.ToBase64String(_certificates.Reader.RawData)], X5c(request.SignedRequestObject));
    }

    [Fact]
    public void Does_not_compare_a_signing_key_that_is_not_an_ecdsa_key()
    {
        // The documented limit: only an ECDsaSecurityKey is compared with the leaf. A key held elsewhere
        // reaches the builder as some other SecurityKey and is the caller's to pair correctly.
        using var rsa = RSA.Create(2048);
        var builder = new SignedPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
            SigningCertificateChain = [_certificates.Reader],
        });

        Assert.NotNull(builder);
    }

    [Fact]
    public void Refuses_options_without_signing_credentials() =>
        Assert.Throws<ArgumentNullException>(() => new SignedPresentationRequestBuilder(
            new PresentationRequestBuilderOptions { SigningCredentials = null!, SigningCertificateChain = [_certificates.Reader] }));

    [Fact]
    public async Task Accepts_a_signing_certificate_without_basic_constraints()
    {
        // RFC 5280 section 4.2.1.9: basic constraints "MAY appear ... in end entity certificates", and
        // real access certificates often leave it out. Only an extension saying CA counts against it.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=No Basic Constraints", key, HashAlgorithmName.SHA256).Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [3]);

        var request = await Builder([leaf], key).BuildAsync(Options());

        Assert.Equal([Convert.ToBase64String(leaf.RawData)], X5c(request.SignedRequestObject));
    }

    [Fact]
    public void Refuses_an_rsa_signing_certificate_for_an_ec_key()
    {
        using var rsa = RSA.Create(2048);
        using var rsaLeaf = new CertificateRequest("CN=RSA Leaf", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [4]);

        Refused([rsaLeaf], "does not hold the public half of the signing key");
    }

    [Fact]
    public void Refuses_a_disposed_signing_key_as_an_argument_error()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256);
        key.Dispose();

        var ex = Assert.Throws<ArgumentException>(() => new SignedPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = credentials,
            SigningCertificateChain = [_certificates.Reader],
        }));
        Assert.Equal(ParameterName, ex.ParamName);
    }

    [Fact]
    public void Refuses_a_signing_key_that_will_not_export_as_an_argument_error()
    {
        using var key = new NonExportingECDsa();

        var ex = Assert.Throws<ArgumentException>(() => Builder([_certificates.Reader], key));
        Assert.Equal(ParameterName, ex.ParamName);
    }

    [Fact]
    public async Task Keeps_the_credentials_it_checked_when_new_ones_are_assigned()
    {
        var options = new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = [_certificates.Reader],
        };
        var builder = new SignedPresentationRequestBuilder(options);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        options.SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(otherKey), SecurityAlgorithms.EcdsaSha256);

        var request = await builder.BuildAsync(Options());

        // Signed with the key the leaf holds, not the one assigned afterwards.
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(
            request.SignedRequestObject,
            new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = new ECDsaSecurityKey(leafKey),
            });
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task Signs_after_the_caller_disposes_the_certificates()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leaf = TestReaderCertificates.CreateLeaf("CN=Disposed Later", key, _certificates.Root, _certificates.RootKey);
        var der = leaf.RawData;
        var builder = Builder([leaf], key);
        leaf.Dispose();

        var request = await builder.BuildAsync(Options());

        Assert.Equal([Convert.ToBase64String(der)], X5c(request.SignedRequestObject));
    }

    public void Dispose() => _certificates.Dispose();

    /// <summary>An ECDsa whose provider will not export its public key, as some remote providers do.</summary>
    private sealed class NonExportingECDsa : ECDsa
    {
        public override byte[] SignHash(byte[] hash) => throw new NotSupportedException();

        public override bool VerifyHash(byte[] hash, byte[] signature) => throw new NotSupportedException();

        public override ECParameters ExportParameters(bool includePrivateParameters) =>
            throw new NotSupportedException("This provider does not export keys.");
    }
}
