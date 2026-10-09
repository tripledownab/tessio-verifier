using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Lists built to slip past the trust rules through the platform rather than through the rules: chains the
/// platform builds differently from the ones provided, constraints that apply only to a full path, encodings
/// other than DER, keys on unnamed curves. Also the algorithm and header cases the rest of the suite does not reach.
/// </summary>
public sealed partial class MsoRevocationTests
{
    [Fact]
    public void APathTheBuildExtendsBeyondItsTop_StillHolds()
    {
        // The platform also searches the account's own certificate stores and may carry a chain past the last
        // certificate a list provides. Simulated here with the extra store rather than by writing to a real one:
        // the signer alone is expected, and the build reaches the IACA above it.
        var clock = TimeProvider.System;
        using var build = MsoRevocationTrust.BuildWithNothingTrusted(_list.SignerCertificate, [_builder.IacaCertificate], clock);

        Assert.Equal(2, build.ChainElements.Count);
        Assert.True(MsoRevocationTrust.PathHolds(build, [_list.SignerCertificate]));
    }

    [Fact]
    public void APathThroughAnotherCertificateThanTheOneExpected_DoesNotHold()
    {
        // The IACA re-issued under the same name and key: the signer verifies under either copy, so only the
        // bytes tell which one the build went through.
        var reissueRequest = new CertificateRequest(_builder.IacaCertificate.SubjectName, _builder.IacaKey, HashAlgorithmName.SHA256);
        reissueRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        reissueRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(reissueRequest.PublicKey, false));
        using var reissued = reissueRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        using var build = MsoRevocationTrust.BuildWithNothingTrusted(_list.SignerCertificate, [reissued], TimeProvider.System);

        Assert.False(MsoRevocationTrust.PathHolds(build, [_list.SignerCertificate, _builder.IacaCertificate]));
        Assert.True(MsoRevocationTrust.PathHolds(build, [_list.SignerCertificate, reissued]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TheAnchorsPathLengthBindsTheWholePath(bool namedByTheReference)
    {
        // An IACA that allows no CA below it, and a list signed under a sub-CA it issued anyway.
        using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Path Length IACA", iacaKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var iaca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        using var subKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var sub = CertificateAuthority("CN=Test Sub CA", subKey, iaca, iacaKey, withKeyId: true);
        using var builder = new MdocTestBuilder(iaca, iacaKey)
        {
            MsoStatus = namedByTheReference
                ? RevocationListBuilder.StatusListReference(0, ListUri, certificate: iaca.RawData)
                : RevocationListBuilder.StatusListReference(0, ListUri),
        };
        using var list = new RevocationListBuilder(sub, subKey) { IncludeIssuerInChain = true };
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [iaca]), clock: null, httpClient: new HttpClient(_http));

        AssertRefused(await verifier.VerifyAsync(Credential(builder), Context(builder)), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ACertificateWithTheIacasKeyButNotTheIacasLimits_IsNotTheIaca(bool inTheListsChain)
    {
        // The IACA allows no CA below it. A certificate of the attacker's own making wraps the IACA's PUBLIC key,
        // with its name and no such limit, and is put where the IACA would be: at the top of the list's chain, or
        // in the MSO's unprotected x5chain. It holds the key that signed the Document Signer, so only asking the
        // seam about that very certificate tells it from the real one.
        using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Path Length IACA", iacaKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var iaca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrapper = new CertificateRequest(iaca.SubjectName, iaca.PublicKey, HashAlgorithmName.SHA256);
        wrapper.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        wrapper.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(iaca.PublicKey, false));
        using var forged = wrapper.Create(
            new X500DistinguishedName("CN=Test Attacker"), X509SignatureGenerator.CreateForECDsa(attackerKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5), Guid.NewGuid().ToByteArray());
        using var subKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var sub = CertificateAuthority("CN=Test Sub CA", subKey, iaca, iacaKey, withKeyId: true);
        using var builder = new MdocTestBuilder(iaca, iacaKey)
        {
            MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri),
            X5ChainWithoutIssuer = true,
            ExtraX5ChainCertificate = inTheListsChain ? null : forged,
        };
        using var list = new RevocationListBuilder(sub, subKey)
        {
            IncludeIssuerInChain = true,
            ExtraChainCertificate = inTheListsChain ? forged.RawData : null,
        };
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [iaca]), clock: null, httpClient: new HttpClient(_http));

        AssertRefused(await verifier.VerifyAsync(Credential(builder), Context(builder)), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AnEmptyCertificate_IsRefusedNotThrown()
    {
        _list.ExtraChainCertificate = [];
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ACertificateNotInDer_IsRefused(bool inTheListsChain)
    {
        var pem = System.Text.Encoding.ASCII.GetBytes(_builder.IacaCertificate.ExportCertificatePem());
        if (inTheListsChain)
        {
            _list.ExtraChainCertificate = pem;
            _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        }
        else
        {
            _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: pem);
        }

        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task ASigningKeyOnAnUnnamedCurve_IsRefusedNotThrown()
    {
        // P-256's parameters with a different generator: a valid curve with no name, so no OID to compare.
        var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var explicitCurve = p256.ExportExplicitParameters(false).Curve;
        using (var other = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            explicitCurve.G = other.ExportParameters(false).Q;
        }

        p256.Dispose();
        using var key = ECDsa.Create(explicitCurve);
        // From the exported public key: handed the key itself, the request refuses an unnamed curve.
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=Test Unnamed Curve Signer"),
            PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _), HashAlgorithmName.SHA256);
        using var signer = request.Create(
            _builder.IacaCertificate.SubjectName, X509SignatureGenerator.CreateForECDsa(_builder.IacaKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());
        using var list = new RevocationListBuilder(_builder.IacaCertificate, _builder.IacaKey);
        list.UseSigner(signer, key, _builder.IacaCertificate);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData("nistP384")]
    [InlineData("nistP521")]
    public async Task TheLargerCurves_VerifyUnderTheirOwnAlgorithms(string curve)
    {
        // SPEC: EAA-6.2.10.1-08, ES384 on P-384 and ES512 on P-521.
        var (namedCurve, hash) = curve == "nistP384"
            ? (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384)
            : (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
        using var list = new RevocationListBuilder(_builder.IacaCertificate, _builder.IacaKey, curve: namedCurve) { Hash = hash };
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task ACriticalTextLabel_IsRefused()
    {
        _list.CriticalTextLabel = "x";
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheReferencedCertificate_MayEndTheListsOwnChain()
    {
        _list.IncludeIssuerInChain = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: _builder.IacaCertificate.RawData);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task ASeamThatCannotAnswer_LeavesTheListUnresolvable()
    {
        _builder.X5ChainWithoutIssuer = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(Verifier(trust: new FailsForAllButTheDocumentSigner(_builder.DsCertificate))), ErrorCodes.StatusUnresolvable);
    }

    /// <summary>Anchors the Document Signer and fails, as a seam doing I/O can, for every other chain.</summary>
    private sealed class FailsForAllButTheDocumentSigner(X509Certificate2 documentSigner) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            x5c[0].Span.SequenceEqual(documentSigner.RawData)
                ? Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "test", TrustAnchorThumbprint = "AA" })
                : throw new HttpRequestException("trust list unreachable");
    }
}
