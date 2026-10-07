// What belongs in this file: the checks MdocReaderKey makes on a reader key and its certificate path
// before anything is signed with them.
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class MdocReaderKeyTests : IDisposable
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    [Fact]
    public void RefusesAnEmptyPath()
    {
        Assert.Throws<ArgumentException>(() => new MdocReaderKey(_certificates.ReaderKey, []));
    }

    [Fact]
    public void RefusesANullEntry()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader, null!]));
        Assert.Contains("null entry", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesTheTrustAnchorInThePath()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader, _certificates.Root]));
        Assert.Contains("self-issued", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesASelfSignedReaderCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var selfSigned = new CertificateRequest("CN=Self-Signed Reader", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(key, [selfSigned]));
        Assert.Contains("self-issued", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesAPathBrokenBeyondTheFirstLink()
    {
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var intermediate = TestReaderCertificates.CreateCa(
            "CN=Test Reader Intermediate", intermediateKey, _certificates.Root, _certificates.RootKey);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = TestReaderCertificates.CreateLeaf("CN=Test Reader Two Down", leafKey, intermediate, intermediateKey);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherRoot = TestReaderCertificates.CreateCa("CN=Unrelated Root", otherKey, issuer: null, issuerKey: null);
        using var unrelated = TestReaderCertificates.CreateCa("CN=Unrelated Intermediate", otherKey, otherRoot, otherKey);

        _ = new MdocReaderKey(leafKey, [leaf, intermediate]);
        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(leafKey, [leaf, intermediate, unrelated]));
        Assert.Contains("Certificate 1", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TurnsADisposedCertificateIntoArgumentException()
    {
#if NET9_0_OR_GREATER
        var reader = X509CertificateLoader.LoadCertificate(_certificates.Reader.RawData);
#else
        var reader = new X509Certificate2(_certificates.Reader.RawData);
#endif
        reader.Dispose();

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(_certificates.ReaderKey, [reader]));
        Assert.IsAssignableFrom<CryptographicException>(error.InnerException);
    }

    [Fact]
    public void TurnsAMalformedReaderCertificateIntoArgumentException()
    {
        // basicConstraints holding a BOOLEAN with no value byte: the certificate loads, the extension
        // does not decode.
        var request = new CertificateRequest("CN=Malformed Reader", _certificates.ReaderKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.19", [0x30, 0x03, 0x01, 0x01], critical: true));
        using var malformed = request.Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [5]);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(_certificates.ReaderKey, [malformed]));
        Assert.IsAssignableFrom<CryptographicException>(error.InnerException);
    }

    [Fact]
    public void RefusesAPathWhoseNextCertificateIsNotTheIssuer()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherRoot = TestReaderCertificates.CreateCa("CN=Unrelated Root", otherKey, issuer: null, issuerKey: null);
        using var unrelated = TestReaderCertificates.CreateCa("CN=Unrelated Intermediate", otherKey, otherRoot, otherKey);

        Assert.Contains("not issued by", Assert.Throws<ArgumentException>(
            () => new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader, unrelated])).Message, StringComparison.Ordinal);
        Assert.Contains("not issued by", Assert.Throws<ArgumentException>(
            () => new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader, _certificates.Reader])).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesACaCertificateAsTheReaderCertificate()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = TestReaderCertificates.CreateCa(
            "CN=Test Reader Intermediate", caKey, _certificates.Root, _certificates.RootKey);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(caKey, [ca]));
        Assert.Contains("CA certificate", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesAPathThatDoesNotStartWithTheKeysCertificate()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(otherKey, [_certificates.Reader]));
        Assert.Contains("public half", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesACurveCoseHasNoAlgorithmFor()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        using var leaf = TestReaderCertificates.CreateLeaf(
            "CN=Test Reader Brainpool", key, _certificates.Root, _certificates.RootKey);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(key, [leaf]));
        Assert.Contains("P-256, P-384 or P-521", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(typeof(NotSupportedException))]
    [InlineData(typeof(InvalidOperationException))]
    [InlineData(typeof(CryptographicException))]
    public void TurnsAnUnreadableKeyIntoArgumentException(Type thrown)
    {
        using var key = new UnreadableKey((Exception)Activator.CreateInstance(thrown, "This key does not export.")!);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(key, [_certificates.Reader]));
        Assert.IsType(thrown, error.InnerException);
    }

    [Fact]
    public void IgnoresWhatTheCallerAddsToTheirListLater()
    {
        List<X509Certificate2> path = [_certificates.Reader];
        var reader = new MdocReaderKey(_certificates.ReaderKey, path);
        path.Add(_certificates.Root);

        var deviceRequest = DeviceRequestBuilder.BuildSigned(
            PidDocType, PidDocType, ["family_name"], intentToRetain: false, [0xf6], reader, registrationCertificate: null);

        var (_, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(deviceRequest);
        Assert.Equal(
            _certificates.Reader.RawData,
            DeviceRequestReader.ReadX5Chain(CoseMessage.DecodeSign1(encodedReaderAuth!)).ReadByteString());
    }

    /// <summary>A key provider that will not export, as some hardware-backed ones behave.</summary>
    private sealed class UnreadableKey(Exception onExport) : ECDsa
    {
        public override byte[] SignHash(byte[] hash) => throw new NotSupportedException();

        public override bool VerifyHash(byte[] hash, byte[] signature) => throw new NotSupportedException();

        public override ECParameters ExportParameters(bool includePrivateParameters) => throw onExport;
    }
}
