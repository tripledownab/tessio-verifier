// What belongs in this file: how MdocReaderKey compares the names in a reader's path (by encoding),
// through the public constructor: whether each certificate names the next as its issuer.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class ReaderPathNameTests : IDisposable
{
    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    [Fact]
    public void DoesNotLinkNamesWithADifferentNumberOfParts()
    {
        // One CN whose value reads like the two-part name, written with a fullwidth comma and equals
        // sign: a different name, and different bytes.
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest("CN=Int, O=Org", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var intermediate = intermediateRequest.Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [7]);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=Reader", leafKey, HashAlgorithmName.SHA256).Create(
            new X500DistinguishedName("CN=\"Int\uff0c O\uff1dOrg\""), X509SignatureGenerator.CreateForECDsa(intermediateKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [8]);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(leafKey, [leaf, intermediate]));
        Assert.Contains("not issued by", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("CN=Int, O=Org", "CN=Int")]
    [InlineData("CN=Int, O=Org", "O=Org")]
    [InlineData("O=Int", "CN=Int")]
    public void DoesNotLinkANameThatIsOnlyPartlyTheSame(string issuerSubject, string leafIssuer)
    {
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest(issuerSubject, intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var intermediate = intermediateRequest.Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [9]);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=Reader", leafKey, HashAlgorithmName.SHA256).Create(
            new X500DistinguishedName(leafIssuer), X509SignatureGenerator.CreateForECDsa(intermediateKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [10]);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(leafKey, [leaf, intermediate]));
        Assert.Contains("not issued by", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DoesNotLinkAnIssuerWrittenInAnotherStringType()
    {
        // The intermediate's subject as PrintableString, the leaf's issuer as UTF8String: the same
        // name, but RFC 5280 section 4.1.2.6 (a) has a CA encode it the same way in both places, and
        // names are compared by encoding.
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest(
            new X500DistinguishedName([0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x49, 0x6e, 0x74]),
            intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var intermediate = intermediateRequest.Create(
            _certificates.Root.SubjectName, X509SignatureGenerator.CreateForECDsa(_certificates.RootKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [11]);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=Reader", leafKey, HashAlgorithmName.SHA256).Create(
            new X500DistinguishedName([0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x49, 0x6e, 0x74]),
            X509SignatureGenerator.CreateForECDsa(intermediateKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1), [12]);

        var error = Assert.Throws<ArgumentException>(() => new MdocReaderKey(leafKey, [leaf, intermediate]));
        Assert.Contains("not issued by", error.Message, StringComparison.Ordinal);
    }
}
