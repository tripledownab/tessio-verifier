// What belongs in this file: throwaway reader certificates for tests, a root and a reader certificate
// it issued, and the helpers that mint more.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>A test root and a reader certificate it issued, each with its key.</summary>
internal sealed class TestReaderCertificates : IDisposable
{
    public TestReaderCertificates()
    {
        Root = CreateCa("CN=Test Reader Root", RootKey, issuer: null, issuerKey: null);
        Reader = CreateLeaf("CN=Test Reader", ReaderKey, Root, RootKey);
    }

    public ECDsa RootKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public X509Certificate2 Root { get; }

    public ECDsa ReaderKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public X509Certificate2 Reader { get; }

    public void Dispose()
    {
        Reader.Dispose();
        ReaderKey.Dispose();
        Root.Dispose();
        RootKey.Dispose();
    }

    /// <summary>A CA certificate: self-signed when <paramref name="issuer"/> is null, else issued by it.</summary>
    public static X509Certificate2 CreateCa(string subject, ECDsa key, X509Certificate2? issuer, ECDsa? issuerKey)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        if (issuer is null)
        {
            return request.CreateSelfSigned(notBefore, notBefore.AddYears(1));
        }

        using var issued = request.Create(
            issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey!), notBefore, notBefore.AddDays(30), [1]);
        return issued.CopyWithPrivateKey(key);
    }

    /// <summary>An end-entity certificate for <paramref name="key"/>, issued by <paramref name="issuer"/>.</summary>
    public static X509Certificate2 CreateLeaf(string subject, ECDsa key, X509Certificate2 issuer, ECDsa issuerKey)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.Create(
            issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1), [2]);
    }
}
