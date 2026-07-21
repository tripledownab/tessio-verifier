using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust.Tests;

/// <summary>
/// x5c-resolved credentials must anchor on configured certificates. Identifier membership alone is
/// spoofable: anyone can put a trusted issuer's name in a self-signed certificate's SAN.
/// </summary>
public sealed class X5cAnchoringTests : IDisposable
{
    private const string Issuer = "https://issuer.example";

    private readonly ECDsa _legitKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _spoofKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _legitCert;
    private readonly X509Certificate2 _spoofCert;

    public X5cAnchoringTests()
    {
        _legitCert = SelfSigned("CN=Legit Issuer", _legitKey);
        _spoofCert = SelfSigned("CN=Spoofed Issuer", _spoofKey); // same SAN, different key
    }

    private static X509Certificate2 SelfSigned(string subject, ECDsa key, bool isCa = false)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(new Uri(Issuer).Host);
        request.CertificateExtensions.Add(san.Build());
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static ReadOnlyMemory<byte>[] Chain(params X509Certificate2[] certificates) =>
        certificates.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray();

    [Fact]
    public async Task X5c_WithoutAnchors_IsRejected_EvenForListedIssuer()
    {
        var resolver = new StaticTrustListResolver([Issuer]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_legitCert));

        Assert.False(status.Trusted);
        Assert.Contains("trust anchors", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task X5c_PinnedLeaf_IsTrusted()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_legitCert));

        Assert.True(status.Trusted);
    }

    [Fact]
    public async Task X5c_SelfSignedSpoof_WithSameName_IsRejected()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        // The attack from the assessment: a listed issuer identifier presented with a
        // self-signed certificate the attacker controls.
        var status = await resolver.ResolveAsync(Issuer, Chain(_spoofCert));

        Assert.False(status.Trusted);
        Assert.Contains("does not anchor", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task X5c_LeafSignedByCaAnchor_IsTrusted()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = SelfSigned("CN=Test CA", caKey, isCa: true);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=CA-Issued Issuer", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(new Uri(Issuer).Host);
        leafRequest.CertificateExtensions.Add(san.Build());
        using var leaf = leafRequest.Create(
            ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(6),
            Guid.NewGuid().ToByteArray());

        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [ca]);

        Assert.True((await resolver.ResolveAsync(Issuer, Chain(leaf, ca))).Trusted);
        Assert.False((await resolver.ResolveAsync(Issuer, Chain(_spoofCert))).Trusted);
    }

    [Fact]
    public async Task MetadataPath_EmptyX5c_StillTrustsByIdentifier()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        Assert.True((await resolver.ResolveAsync(Issuer, [])).Trusted);
    }

    public void Dispose()
    {
        _legitCert.Dispose();
        _spoofCert.Dispose();
        _legitKey.Dispose();
        _spoofKey.Dispose();
    }
}
