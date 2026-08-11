using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.ConformanceHarness;

/// <summary>
/// The key and certificate chain the harness signs request objects with, persisted between runs.
/// </summary>
/// <remarks>
/// A two-certificate chain, not a self-signed leaf: OpenID4VP 1.0 §5.9.3 requires the leaf in
/// <c>x5c</c> to be issued by something, and the suite fails a self-signed one outright. So we mint a
/// throwaway CA and issue the signing certificate from it. The CA is what goes in the plan's
/// <c>client.request_object_trust_anchor_pem</c>; the leaf is what <c>client_id</c> hashes.
/// <para>
/// Persistence matters because that plan field would otherwise go stale on every restart, and the
/// symptom is the suite rejecting the request object with no hint that a restart is the cause.
/// </para>
/// <para>
/// Self-signed at the root is fine here. The suite checks that the leaf chains to the anchor you
/// configured and that <c>client_id</c> matches the leaf, neither of which needs public trust. No real
/// access certificate should go near this tool.
/// </para>
/// </remarks>
internal sealed record HarnessCertificate(
    ECDsa Key,
    X509Certificate2 Leaf,
    X509Certificate2 Authority,
    string LeafPem,
    string AuthorityPem)
{
    /// <summary>
    /// What goes in the JAR <c>x5c</c> header: the leaf alone.
    /// </summary>
    /// <remarks>
    /// Not the CA. The suite rejects a chain containing the configured trust anchor
    /// ("Trust anchor certificate must not be included in x5c chain"), which is reasonable: the anchor
    /// is known out of band, so repeating it in the chain proves nothing and lets a sender appear to
    /// supply its own root.
    /// </remarks>
    public IReadOnlyList<X509Certificate2> Chain => [Leaf];

    public static HarnessCertificate LoadOrCreate(string leafPath, string keyPath, string caPath)
    {
        if (File.Exists(leafPath) && File.Exists(keyPath) && File.Exists(caPath))
        {
            var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(keyPath));
            var leafPem = File.ReadAllText(leafPath);
            var caPem = File.ReadAllText(caPath);
            return new HarnessCertificate(
                key, X509Certificate2.CreateFromPem(leafPem), X509Certificate2.CreateFromPem(caPem), leafPem, caPem);
        }

        // Long lived deliberately: a plan is hours of manual clicking spread over days, and an expiry
        // mid-run looks like a signature failure.
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);

        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(
            "CN=Tessio Conformance Harness CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var ca = caRequest.CreateSelfSigned(notBefore, notAfter);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest(
            "CN=conformance.tessio.local", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("host.docker.internal");
        san.AddDnsName("localhost");
        leafRequest.CertificateExtensions.Add(san.Build());

        using var issued = leafRequest.Create(
            ca, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));

        File.WriteAllText(leafPath, new string(PemEncoding.Write("CERTIFICATE", issued.RawData)));
        File.WriteAllText(caPath, new string(PemEncoding.Write("CERTIFICATE", ca.RawData)));
        File.WriteAllText(keyPath, new string(PemEncoding.Write("PRIVATE KEY", leafKey.ExportPkcs8PrivateKey())));

        return LoadOrCreate(leafPath, keyPath, caPath);
    }

    /// <summary>The TLS certificate for Kestrel, which needs the private key attached.</summary>
    /// <remarks>
    /// The suite installs a trust-all X509TrustManager and a NoopHostnameVerifier, so it accepts this
    /// without the CA being installed anywhere. Reusing the signing leaf keeps the harness to one
    /// identity; it carries host.docker.internal and localhost as SANs for the same reason.
    /// </remarks>
    public X509Certificate2 TlsCertificate() =>
        X509Certificate2.CreateFromPem(LeafPem, ExportKeyPem());

    private string ExportKeyPem() => new(PemEncoding.Write("PRIVATE KEY", Key.ExportPkcs8PrivateKey()));

    public void Dispose()
    {
        Leaf.Dispose();
        Authority.Dispose();
        Key.Dispose();
    }
}
