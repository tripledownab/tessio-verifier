using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.ConformanceHarness;

/// <summary>
/// The key and certificate the harness signs request objects with, persisted between runs.
/// </summary>
/// <remarks>
/// Persistence is the whole point. The HAIP plan has one configuration field,
/// <c>client.request_object_trust_anchor_pem</c>, which is this certificate: the suite uses it to
/// validate the signature on our request object. A certificate regenerated on every start would
/// invalidate that field on every restart, and the symptom is the suite rejecting the request object
/// with no hint that the cause is a restart rather than the code.
/// <para>
/// Self-signed is correct here. The suite checks that the hash in our client_id matches the leaf we
/// send in x5c and that the signature chains to the anchor you pasted, neither of which needs a
/// publicly trusted chain. No real access certificate should go anywhere near this tool.
/// </para>
/// </remarks>
internal sealed record HarnessCertificate(ECDsa Key, X509Certificate2 Certificate, string Pem)
{
    private const string Subject = "CN=conformance.tessio.local";

    public static HarnessCertificate LoadOrCreate(string certPath, string keyPath)
    {
        if (File.Exists(certPath) && File.Exists(keyPath))
        {
            var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(keyPath));
            var certPem = File.ReadAllText(certPath);
            return new HarnessCertificate(key, X509Certificate2.CreateFromPem(certPem), certPem);
        }

        // Deliberately long lived: a plan takes hours of manual clicking spread over days, and an
        // expiry mid-run looks like a signature failure.
        using var fresh = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Subject, fresh, HashAlgorithmName.SHA256);
        using var created = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var pem = new string(PemEncoding.Write("CERTIFICATE", created.RawData));
        File.WriteAllText(certPath, pem);
        File.WriteAllText(keyPath, new string(PemEncoding.Write("PRIVATE KEY", fresh.ExportPkcs8PrivateKey())));

        var loadedKey = ECDsa.Create();
        loadedKey.ImportFromPem(File.ReadAllText(keyPath));
        return new HarnessCertificate(loadedKey, X509Certificate2.CreateFromPem(pem), pem);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        Key.Dispose();
    }
}
