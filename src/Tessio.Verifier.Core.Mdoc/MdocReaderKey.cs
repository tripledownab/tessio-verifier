// What belongs in this file: the reader's signing identity for an mdoc request, and the checks this
// library makes on it before it signs anything.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The key a reader signs an mdoc request's <c>readerAuth</c> with, and the certificate path that
/// names it to the wallet: the reader (access) certificate first, then any intermediates, never the
/// trust anchor. Checked once, here, so a request is never signed by a key its own certificate does
/// not hold, as long as the caller leaves the key as it was.
/// </summary>
/// <remarks>
/// <para>
/// What is checked, in this order: the path is non-empty and holds no null entry, none of its
/// certificates is self-issued, each names the next as its issuer, the reader certificate is not a
/// CA, the key is on a curve with a COSE algorithm, and the reader certificate holds the key's public
/// half. A path that breaks two rules is refused for the first. Names are compared by their encoded
/// bytes, which is stricter than RFC 5280's name matching: a path whose names differ only in case,
/// spacing or string type is refused as unlinked, and a root whose own subject and issuer are encoded
/// differently is not recognised as self-issued. Nothing else is checked here, among others validity
/// periods, revocation, the signatures along the path, key usage and extended key usage, and whether
/// the intermediates are CAs: judging the path is the wallet's, against its own trust list.
/// </para>
/// <para>
/// The caller keeps ownership of the key and the certificates, and must neither dispose them nor
/// import other parameters into the key while this is in use; this disposes neither. The path itself is copied, so adding to the caller's list
/// afterwards cannot slip an unchecked certificate past the checks.
/// </para>
/// </remarks>
// SPEC: ETSI TS 119 472-2 V1.2.1 clause 5.3.2, ISO/IEC 18013-REQ-02: readerAuth "shall be generated
// with the private key whose corresponding public key is enclosed within the RP access certificate";
// REQ-03: x5chain holds "the RP access certificate in its first element, and its certificate path up
// to, but excluding, the trust anchor". OpenID4VC HAIP 1.0 section 5 likewise keeps the trust anchor
// out of a signed request's x5c.
public sealed class MdocReaderKey
{
    // RFC 9053 section 2.1 "defines ECDSA as working only with the curves P-256, P-384, and P-521",
    // and suggests SHA-256 only with P-256, SHA-384 only with P-384 and SHA-512 only with P-521. The
    // pairing picks ES256, ES384 or ES512 from the key alone, so a caller cannot get it wrong. Other
    // curves (brainpool, for one) are refused: ISO/IEC 18013-5 may allow more, but it is not available
    // to this library, and admitting a curve later is an additive change.
    private static readonly Dictionary<string, HashAlgorithmName> HashByCurveOid = new(StringComparer.Ordinal)
    {
        ["1.2.840.10045.3.1.7"] = HashAlgorithmName.SHA256, // P-256, ES256
        ["1.3.132.0.34"] = HashAlgorithmName.SHA384,        // P-384, ES384
        ["1.3.132.0.35"] = HashAlgorithmName.SHA512,        // P-521, ES512
    };

    /// <summary>Checks and holds a reader key and its certificate path.</summary>
    /// <param name="key">The private key of the reader certificate. Must be on P-256, P-384 or P-521.</param>
    /// <param name="certificatePath">
    /// The reader certificate first, then any intermediates up to but excluding the trust anchor.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Any check in the remarks fails, or the key or a certificate in the path cannot be read.
    /// </exception>
    public MdocReaderKey(ECDsa key, IReadOnlyList<X509Certificate2> certificatePath)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(certificatePath);
        var path = certificatePath.ToArray();
        try
        {
            HashAlgorithm = Check(key, path);
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or InvalidOperationException)
        {
            // A disposed or malformed certificate, or a key provider that will not export, surfaces as
            // whatever the platform throws; a caller handles one documented type instead.
            throw new ArgumentException($"The reader key or a certificate in its path cannot be read: {e.Message}", e);
        }

        Key = key;
        CertificatePath = path;
    }

    /// <summary>The checks the remarks list, in that order; returns the hash the key's curve selects.</summary>
    private static HashAlgorithmName Check(ECDsa key, X509Certificate2[] certificatePath)
    {
        ReaderCertificatePath.Check(certificatePath, nameof(certificatePath), "x5chain");

        var (curveOid, keyInfo, leafKeyInfo) = ReadKeys(key, certificatePath[0]);
        if (curveOid is null || !HashByCurveOid.TryGetValue(curveOid, out var hash))
        {
            throw new ArgumentException(
                "The reader key must be on P-256, P-384 or P-521, the curves COSE ES256, ES384 and ES512 are defined over.",
                nameof(key));
        }

        if (leafKeyInfo is null || !leafKeyInfo.AsSpan().SequenceEqual(keyInfo))
        {
            throw new ArgumentException(
                "The first certificate in the path does not hold the public half of the reader key. The wallet checks "
                + "readerAuth against that certificate, so this pair would sign requests no wallet can verify.",
                nameof(certificatePath));
        }

        return hash;
    }

    /// <summary>The reader certificate's private key.</summary>
    internal ECDsa Key { get; }

    /// <summary>The reader certificate first, then intermediates; never the anchor.</summary>
    internal IReadOnlyList<X509Certificate2> CertificatePath { get; }

    /// <summary>The hash the key's curve fixes, which selects ES256, ES384 or ES512.</summary>
    internal HashAlgorithmName HashAlgorithm { get; }

    /// <summary>
    /// The key's curve and public key, and the reader certificate's public key (null when it holds no EC
    /// key).
    /// </summary>
    private static (string? CurveOid, byte[] KeyInfo, byte[]? LeafKeyInfo) ReadKeys(ECDsa key, X509Certificate2 leaf)
    {
        var curveOid = key.ExportParameters(includePrivateParameters: false).Curve.Oid?.Value;
        using var leafKey = leaf.GetECDsaPublicKey();
        return (curveOid, key.ExportSubjectPublicKeyInfo(), leafKey?.ExportSubjectPublicKeyInfo());
    }
}
