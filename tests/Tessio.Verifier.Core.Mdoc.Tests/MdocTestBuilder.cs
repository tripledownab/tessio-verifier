using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Builds real mdoc DeviceResponses for tests: a Document Signer certificate chained to an IACA-like
/// root, IssuerSignedItems with random salts, an MSO with computed digests signed as COSE_Sign1
/// (x5chain header) and a device key. Follows the TestCredentialBuilder pattern from Core.Tests.
/// </summary>
internal sealed class MdocTestBuilder : IDisposable
{
    public const string DefaultDocType = "org.iso.18013.5.1.mDL";
    public const string DefaultNamespace = "org.iso.18013.5.1";

    private readonly ECDsa _iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _dsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public MdocTestBuilder()
    {
        var iacaReq = new CertificateRequest("CN=Test IACA Root", _iacaKey, HashAlgorithmName.SHA256);
        iacaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        IacaCertificate = iacaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));

        var dsReq = new CertificateRequest("CN=Test Document Signer", _dsKey, HashAlgorithmName.SHA256);
        DsCertificate = dsReq.Create(
            IacaCertificate, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
    }

    public X509Certificate2 IacaCertificate { get; }

    public X509Certificate2 DsCertificate { get; }

    public ECDsa DeviceKey => _deviceKey;

    public string DocType { get; set; } = DefaultDocType;

    /// <summary>docType written into the MSO; defaults to <see cref="DocType"/>.</summary>
    public string? MsoDocType { get; set; }

    public string DigestAlgorithm { get; set; } = "SHA-256";

    public DateTimeOffset ValidFrom { get; set; } = DateTimeOffset.UtcNow.AddMinutes(-10);

    public DateTimeOffset ValidUntil { get; set; } = DateTimeOffset.UtcNow.AddDays(30);

    /// <summary>Claims to issue, in insertion order; digestIDs are assigned sequentially.</summary>
    public Dictionary<string, object?> Claims { get; } = new(StringComparer.Ordinal)
    {
        ["family_name"] = "Mobius",
        ["age_over_18"] = true,
    };

    /// <summary>Mutates one encoded item after digest computation, to model tampering.</summary>
    public Func<byte[], string, byte[]>? TamperItem { get; set; }

    /// <summary>Signs the MSO with this key instead of the DS certificate's key (signature mismatch).</summary>
    public ECDsa? SignerKeyOverride { get; set; }

    /// <summary>Builds a DeviceResponse and returns it base64url-encoded (the vp_token form).</summary>
    public string BuildBase64Url() => Base64UrlEncoder.Encode(Build());

    /// <summary>Builds the raw CBOR DeviceResponse.</summary>
    public byte[] Build()
    {
        List<byte[]> encodedItems = [];
        List<byte[]> digests = [];
        long digestId = 0;
        foreach (var (name, value) in Claims)
        {
            var item = EncodeIssuerSignedItem(digestId++, name, value);
            digests.Add(Hash(item));
            encodedItems.Add(TamperItem is null ? item : TamperItem(item, name));
        }

        var issuerAuth = SignMso(digests);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("version");
        w.WriteTextString("1.0");
        w.WriteTextString("documents");
        w.WriteStartArray(1);
        w.WriteStartMap(2);
        w.WriteTextString("docType");
        w.WriteTextString(DocType);
        w.WriteTextString("issuerSigned");
        w.WriteStartMap(2);
        w.WriteTextString("nameSpaces");
        w.WriteStartMap(1);
        w.WriteTextString(DefaultNamespace);
        w.WriteStartArray(encodedItems.Count);
        foreach (var item in encodedItems)
        {
            w.WriteEncodedValue(item);
        }

        w.WriteEndArray();
        w.WriteEndMap();
        w.WriteTextString("issuerAuth");
        w.WriteEncodedValue(issuerAuth);
        w.WriteEndMap();
        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteTextString("status");
        w.WriteInt32(0);
        w.WriteEndMap();
        return w.Encode();
    }

    private static byte[] EncodeIssuerSignedItem(long digestId, string name, object? value)
    {
        var inner = new CborWriter(CborConformanceMode.Lax);
        inner.WriteStartMap(4);
        inner.WriteTextString("digestID");
        inner.WriteInt64(digestId);
        inner.WriteTextString("random");
        inner.WriteByteString(RandomNumberGenerator.GetBytes(16));
        inner.WriteTextString("elementIdentifier");
        inner.WriteTextString(name);
        inner.WriteTextString("elementValue");
        WriteValue(inner, value);
        inner.WriteEndMap();

        // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
        var outer = new CborWriter(CborConformanceMode.Lax);
        outer.WriteTag((CborTag)24);
        outer.WriteByteString(inner.Encode());
        return outer.Encode();
    }

    private static void WriteValue(CborWriter w, object? value)
    {
        switch (value)
        {
            case null: w.WriteNull(); break;
            case string s: w.WriteTextString(s); break;
            case bool b: w.WriteBoolean(b); break;
            case int i: w.WriteInt64(i); break;
            case long l: w.WriteInt64(l); break;
            case byte[] bytes: w.WriteByteString(bytes); break;
            default: throw new NotSupportedException($"Unsupported test claim type {value.GetType()}.");
        }
    }

    private byte[] SignMso(List<byte[]> digests)
    {
        var mso = new CborWriter(CborConformanceMode.Lax);
        mso.WriteStartMap(6);
        mso.WriteTextString("version");
        mso.WriteTextString("1.0");
        mso.WriteTextString("digestAlgorithm");
        mso.WriteTextString(DigestAlgorithm);
        mso.WriteTextString("valueDigests");
        mso.WriteStartMap(1);
        mso.WriteTextString(DefaultNamespace);
        mso.WriteStartMap(digests.Count);
        for (var i = 0; i < digests.Count; i++)
        {
            mso.WriteInt32(i);
            mso.WriteByteString(digests[i]);
        }

        mso.WriteEndMap();
        mso.WriteEndMap();
        mso.WriteTextString("deviceKeyInfo");
        mso.WriteStartMap(1);
        mso.WriteTextString("deviceKey");
        WriteCoseKey(mso, _deviceKey);
        mso.WriteEndMap();
        mso.WriteTextString("docType");
        mso.WriteTextString(MsoDocType ?? DocType);
        mso.WriteTextString("validityInfo");
        mso.WriteStartMap(3);
        mso.WriteTextString("signed");
        WriteTDate(mso, DateTimeOffset.UtcNow);
        mso.WriteTextString("validFrom");
        WriteTDate(mso, ValidFrom);
        mso.WriteTextString("validUntil");
        WriteTDate(mso, ValidUntil);
        mso.WriteEndMap();
        mso.WriteEndMap();

        // MobileSecurityObjectBytes = #6.24(bstr .cbor MSO), signed as the COSE_Sign1 payload.
        var payload = new CborWriter(CborConformanceMode.Lax);
        payload.WriteTag((CborTag)24);
        payload.WriteByteString(mso.Encode());

        var signer = new CoseSigner(SignerKeyOverride ?? _dsKey, HashAlgorithmName.SHA256);
        // SPEC: RFC 9360 — x5chain at header label 33; DS certificate first, then the chain.
        signer.UnprotectedHeaders.Add(new CoseHeaderLabel(33), CoseHeaderValue.FromEncodedValue(EncodeChain()));
        return CoseSign1Message.SignEmbedded(payload.Encode(), signer);
    }

    private byte[] EncodeChain()
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(2);
        w.WriteByteString(DsCertificate.RawData);
        w.WriteByteString(IacaCertificate.RawData);
        w.WriteEndArray();
        return w.Encode();
    }

    // SPEC: RFC 9053 — COSE_Key for EC2/P-256: {1:2, -1:1, -2:x, -3:y}.
    private static void WriteCoseKey(CborWriter w, ECDsa key)
    {
        var p = key.ExportParameters(false);
        w.WriteStartMap(4);
        w.WriteInt32(1);
        w.WriteInt32(2);
        w.WriteInt32(-1);
        w.WriteInt32(1);
        w.WriteInt32(-2);
        w.WriteByteString(p.Q.X!);
        w.WriteInt32(-3);
        w.WriteByteString(p.Q.Y!);
        w.WriteEndMap();
    }

    private static void WriteTDate(CborWriter w, DateTimeOffset value)
    {
        w.WriteTag((CborTag)0);
        w.WriteTextString(value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
    }

    private byte[] Hash(byte[] data) => DigestAlgorithm switch
    {
        "SHA-384" => SHA384.HashData(data),
        "SHA-512" => SHA512.HashData(data),
        _ => SHA256.HashData(data),
    };

    public void Dispose()
    {
        IacaCertificate.Dispose();
        DsCertificate.Dispose();
        _iacaKey.Dispose();
        _dsKey.Dispose();
        _deviceKey.Dispose();
    }
}
