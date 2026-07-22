using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The MOCK-mode mdoc wallet: issues real ISO 18013-5 DeviceResponses with an ephemeral IACA root,
/// a Document Signer certificate and a device key, and device-signs the OpenID4VP session
/// transcript, so the full mdoc verification pipeline runs offline.
/// </summary>
internal sealed class MockMdocIssuer : IDisposable
{
    private readonly ECDsa _iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _dsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public MockMdocIssuer()
    {
        var iacaReq = new CertificateRequest("CN=Tessio Mock IACA Root", _iacaKey, HashAlgorithmName.SHA256);
        iacaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        IacaCertificate = iacaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));

        var dsReq = new CertificateRequest("CN=Tessio Mock Document Signer", _dsKey, HashAlgorithmName.SHA256);
        DsCertificate = dsReq.Create(
            IacaCertificate, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
    }

    /// <summary>IACA root, pinned as the dev trust anchor for the mdoc path.</summary>
    public X509Certificate2 IacaCertificate { get; }

    /// <summary>Document Signer certificate; its subject is the issuer identifier on the trust list.</summary>
    public X509Certificate2 DsCertificate { get; }

    /// <summary>
    /// Issues a base64url DeviceResponse for the requested claims, with the device signature bound
    /// to this request's session transcript.
    /// </summary>
    public string IssueDeviceResponse(
        IEnumerable<string> claimNames,
        string docType,
        string mdocNamespace,
        string clientId,
        string nonce,
        byte[]? encryptionKeyThumbprint,
        string responseUri)
    {
        List<byte[]> encodedItems = [];
        List<byte[]> digests = [];
        long digestId = 0;
        foreach (var name in claimNames)
        {
            var item = EncodeIssuerSignedItem(digestId++, name, SampleClaimValues.For(name));
            digests.Add(SHA256.HashData(item));
            encodedItems.Add(item);
        }

        var issuerAuth = SignMso(digests, docType, mdocNamespace);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("version");
        w.WriteTextString("1.0");
        w.WriteTextString("documents");
        w.WriteStartArray(1);
        w.WriteStartMap(3);
        w.WriteTextString("docType");
        w.WriteTextString(docType);
        w.WriteTextString("issuerSigned");
        w.WriteStartMap(2);
        w.WriteTextString("nameSpaces");
        w.WriteStartMap(1);
        w.WriteTextString(mdocNamespace);
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
        WriteDeviceSigned(w, docType, clientId, nonce, encryptionKeyThumbprint, responseUri);
        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteTextString("status");
        w.WriteInt32(0);
        w.WriteEndMap();
        return Base64UrlEncoder.Encode(w.Encode());
    }

    private void WriteDeviceSigned(
        CborWriter w, string docType, string clientId, string nonce, byte[]? encryptionKeyThumbprint, string responseUri)
    {
        var emptyMap = new CborWriter(CborConformanceMode.Lax);
        emptyMap.WriteStartMap(0);
        emptyMap.WriteEndMap();
        var nameSpacesBytes = new CborWriter(CborConformanceMode.Lax);
        nameSpacesBytes.WriteTag((CborTag)24);
        nameSpacesBytes.WriteByteString(emptyMap.Encode());
        var encodedNameSpaces = nameSpacesBytes.Encode();

        var transcript = SessionTranscriptBuilder.Build(clientId, nonce, encryptionKeyThumbprint, responseUri);
        var deviceAuthBytes = SessionTranscriptBuilder.BuildDeviceAuthenticationBytes(transcript, docType, encodedNameSpaces);
        var signature = CoseSign1Message.SignDetached(deviceAuthBytes, new CoseSigner(_deviceKey, HashAlgorithmName.SHA256));

        w.WriteTextString("deviceSigned");
        w.WriteStartMap(2);
        w.WriteTextString("nameSpaces");
        w.WriteEncodedValue(encodedNameSpaces);
        w.WriteTextString("deviceAuth");
        w.WriteStartMap(1);
        w.WriteTextString("deviceSignature");
        w.WriteEncodedValue(signature);
        w.WriteEndMap();
        w.WriteEndMap();
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
            default: w.WriteTextString(value.ToString() ?? string.Empty); break;
        }
    }

    private byte[] SignMso(List<byte[]> digests, string docType, string mdocNamespace)
    {
        var mso = new CborWriter(CborConformanceMode.Lax);
        mso.WriteStartMap(6);
        mso.WriteTextString("version");
        mso.WriteTextString("1.0");
        mso.WriteTextString("digestAlgorithm");
        mso.WriteTextString("SHA-256");
        mso.WriteTextString("valueDigests");
        mso.WriteStartMap(1);
        mso.WriteTextString(mdocNamespace);
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
        mso.WriteTextString(docType);
        mso.WriteTextString("validityInfo");
        mso.WriteStartMap(3);
        mso.WriteTextString("signed");
        WriteTDate(mso, DateTimeOffset.UtcNow);
        mso.WriteTextString("validFrom");
        WriteTDate(mso, DateTimeOffset.UtcNow.AddMinutes(-5));
        mso.WriteTextString("validUntil");
        WriteTDate(mso, DateTimeOffset.UtcNow.AddDays(30));
        mso.WriteEndMap();
        mso.WriteEndMap();

        var payload = new CborWriter(CborConformanceMode.Lax);
        payload.WriteTag((CborTag)24);
        payload.WriteByteString(mso.Encode());

        var chain = new CborWriter(CborConformanceMode.Lax);
        chain.WriteStartArray(2);
        chain.WriteByteString(DsCertificate.RawData);
        chain.WriteByteString(IacaCertificate.RawData);
        chain.WriteEndArray();

        var signer = new CoseSigner(_dsKey, HashAlgorithmName.SHA256);
        signer.UnprotectedHeaders.Add(new CoseHeaderLabel(33), CoseHeaderValue.FromEncodedValue(chain.Encode()));
        return CoseSign1Message.SignEmbedded(payload.Encode(), signer);
    }

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

    public void Dispose()
    {
        IacaCertificate.Dispose();
        DsCertificate.Dispose();
        _iacaKey.Dispose();
        _dsKey.Dispose();
        _deviceKey.Dispose();
    }
}
