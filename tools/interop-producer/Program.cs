// Interop producer: OUR issuer creates an mdoc; the OpenWallet Foundation wallet-framework-dotnet
// (an independent implementation) builds and signs the device authentication over an OpenID4VP 1.0
// Annex B.2.6.1 session transcript. The output is pinned as a Tessio conformance fixture: if our
// verifier accepts it, the deviceAuth layer interoperates across implementations.
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using PeterO.Cbor;
using WalletFramework.Core.Cryptography.Models;
using WalletFramework.MdocLib;
using WalletFramework.MdocLib.Device;
using WalletFramework.MdocLib.Device.Implementations;
using WalletFramework.MdocLib.Security;
using WalletFramework.MdocLib.Security.Abstractions;
using WalletFramework.MdocLib.Security.Cose;
using WalletFramework.MdocLib.Security.Cose.Abstractions;

const string DocTypeValue = "org.iso.18013.5.1.mDL";
const string Ns = "org.iso.18013.5.1";
const string ClientId = "x509_san_dns:interop.tessio.test";
const string Nonce = "interop-nonce-0001";
const string ResponseUri = "https://interop.tessio.test/callback";

// ---- Issue an mdoc (our side: IACA root, DS cert, device key) ----
using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var iacaReq = new CertificateRequest("CN=Tessio Interop IACA", iacaKey, HashAlgorithmName.SHA256);
iacaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
using var iaca = iacaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(15));

using var dsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var dsReq = new CertificateRequest("CN=Tessio Interop DS", dsKey, HashAlgorithmName.SHA256);
using var ds = dsReq.Create(iaca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(14), Guid.NewGuid().ToByteArray());

using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var dp = deviceKey.ExportParameters(false);

CBORObject Tag24(byte[] inner) => CBORObject.FromObjectAndTag(CBORObject.FromObject(inner), 24);

var claims = new (string Name, object Value)[] { ("family_name", "Interop"), ("age_over_18", true) };
var items = new List<CBORObject>();
var digests = CBORObject.NewMap();
for (var i = 0; i < claims.Length; i++)
{
    var item = CBORObject.NewMap()
        .Add("digestID", i)
        .Add("random", RandomNumberGenerator.GetBytes(16))
        .Add("elementIdentifier", claims[i].Name)
        .Add("elementValue", CBORObject.FromObject(claims[i].Value));
    var tagged = Tag24(item.EncodeToBytes());
    items.Add(tagged);
    digests.Add(i, SHA256.HashData(tagged.EncodeToBytes()));
}

string TDate(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
CBORObject TDateCbor(DateTimeOffset t) => CBORObject.FromObjectAndTag(CBORObject.FromObject(TDate(t)), 0);

var mso = CBORObject.NewMap()
    .Add("version", "1.0")
    .Add("digestAlgorithm", "SHA-256")
    .Add("valueDigests", CBORObject.NewMap().Add(Ns, digests))
    .Add("deviceKeyInfo", CBORObject.NewMap().Add("deviceKey", CBORObject.NewMap()
        .Add(1, 2).Add(-1, 1).Add(-2, dp.Q.X!).Add(-3, dp.Q.Y!)))
    .Add("docType", DocTypeValue)
    .Add("validityInfo", CBORObject.NewMap()
        .Add("signed", TDateCbor(DateTimeOffset.UtcNow))
        .Add("validFrom", TDateCbor(DateTimeOffset.UtcNow.AddMinutes(-5)))
        .Add("validUntil", TDateCbor(DateTimeOffset.UtcNow.AddYears(10))));

var chain = CBORObject.NewArray().Add(ds.RawData).Add(iaca.RawData);
var issuerSigner = new System.Security.Cryptography.Cose.CoseSigner(dsKey, HashAlgorithmName.SHA256);
issuerSigner.UnprotectedHeaders.Add(new CoseHeaderLabel(33), CoseHeaderValue.FromEncodedValue(chain.EncodeToBytes()));
var issuerAuth = CoseSign1Message.SignEmbedded(Tag24(mso.EncodeToBytes()).EncodeToBytes(), issuerSigner);

var issuerSigned = CBORObject.NewMap()
    .Add("nameSpaces", CBORObject.NewMap().Add(Ns, CBORObject.NewArray().Add(items[0]).Add(items[1])))
    .Add("issuerAuth", CBORObject.DecodeFromBytes(issuerAuth));

// ---- Hand the issued mdoc to the OTHER implementation ----
var mdocB64 = Base64UrlEncode(CBORObject.NewMap()
    .Add("docType", DocTypeValue)
    .Add("issuerSigned", issuerSigned)
    .EncodeToBytes());

var mdoc = Mdoc.ValidMdoc(mdocB64).Value.Match(
    m => m,
    errs => throw new InvalidOperationException(
        "Their parser rejected our mdoc: " + string.Join("; ", errs.Map(e => e.ToString()))));

var handoverInfo = CBORObject.NewArray().Add(ClientId).Add(Nonce).Add(CBORObject.Null).Add(ResponseUri);
var transcript = new FinalSpecHandover(SHA256.HashData(handoverInfo.EncodeToBytes())).ToSessionTranscript();

var authenticated = await new MdocAuthenticationService(new EcdsaCoseSigner(deviceKey))
    .Authenticate(mdoc, transcript, KeyId.CreateKeyId());

// ---- Assemble the DeviceResponse (ISO 18013-5 §8.3.2.1.2.2) ----
var deviceResponse = CBORObject.NewMap()
    .Add("version", "1.0")
    .Add("documents", CBORObject.NewArray().Add(CBORObject.NewMap()
        .Add("docType", DocTypeValue)
        .Add("issuerSigned", issuerSigned)
        .Add("deviceSigned", DeviceSignedFun.ToCbor(authenticated.DeviceSigned))))
    .Add("status", 0);

var fixture = new
{
    producer = "WalletFramework.MdocLib 2.0.0 (OpenWallet Foundation wallet-framework-dotnet)",
    deviceResponseB64 = Base64UrlEncode(deviceResponse.EncodeToBytes()),
    iacaHex = Convert.ToHexString(iaca.RawData),
    dsSubject = ds.Subject,
    clientId = ClientId,
    nonce = Nonce,
    responseUri = ResponseUri,
    docType = DocTypeValue,
};
File.WriteAllText("fixture.json", JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine("fixture written, deviceResponse bytes: " + deviceResponse.EncodeToBytes().Length);

// ---- Diff: what THEY signed vs what OUR verifier reconstructs ----
var emittedDeviceSigned = DeviceSignedFun.ToCbor(authenticated.DeviceSigned);
var emittedNameSpaces = emittedDeviceSigned["nameSpaces"];
var emittedSig1 = emittedDeviceSigned["deviceAuth"]["deviceSignature"];
var emittedProtected = emittedSig1[0];

var ourAuth = CBORObject.NewArray()
    .Add("DeviceAuthentication")
    .Add(CBORObject.NewArray().Add(CBORObject.Null).Add(CBORObject.Null)
        .Add(CBORObject.NewArray().Add("OpenID4VPHandover").Add(SHA256.HashData(handoverInfo.EncodeToBytes()))))
    .Add(DocTypeValue)
    .Add(emittedNameSpaces);
var ourAuthBytes = CBORObject.FromObjectAndTag(CBORObject.FromObject(ourAuth.EncodeToBytes()), 24).EncodeToBytes();
var ourSigStructure = CBORObject.NewArray()
    .Add("Signature1")
    .Add(emittedProtected)
    .Add(Array.Empty<byte>())
    .Add(CBORObject.FromObject(ourAuthBytes))
    .EncodeToBytes();

Console.WriteLine("theirs: " + Convert.ToHexString(EcdsaCoseSigner.LastSigStructure!));
Console.WriteLine("ours:   " + Convert.ToHexString(ourSigStructure));
Console.WriteLine("emitted nameSpaces: " + Convert.ToHexString(emittedNameSpaces.EncodeToBytes()));
Console.WriteLine("emitted sig1: " + emittedSig1.ToString());

static string Base64UrlEncode(byte[] data) =>
    Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

/// <summary>OpenID4VP 1.0 Annex B.2.6.1 handover, implemented against their IHandover seam.</summary>
sealed record FinalSpecHandover(byte[] HandoverInfoHash) : IHandover
{
    public CBORObject ToCbor() => CBORObject.NewArray().Add("OpenID4VPHandover").Add(HandoverInfoHash);

    public SessionTranscript ToSessionTranscript() => new(default, default, this);
}

/// <summary>ES256 signer over their Sig_structure bytes.</summary>
sealed class EcdsaCoseSigner(ECDsa key) : ICoseSign1Signer
{
    public static byte[]? LastSigStructure;

    public Task<WalletFramework.MdocLib.Security.Cose.CoseSignature> Sign(SigStructure sigStructure, KeyId keyId)
    {
        LastSigStructure = SigStructureFun.ToCbor(sigStructure).EncodeToBytes();
        return Task.FromResult(new WalletFramework.MdocLib.Security.Cose.CoseSignature(
            key.SignData(LastSigStructure, HashAlgorithmName.SHA256)));
    }
}
