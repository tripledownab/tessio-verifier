// What belongs in this file: the signed mdoc request, its readerAuth and requestInfo. The reader key's
// checks are in MdocReaderKeyTests and ReaderPathNameTests, the origin rules in SignedRequestOriginTests.
// The external anchor for what readerAuth covers is the Annex D test in Iso18013AnnexDConformanceTests;
// these prove the wiring around it.
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class SignedDeviceRequestTests : IDisposable
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string Origin = "https://verifier.example.com";

    // COSE algorithm identifiers, RFC 9053 section 2.1.
    private const int Es256 = -7;
    private const int Es384 = -35;
    private const int Es512 = -36;

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private Iso18013AnnexCRequest SignedRequest(byte[]? registrationCertificate = null) =>
        Iso18013AnnexC.CreateSignedRequest(
            PidDocType, PidDocType, ["family_name"], Origin, new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), registrationCertificate);

    [Fact]
    public void CreateSignedRequest_SignsOverTheAnnexCTranscript_WithTheReaderCertificate()
    {
        var request = SignedRequest();

        var (itemsRequest, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        Assert.NotNull(encodedReaderAuth);
        var readerAuth = CoseMessage.DecodeSign1(encodedReaderAuth);

        // The bare four-element array (0x84), as in the Annex D example: no COSE_Sign1 tag 18.
        Assert.Equal(0x84, encodedReaderAuth[0]);
        Assert.Equal(Es256, readerAuth.ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32());
        Assert.Null(readerAuth.Content);
        Assert.Equal(_certificates.Reader.RawData, DeviceRequestReader.ReadX5Chain(readerAuth).ReadByteString());

        // Signing changes nothing about what is asked: same items, IntentToRetain false.
        Assert.Equal(DeviceRequestReader.ReadSingleDocRequest(UnsignedDeviceRequest()).ItemsRequest, itemsRequest);

        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, Origin);
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        Assert.True(readerAuth.VerifyDetached(leafKey, ReaderAuthentication.BuildBytes(transcript, itemsRequest)));
    }

    [Fact]
    public void CreateSignedRequest_DoesNotVerifyFromAnotherOrigin()
    {
        var request = SignedRequest();
        var (itemsRequest, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        var readerAuth = CoseMessage.DecodeSign1(encodedReaderAuth!);

        var elsewhere = SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, "https://other.example.com");
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        Assert.False(readerAuth.VerifyDetached(leafKey, ReaderAuthentication.BuildBytes(elsewhere, itemsRequest)));
    }

    [Fact]
    public void CreateSignedRequest_CarriesTheRegistrationCertificateUnderEuWrprc()
    {
        // A stand-in shaped like a CWT (tag 18 over a four-element array), the form CIR (EU)
        // 2026/1731 asks for; the library passes whatever bytes it is given through unchanged.
        byte[] registrationCertificate = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];

        var request = SignedRequest(registrationCertificate);

        var (itemsRequest, _) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        var requestInfo = DeviceRequestReader.ReadRequestInfo(itemsRequest);
        Assert.NotNull(requestInfo);
        var only = Assert.Single(requestInfo);
        Assert.Equal("euWrprc", only.Key);
        Assert.Equal(registrationCertificate, new CborReader(only.Value).ReadByteString());

        // Inside the signed bytes: readerAuth verifies over the itemsRequest that carries it.
        var (_, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, Origin);
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        Assert.True(CoseMessage.DecodeSign1(encodedReaderAuth!)
            .VerifyDetached(leafKey, ReaderAuthentication.BuildBytes(transcript, itemsRequest)));
    }

    [Fact]
    public void CreateSignedRequest_WithoutARegistrationCertificate_WritesNoRequestInfo()
    {
        var (itemsRequest, _) = DeviceRequestReader.ReadSingleDocRequest(SignedRequest().DeviceRequest);

        Assert.Null(DeviceRequestReader.ReadRequestInfo(itemsRequest));
    }

    [Fact]
    public void CreateSignedRequest_RefusesAnEmptyRegistrationCertificate()
    {
        Assert.Throws<ArgumentException>(() => SignedRequest(registrationCertificate: []));
    }

    [Fact]
    public void CreateRequest_StaysUnsigned()
    {
        var request = Iso18013AnnexC.CreateRequest(PidDocType, PidDocType, ["family_name"]);

        // The builder's unsigned output is pinned to a published example elsewhere; IntentToRetain
        // false is this seam's own promise.
        Assert.Equal(UnsignedDeviceRequest(), request.DeviceRequest);
        Assert.Null(DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest).ReaderAuth);
    }

    [Fact]
    public void BuildSigned_WithAnIntermediate_SendsAnArray_ReaderCertificateFirst()
    {
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var intermediate = TestReaderCertificates.CreateCa("CN=Test Reader Intermediate", intermediateKey, _certificates.Root, _certificates.RootKey);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = TestReaderCertificates.CreateLeaf("CN=Test Reader Behind An Intermediate", leafKey, intermediate, intermediateKey);

        var deviceRequest = DeviceRequestBuilder.BuildSigned(
            PidDocType, PidDocType, ["family_name"], intentToRetain: false, [0xf6],
            new MdocReaderKey(leafKey, [leaf, intermediate]), registrationCertificate: null);

        var (_, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(deviceRequest);
        var x5chain = DeviceRequestReader.ReadX5Chain(CoseMessage.DecodeSign1(encodedReaderAuth!));
        Assert.Equal(2, x5chain.ReadStartArray());
        Assert.Equal(leaf.RawData, x5chain.ReadByteString());
        Assert.Equal(intermediate.RawData, x5chain.ReadByteString());
        x5chain.ReadEndArray();
    }

    [Fact]
    public void BuildSigned_WithAP384Key_SignsES384()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var leaf = TestReaderCertificates.CreateLeaf("CN=Test Reader P-384", key, _certificates.Root, _certificates.RootKey);

        var deviceRequest = DeviceRequestBuilder.BuildSigned(
            PidDocType, PidDocType, ["family_name"], intentToRetain: false, [0xf6],
            new MdocReaderKey(key, [leaf]), registrationCertificate: null);

        var (_, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(deviceRequest);
        Assert.Equal(Es384, CoseMessage.DecodeSign1(encodedReaderAuth!).ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32());
    }

    [Fact]
    public void BuildSigned_WithAP521Key_SignsES512()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        using var leaf = TestReaderCertificates.CreateLeaf("CN=Test Reader P-521", key, _certificates.Root, _certificates.RootKey);

        var deviceRequest = DeviceRequestBuilder.BuildSigned(
            PidDocType, PidDocType, ["family_name"], intentToRetain: false, [0xf6],
            new MdocReaderKey(key, [leaf]), registrationCertificate: null);

        var (_, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(deviceRequest);
        Assert.Equal(Es512, CoseMessage.DecodeSign1(encodedReaderAuth!).ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32());
    }

    [Fact]
    public void BuildSigned_RefusesANullTranscript()
    {
        Assert.Throws<ArgumentNullException>(() => DeviceRequestBuilder.BuildSigned(
            PidDocType, PidDocType, ["family_name"], intentToRetain: false, null!,
            new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), registrationCertificate: null));
    }

    private static byte[] UnsignedDeviceRequest() =>
        DeviceRequestBuilder.Build(PidDocType, PidDocType, ["family_name"], intentToRetain: false);
}
