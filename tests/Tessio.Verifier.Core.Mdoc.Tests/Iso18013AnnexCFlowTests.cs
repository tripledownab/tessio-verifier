using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// The Annex C seam end to end: request creation, a wallet-side seal, and opening. Both sides
/// here are this codebase, so these prove wiring and self-consistency; the external anchoring
/// lives in <see cref="Iso18013AnnexCConformanceTests"/> and the RFC 9180 vector tests, and a
/// live wallet arbitrates what no published vector covers.
/// </summary>
public sealed class Iso18013AnnexCFlowTests
{
    private const string AvDocType = "eu.europa.ec.av.1";
    private const string Origin = "https://verifier.example.com";

    private static Iso18013AnnexCRequest Request() =>
        Iso18013AnnexC.CreateRequest(AvDocType, AvDocType, ["age_over_18"]);

    [Fact]
    public void CreateRequest_GeneratesAFreshKeyAndNoncePerRequest()
    {
        var first = Request();
        var second = Request();

        Assert.NotEqual(first.ResponseKeyPkcs8, second.ResponseKeyPkcs8);
        Assert.NotEqual(first.EncryptionInfo, second.EncryptionInfo);
        Assert.Equal(first.DeviceRequest, second.DeviceRequest);
    }

    [Fact]
    public void OpenResponse_ReturnsWhatAWalletSealed_AndTheTranscriptItIsBoundTo()
    {
        var request = Request();
        var plaintext = "stand-in DeviceResponse bytes"u8.ToArray();

        var opened = Iso18013AnnexC.OpenResponse(
            SealLikeAWallet(request.EncryptionInfo, Origin, plaintext),
            request.ResponseKeyPkcs8, request.EncryptionInfo, Origin);

        Assert.Equal(plaintext, opened.DeviceResponse);
        Assert.Equal(
            SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, Origin),
            opened.SessionTranscript);
    }

    [Fact]
    public void OpenResponse_WithADifferentOrigin_FailsDecryptionOutright()
    {
        // The transcript is the HPKE info, so an origin mismatch can never produce wrong bytes:
        // it fails the tag check before anything decodes.
        var request = Request();
        var sealed_ = SealLikeAWallet(request.EncryptionInfo, Origin, [0x01]);

        Assert.Throws<AuthenticationTagMismatchException>(() => Iso18013AnnexC.OpenResponse(
            sealed_, request.ResponseKeyPkcs8, request.EncryptionInfo, "https://other.example.com"));
    }

    [Fact]
    public void Decode_RefusesAWrongLabel()
    {
        var e = Assert.Throws<MdocProcessingException>(() => EncryptedResponse.Decode(
            WrapEncryptedResponse([0x01], [0x02], label: "dcapi2")));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
    }

    [Fact]
    public void Decode_RefusesAMissingCipherText()
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(2);
        w.WriteTextString("dcapi");
        w.WriteStartMap(1);
        w.WriteTextString("enc");
        w.WriteByteString([0x01]);
        w.WriteEndMap();
        w.WriteEndArray();

        var e = Assert.Throws<MdocProcessingException>(() => EncryptedResponse.Decode(w.Encode()));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
    }

    [Fact]
    public void Decode_SkipsUnknownMembers()
    {
        // Newer ISO/IEC 18013-7 editions add members to the response map; enc and cipherText are
        // what decryption needs, so extras must not refuse the response.
        var (enc, cipherText) = EncryptedResponse.Decode(
            WrapEncryptedResponse([0x01], [0x02], extraMember: true));

        Assert.Equal([0x01], enc);
        Assert.Equal([0x02], cipherText);
    }

    // The wallet side of the round trip is the library's own SealResponse, so this suite also
    // covers the public seal-open pair end to end.
    private static byte[] SealLikeAWallet(byte[] encryptionInfo, string origin, byte[] plaintext) =>
        Iso18013AnnexC.SealResponse(plaintext, encryptionInfo, origin);

    private static byte[] WrapEncryptedResponse(
        byte[] enc, byte[] cipherText, string label = "dcapi", bool extraMember = false)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(2);
        w.WriteTextString(label);
        w.WriteStartMap(extraMember ? 3 : 2);
        w.WriteTextString("enc");
        w.WriteByteString(enc);
        w.WriteTextString("cipherText");
        w.WriteByteString(cipherText);
        if (extraMember)
        {
            w.WriteTextString("docRequestID");
            w.WriteTextString("0");
        }

        w.WriteEndMap();
        w.WriteEndArray();
        return w.Encode();
    }
}
