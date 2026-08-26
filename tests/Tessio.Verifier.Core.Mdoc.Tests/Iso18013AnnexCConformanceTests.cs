using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// The Annex C encoders against the published example in <see cref="Iso18013AnnexCVectors"/>:
/// externally produced bytes the builders must reproduce exactly, so a shared misreading between
/// our writer and our reader cannot pass. The published response example is NOT here, because its
/// recipient private key was never published and its ciphertext cannot be opened.
/// </summary>
public sealed class Iso18013AnnexCConformanceTests
{
    private const string AvDocType = "eu.europa.ec.av.1";

    [Fact]
    public void DeviceRequestBuilder_ReproducesThePublishedExample()
    {
        // IntentToRetain false: the example's age_over_18 carries false, and it is the retention
        // flag, not a requested value.
        var built = DeviceRequestBuilder.Build(AvDocType, AvDocType, ["age_over_18"], intentToRetain: false);

        Assert.Equal(Iso18013AnnexCVectors.DeviceRequest, built);
    }

    [Fact]
    public void EncryptionInfo_Encode_ReproducesThePublishedExample()
    {
        // Read the example's own nonce and key back out of the published bytes, then re-encode.
        var (nonce, recipientKey) = ReadPublishedEncryptionInfo();

        var built = EncryptionInfo.Encode(nonce, recipientKey);

        Assert.Equal(Iso18013AnnexCVectors.EncryptionInfo, built);
    }

    [Fact]
    public void AnnexCTranscript_ReproducesThePublishedDigest()
    {
        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(
            Iso18013AnnexCVectors.EncryptionInfo, Iso18013AnnexCVectors.Origin, encryptionParameters: null);

        // 83 = array(3), f6 f6 = null null, 82 = array(2), 65 + "dcapi", 5820 = 32-byte bstr,
        // then the digest the specification prints.
        byte[] expected =
            [.. Convert.FromHexString("83f6f6826564636170695820"), .. Iso18013AnnexCVectors.TranscriptDigest];
        Assert.Equal(expected, transcript);
    }

    [Fact]
    public void AnnexCEncryptionTranscript_EmbedsTheSentParameterBytesVerbatim()
    {
        // No published vector exists for this form; the construction comes from the reference
        // implementations, and this pins its shape against drift: the base transcript with the
        // second null replaced by the tag-24-wrapped EncryptionParameters bytes as sent.
        var parameters = EncryptionInfo.ExtractEncryptionParameters(Iso18013AnnexCVectors.EncryptionInfo);

        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(
            Iso18013AnnexCVectors.EncryptionInfo, Iso18013AnnexCVectors.Origin, parameters);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(3);
        w.WriteNull();
        w.WriteTag((CborTag)24);
        w.WriteByteString(parameters);
        w.WriteStartArray(2);
        w.WriteTextString("dcapi");
        w.WriteByteString(Iso18013AnnexCVectors.TranscriptDigest);
        w.WriteEndArray();
        w.WriteEndArray();
        Assert.Equal(w.Encode(), transcript);
    }

    [Fact]
    public void ExtractEncryptionParameters_ReturnsThePublishedMapSlice()
    {
        var parameters = EncryptionInfo.ExtractEncryptionParameters(Iso18013AnnexCVectors.EncryptionInfo);

        // The published parameters map: a2 = map(2), 65 + "nonce". A verbatim slice, so it must
        // start exactly where the map starts inside the published bytes.
        Assert.Equal(0xa2, parameters[0]);
        Assert.Equal("nonce"u8.ToArray(), parameters[2..7]);
        var wrapper = Iso18013AnnexCVectors.EncryptionInfo;
        Assert.Equal(wrapper[^parameters.Length..], parameters);
    }

    private static (byte[] Nonce, ECParameters RecipientKey) ReadPublishedEncryptionInfo()
    {
        var reader = new CborReader(Iso18013AnnexCVectors.EncryptionInfo, CborConformanceMode.Lax);
        reader.ReadStartArray();
        Assert.Equal("dcapi", reader.ReadTextString());
        byte[]? nonce = null;
        ECParameters? key = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "nonce":
                    nonce = reader.ReadByteString();
                    break;
                case "recipientPublicKey":
                    key = CoseKey.ReadEc2PublicKey(reader.ReadEncodedValue().ToArray());
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        Assert.NotNull(nonce);
        Assert.NotNull(key);
        return (nonce, key.Value);
    }
}
