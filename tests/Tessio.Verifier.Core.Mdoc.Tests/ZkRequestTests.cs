// What belongs in this file: asking a wallet for a zero knowledge proof, the zkRequest in a request's
// requestInfo. The external anchor is the age verification technical specification 1.1.0, Annex A, A.11
// request example, which the first test reproduces byte for byte.
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class ZkRequestTests : IDisposable
{
    private const string Origin = "https://verifier.example.com";

    private const string Hash = "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6";

    private static readonly ZkRequest A11 = new(AvZkVectors.RequestedSystemIds);

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    [Fact]
    public void The_specification_example_request_is_built_byte_for_byte()
    {
        var request = Iso18013AnnexC.CreateRequest(AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], A11);

        Assert.Equal(Convert.ToHexString(AvZkVectors.DeviceRequest), Convert.ToHexString(request.DeviceRequest));
    }

    [Fact]
    public void A_required_proof_says_so()
    {
        var request = Iso18013AnnexC.CreateRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], new ZkRequest(AvZkVectors.RequestedSystemIds) { Required = true });

        // zkRequired is the last value in the zkRequest map, so the encodings differ in their final byte only:
        // CBOR true (0xf5) where the example has false (0xf4).
        var example = ZkRequestBytes(AvZkVectors.DeviceRequest);
        var required = ZkRequestBytes(request.DeviceRequest);
        Assert.Equal(0xf4, example[^1]);
        Assert.Equal(Convert.ToHexString(example[..^1]) + "F5", Convert.ToHexString(required));
    }

    [Fact]
    public void A_signed_request_carries_the_zkRequest_beside_the_registration_certificate_inside_the_signed_bytes()
    {
        // The certificate's bytes pass through unchanged, so any CBOR stands in for one: here an empty map.
        byte[] registrationCertificate = [0xa0];
        var request = Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin,
            new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), registrationCertificate, A11);

        var (itemsRequest, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        var requestInfo = DeviceRequestReader.ReadRequestInfo(itemsRequest)!;
        Assert.Equal(["euWrprc", "zkRequest"], requestInfo.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(Convert.ToHexString(ZkRequestBytes(AvZkVectors.DeviceRequest)), Convert.ToHexString(requestInfo["zkRequest"]));

        var readerAuth = CoseMessage.DecodeSign1(encodedReaderAuth!);
        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, Origin);
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        Assert.True(readerAuth.VerifyDetached(leafKey, ReaderAuthentication.BuildBytes(transcript, itemsRequest)));
    }

    [Fact]
    public void A_request_without_one_carries_no_zkRequest()
    {
        var request = Iso18013AnnexC.CreateRequest(AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"]);

        var (itemsRequest, _) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        Assert.Null(DeviceRequestReader.ReadRequestInfo(itemsRequest));
    }

    [Fact]
    public void A_request_for_more_elements_than_any_offered_circuit_proves_is_refused()
    {
        var oneElementCircuitOnly = new ZkRequest([AvZkVectors.RequestedSystemIds[0]]);

        Assert.Throws<ArgumentException>("zkRequest", () => Iso18013AnnexC.CreateRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18", "age_over_21"], oneElementCircuitOnly));
    }

    [Theory]
    [InlineData("longfellow-libzk-v2_6_1_4096_2945_" + Hash)]
    [InlineData("longfellow-libzk-v1_6_1_4096_" + Hash)]
    [InlineData("longfellow-libzk-v1_06_1_4096_2945_" + Hash)]
    [InlineData("longfellow-libzk-v1_+6_1_4096_2945_" + Hash)]
    [InlineData("longfellow-libzk-v1_6_1_4096_2945999999_" + Hash)]
    [InlineData("longfellow-libzk-v1_6_1_4096_2945_137E5A75CE72735A37C8A72DA1A8A0A5DF8D13365C2AE3D2C2BD6A0E7197C7C6")]
    [InlineData("longfellow-libzk-v1_6_1_4096_2945_137e5a75")]
    public void An_identifier_not_in_the_form_the_example_uses_is_refused(string systemId)
    {
        Assert.Throws<ArgumentException>("systemIds", () => new ZkRequest([systemId]));
    }

    [Fact]
    public void An_empty_list_is_refused()
    {
        Assert.Throws<ArgumentException>("systemIds", () => new ZkRequest([]));
    }

    [Fact]
    public void One_circuit_offered_twice_is_refused_even_under_different_parameters()
    {
        Assert.Throws<ArgumentException>("systemIds", () => new ZkRequest(
            ["longfellow-libzk-v1_6_1_4096_2945_" + Hash, "longfellow-libzk-v1_6_2_4096_2945_" + Hash]));
    }

    [Fact]
    public void A_null_list_or_identifier_is_refused()
    {
        Assert.Throws<ArgumentNullException>("systemIds", () => new ZkRequest(null!));
        Assert.Throws<ArgumentNullException>("systemIds", () => new ZkRequest([null!]));
    }

    [Fact]
    public void A_null_zkRequest_is_refused_rather_than_read_as_none()
    {
        Assert.Throws<ArgumentNullException>("zkRequest", () => Iso18013AnnexC.CreateRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], zkRequest: null!));
        Assert.Throws<ArgumentNullException>("zkRequest", () => Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin,
            new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), null, zkRequest: null!));
    }

    /// <summary>The encoded zkRequest value in a single docRequest's requestInfo.</summary>
    private static byte[] ZkRequestBytes(byte[] deviceRequest) =>
        DeviceRequestReader.ReadRequestInfo(DeviceRequestReader.ReadSingleDocRequest(deviceRequest).ItemsRequest)!["zkRequest"];
}
