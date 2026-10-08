using System.Formats.Cbor;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: how a DeviceResponse carrying zero-knowledge presentations (<c>zkDocuments</c>) is
/// reported. This library does not verify them; the point is that such a response gets its own code
/// rather than passing for a malformed one.
/// </summary>
/// <remarks>
/// The response shape follows the age verification profile's example of a zero-knowledge response
/// (AV technical specification 1.1.0, Annex A, A.11): <c>version</c>, a <c>zkDocuments</c> array whose
/// entries hold a <c>proof</c> and a tag-24 <c>documentData</c>, and <c>status</c>, with no
/// <c>documents</c> member. The proof bytes here are placeholders, because nothing reads them.
/// </remarks>
public sealed class ZkPresentationTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    private MdocVerifier Verifier() => new(
        new StaticTrustListResolver(
            [_builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]));

    private MdocVerificationContext Context() => new()
    {
        ExpectedDocType = MdocTestBuilder.DefaultDocType,
        ClientId = _builder.ClientId,
        Nonce = _builder.Nonce,
        EncryptionKeyThumbprint = _builder.EncryptionKeyThumbprint,
        ResponseUri = _builder.ResponseUri,
    };

    private static PresentedCredential Mdoc(byte[] deviceResponse) =>
        new() { Format = MdocVerifier.Format, RawValue = Base64UrlEncoder.Encode(deviceResponse) };

    [Fact]
    public async Task A_response_of_only_zero_knowledge_presentations_gets_its_own_code()
    {
        var result = await Verifier().VerifyAsync(Mdoc(ZkOnlyResponse()), Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal(MdocErrorCodes.ZkPresentationUnsupported, error.Code);
    }

    [Fact]
    public async Task A_response_with_no_documents_and_no_zero_knowledge_presentation_stays_a_structure_error()
    {
        // The control: the new code must name zero-knowledge presentations only, not every empty response.
        var result = await Verifier().VerifyAsync(Mdoc(Response(includeZk: false)), Context());

        Assert.False(result.IsValid);
        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_plain_document_beside_a_zero_knowledge_presentation_is_still_verified()
    {
        // A wallet that sends both answers what we can verify; the zero-knowledge part is ignored.
        var result = await Verifier().VerifyAsync(Mdoc(WithZkDocuments(_builder.Build())), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public void The_parser_records_zero_knowledge_presentations()
    {
        Assert.True(DeviceResponseParser.Parse(Base64UrlEncoder.Encode(ZkOnlyResponse())).HasZkDocuments);
        Assert.False(DeviceResponseParser.Parse(_builder.BuildBase64Url()).HasZkDocuments);
    }

    [Fact]
    public async Task An_empty_zkDocuments_array_is_not_a_zero_knowledge_presentation()
    {
        // The new code names a response that holds a proof. An empty array holds none, so it stays the
        // structure error it was before the code existed.
        var result = await Verifier().VerifyAsync(Mdoc(Response(includeZk: true, zkItems: 0)), Context());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_failed_status_is_reported_before_a_zero_knowledge_presentation()
    {
        // A wallet that reports an error status has not answered, whatever else it sent.
        var result = await Verifier().VerifyAsync(Mdoc(Response(includeZk: true, status: 10)), Context());

        var error = Assert.Single(result.Errors);
        Assert.Equal(MdocErrorCodes.StructureInvalid, error.Code);
        Assert.Contains("status is 10", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_member_is_not_taken_for_zero_knowledge_presentations()
    {
        var response = Response(includeZk: false, extraKey: "futureMember");

        Assert.False(DeviceResponseParser.Parse(Base64UrlEncoder.Encode(response)).HasZkDocuments);
    }

    private static byte[] ZkOnlyResponse() => Response(includeZk: true);

    private static byte[] Response(bool includeZk, int zkItems = 1, long status = 0, string? extraKey = null)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2 + (includeZk ? 1 : 0) + (extraKey is null ? 0 : 1));
        writer.WriteTextString("version");
        writer.WriteTextString("1.0");
        if (includeZk)
        {
            writer.WriteTextString("zkDocuments");
            WriteZkDocuments(writer, zkItems);
        }

        if (extraKey is not null)
        {
            writer.WriteTextString(extraKey);
            writer.WriteStartArray(1);
            writer.WriteInt32(1);
            writer.WriteEndArray();
        }

        writer.WriteTextString("status");
        writer.WriteInt64(status);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>Copies a DeviceResponse map and adds a <c>zkDocuments</c> member to it.</summary>
    private static byte[] WithZkDocuments(byte[] deviceResponse)
    {
        var reader = new CborReader(deviceResponse, CborConformanceMode.Lax);
        var count = reader.ReadStartMap() ?? throw new InvalidOperationException("Expected a definite-length map.");

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(count + 1);
        for (var i = 0; i < count; i++)
        {
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        }

        writer.WriteTextString("zkDocuments");
        WriteZkDocuments(writer);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static void WriteZkDocuments(CborWriter writer, int items = 1)
    {
        if (items == 0)
        {
            writer.WriteStartArray(0);
            writer.WriteEndArray();
            return;
        }

        var data = new CborWriter(CborConformanceMode.Lax);
        data.WriteStartMap(4);
        data.WriteTextString("zkSystemId");
        data.WriteTextString("longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6");
        data.WriteTextString("docType");
        data.WriteTextString(MdocTestBuilder.DefaultDocType);
        data.WriteTextString("timestamp");
        data.WriteTag(CborTag.DateTimeString);
        data.WriteTextString("2026-02-05T08:44:59Z");
        data.WriteTextString("issuerSigned");
        data.WriteStartMap(0);
        data.WriteEndMap();
        data.WriteEndMap();

        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteTextString("proof");
        writer.WriteByteString(new byte[] { 0xb3, 0x03, 0x08, 0xf8 });
        writer.WriteTextString("documentData");
        writer.WriteTag((CborTag)24);
        writer.WriteByteString(data.Encode());
        writer.WriteEndMap();
        writer.WriteEndArray();
    }

    public void Dispose() => _builder.Dispose();
}
