
namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>DeviceResponse and MSO parsing plus the digest checks (ISO 18013-5 §9.1.2.4, §9.3.1).</summary>
public sealed class DeviceResponseParserTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    [Fact]
    public void Parse_RoundTrips_DocumentAndClaims()
    {
        var response = DeviceResponseParser.Parse(_builder.BuildBase64Url());

        Assert.Equal("1.0", response.Version);
        Assert.Equal(0, response.Status);
        var document = Assert.Single(response.Documents);
        Assert.Equal(MdocTestBuilder.DefaultDocType, document.DocType);

        var items = document.NameSpaces[MdocTestBuilder.DefaultNamespace];
        Assert.Equal(2, items.Count);
        Assert.Equal("Mobius", items.Single(i => i.ElementIdentifier == "family_name").ElementValue);
        Assert.Equal(true, items.Single(i => i.ElementIdentifier == "age_over_18").ElementValue);
    }

    [Fact]
    public void ParseMso_ReadsAlgorithmDigestsAndValidity()
    {
        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];

        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        Assert.Equal("SHA-256", mso.DigestAlgorithm);
        Assert.Equal(MdocTestBuilder.DefaultDocType, mso.DocType);
        Assert.Equal(2, mso.ValueDigests[MdocTestBuilder.DefaultNamespace].Count);
        Assert.True(mso.ValidFrom < DateTimeOffset.UtcNow);
        Assert.True(mso.ValidUntil > DateTimeOffset.UtcNow);
        Assert.NotEmpty(mso.DeviceKeyEncoded);
    }

    [Fact]
    public void Digests_Match_ForUntamperedItems()
    {
        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        Assert.Empty(DigestVerifier.Verify(document, mso));
    }

    [Fact]
    public void TamperedItemValue_FailsTheDigestCheck()
    {
        // Re-encode the family_name item with a different value after the MSO digests are fixed.
        _builder.TamperItem = (encoded, name) =>
            name == "family_name" ? Retag(encoded, "Mallory") : encoded;

        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        var errors = DigestVerifier.Verify(document, mso);
        var error = Assert.Single(errors);
        Assert.Equal(MdocErrorCodes.DigestMismatch, error.Code);
        Assert.Contains("family_name", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ItemWithUnknownDigestId_IsRejected()
    {
        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        // A document claiming an item the MSO never digested.
        var forged = document with
        {
            NameSpaces = new Dictionary<string, IReadOnlyList<ParsedIssuerSignedItem>>(StringComparer.Ordinal)
            {
                [MdocTestBuilder.DefaultNamespace] =
                [
                    .. document.NameSpaces[MdocTestBuilder.DefaultNamespace],
                    document.NameSpaces[MdocTestBuilder.DefaultNamespace][0] with { DigestId = 99 },
                ],
            },
        };

        var errors = DigestVerifier.Verify(forged, mso);
        Assert.Contains(errors, e => e.Code == MdocErrorCodes.DigestMismatch && e.Message.Contains("digestID 99", StringComparison.Ordinal));
    }

    [Fact]
    public void MsoDocTypeMismatch_IsRejected()
    {
        _builder.MsoDocType = "org.example.other";

        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        var error = Assert.Single(DigestVerifier.Verify(document, mso));
        Assert.Equal(MdocErrorCodes.MsoInvalid, error.Code);
    }

    [Fact]
    public void UnsupportedDigestAlgorithm_IsRejected()
    {
        _builder.DigestAlgorithm = "MD5";

        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        var error = Assert.Single(DigestVerifier.Verify(document, mso));
        Assert.Equal(MdocErrorCodes.MsoInvalid, error.Code);
        Assert.Contains("MD5", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Sha384DigestAlgorithm_IsSupported()
    {
        _builder.DigestAlgorithm = "SHA-384";

        var document = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0];
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        Assert.Empty(DigestVerifier.Verify(document, mso));
    }

    [Fact]
    public void MalformedBase64_ThrowsStructureInvalid()
    {
        var ex = Assert.Throws<MdocProcessingException>(() => DeviceResponseParser.Parse("!!not-base64url!!"));
        Assert.Equal(MdocErrorCodes.StructureInvalid, ex.Code);
    }

    [Fact]
    public void MalformedCbor_ThrowsStructureInvalid()
    {
        var ex = Assert.Throws<MdocProcessingException>(
            () => DeviceResponseParser.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode([0xFF, 0x00, 0x01])));
        Assert.Equal(MdocErrorCodes.StructureInvalid, ex.Code);
    }

    [Fact]
    public void GarbageIssuerAuth_ThrowsMsoInvalid()
    {
        var ex = Assert.Throws<MdocProcessingException>(() => DeviceResponseParser.ParseMso([0x01, 0x02, 0x03]));
        Assert.Equal(MdocErrorCodes.MsoInvalid, ex.Code);
    }

    public void Dispose() => _builder.Dispose();

    /// <summary>Re-encodes a captured IssuerSignedItemBytes with a replaced string elementValue.</summary>
    private static byte[] Retag(byte[] encoded, string newValue)
    {
        var outerReader = new System.Formats.Cbor.CborReader(encoded, System.Formats.Cbor.CborConformanceMode.Lax);
        outerReader.ReadTag();
        var innerReader = new System.Formats.Cbor.CborReader(outerReader.ReadByteString(), System.Formats.Cbor.CborConformanceMode.Lax);

        var inner = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        innerReader.ReadStartMap();
        inner.WriteStartMap(4);
        while (innerReader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            var key = innerReader.ReadTextString();
            inner.WriteTextString(key);
            if (key == "elementValue")
            {
                innerReader.SkipValue();
                inner.WriteTextString(newValue);
            }
            else
            {
                inner.WriteEncodedValue(innerReader.ReadEncodedValue().Span);
            }
        }

        inner.WriteEndMap();

        var outer = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        outer.WriteTag((System.Formats.Cbor.CborTag)24);
        outer.WriteByteString(inner.Encode());
        return outer.Encode();
    }
}
