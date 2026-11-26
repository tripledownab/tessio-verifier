using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: element values as the result reports them. A value the result's shape cannot carry is
/// refused, not reported as an approximation of what the issuer signed.
/// </summary>
public sealed class ClaimValueTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    public void Dispose() => _builder.Dispose();

    private object? ParsedValue(string hex)
    {
        _builder.Claims["value"] = (Action<CborWriter>)(w => w.WriteEncodedValue(Convert.FromHexString(hex)));
        var items = DeviceResponseParser.Parse(_builder.BuildBase64Url()).Documents[0].NameSpaces[MdocTestBuilder.DefaultNamespace];
        return items.Single(i => i.ElementIdentifier == "value").ElementValue;
    }

    private string Refusal(string hex)
    {
        _builder.Claims["value"] = (Action<CborWriter>)(w => w.WriteEncodedValue(Convert.FromHexString(hex)));
        var e = Assert.Throws<MdocProcessingException>(() => DeviceResponseParser.Parse(_builder.BuildBase64Url()));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
        return e.Message;
    }

    [Theory]
    [InlineData("7F6161FF", "a")]           // (_ "a")
    [InlineData("7F61616162FF", "ab")]      // (_ "a", "b")
    [InlineData("7FFF", "")]                // (_ ): no chunks
    [InlineData("7F62C3A9FF", "é")]         // (_ "é"): a code point of two bytes inside one chunk
    public void An_indefinite_length_text_is_reported_as_its_chunks_joined(string hex, string expected) =>
        Assert.Equal(expected, ParsedValue(hex));

    [Fact]
    public void An_indefinite_length_byte_string_is_reported_as_its_chunks_joined() =>
        // (_ h'01', h'0203')
        Assert.Equal(new byte[] { 1, 2, 3 }, ParsedValue("5F4101420203FF"));

    [Theory]
    [InlineData("62C328")]       // "\xC3\x28": a lead byte followed by no continuation
    [InlineData("61FF")]         // "\xFF"
    [InlineData("7F61C361A9FF")] // (_ "\xC3", "\xA9"): "é" split across two chunks
    public void Text_that_is_not_utf8_is_refused(string hex) =>
        Assert.Contains("not UTF-8", Refusal(hex), StringComparison.Ordinal);

    [Fact]
    public void A_map_key_that_is_not_utf8_is_refused() =>
        // {"\xFF": 1}
        Assert.Contains("not UTF-8", Refusal("A161FF01"), StringComparison.Ordinal);

    [Fact]
    public void An_indefinite_length_map_key_is_read() =>
        // {(_ "a"): 1}
        Assert.Equal(1L, Assert.IsType<Dictionary<string, object?>>(ParsedValue("A17F6161FF01"))["a"]);

    [Theory]
    [InlineData("F7")]     // undefined
    [InlineData("F0")]     // simple(16)
    [InlineData("F820")]   // simple(32)
    public void A_simple_value_other_than_true_false_and_null_is_refused(string hex) =>
        Assert.Contains("cannot represent", Refusal(hex), StringComparison.Ordinal);

    [Theory]
    [InlineData("C249010000000000000000", 2)]  // 2(h'010000000000000000'): 2^64
    [InlineData("C349010000000000000000", 3)]  // 3(h'010000000000000000'): -1 - 2^64
    [InlineData("C482211A00006AB3", 4)]        // 4([-2, 27315]): the decimal 273.15
    [InlineData("C5822103", 5)]                // 5([-2, 3]): a bigfloat
    [InlineData("D81E820103", 30)]             // 30([1, 3]): the rational 1/3
    [InlineData("D81900", 25)]                 // 25(0): a reference to a shared string
    [InlineData("D81D00", 29)]                 // 29(0): a reference to a shared value
    [InlineData("C001", 0)]                    // 0(1): tag 0 on an integer
    [InlineData("C0F97E00", 0)]                // 0(NaN)
    [InlineData("D818420102", 24)]             // 24(h'0102'): embedded CBOR
    [InlineData("D8206A323032342D30312D3031", 32)] // 32("2024-01-01"): a URI, whatever its text
    [InlineData("C0D903EC6A323032342D30312D3031", 1004)] // 0(1004("2024-01-01")): two date tags
    public void A_tag_the_result_cannot_carry_is_refused(string hex, int tag) =>
        Assert.Contains($"tag {tag}", Refusal(hex), StringComparison.Ordinal);

    [Theory]
    [InlineData("D903EC6A323032342D31332D3939")]               // 1004("2024-13-99")
    [InlineData("D903EC6A32303234303130312020")]               // 1004("20240101  ")
    [InlineData("C06A323032342D30312D3031")]                   // 0("2024-01-01"): a date with no time
    [InlineData("C073323032342D30312D30315431303A30303A3030")] // 0("2024-01-01T10:00:00"): no offset
    [InlineData("C074323032342D30312D30317431303A30303A30305A")] // 0("2024-01-01t10:00:00Z"): RFC 4287 wants "T"
    [InlineData("C075323032342D30312D30315431303A30303A30305A0A")] // 0("2024-01-01T10:00:00Z\n")
    [InlineData("C074323031362D31322D33315432333A35393A36305A")] // 0("2016-12-31T23:59:60Z"): a leap second
    [InlineData("C07819323032342D30312D30315431303A30303A30302B31343A3330")] // 0("2024-01-01T10:00:00+14:30"): beyond what DateTimeOffset holds
    [InlineData("D903EC6A303030302D30312D3031")] // 1004("0000-01-01"): before what DateOnly holds
    public void A_date_tag_on_text_that_is_not_its_date_is_refused(string hex) =>
        Assert.Contains("not its date", Refusal(hex), StringComparison.Ordinal);

    [Theory]
    [InlineData("D903EC6A323032342D30312D3031", "2024-01-01")]                   // 1004("2024-01-01")
    [InlineData("C074323032342D30312D30315431303A30303A30305A", "2024-01-01T10:00:00Z")] // 0("2024-01-01T10:00:00Z")
    [InlineData("C0781B323032342D30312D30315431303A30303A30302E352B30323A3030", "2024-01-01T10:00:00.5+02:00")]
    [InlineData("D9D9F7D903EC6A323032342D30312D3031", "2024-01-01")]             // 55799(1004("2024-01-01"))
    public void A_date_is_reported_as_its_text(string hex, string expected) =>
        Assert.Equal(expected, ParsedValue(hex));

    [Theory]
    [InlineData("F97E00")] // NaN
    [InlineData("F97C00")] // infinity
    [InlineData("FBFFF0000000000000")] // negative infinity
    public void A_number_with_no_json_form_is_refused(string hex) =>
        Assert.Contains("not finite", Refusal(hex), StringComparison.Ordinal);

    [Fact]
    public void An_item_without_an_element_value_is_refused()
    {
        _builder.Claims["value"] = true;
        _builder.TamperItem = (encoded, name) => name == "value" ? ItemWithoutValue() : encoded;
        var e = Assert.Throws<MdocProcessingException>(() => DeviceResponseParser.Parse(_builder.BuildBase64Url()));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
        Assert.Contains("elementValue", e.Message, StringComparison.Ordinal);
    }

    private static byte[] ItemWithoutValue()
    {
        var item = new CborWriter();
        item.WriteStartMap(3);
        item.WriteTextString("digestID");
        item.WriteInt64(0);
        item.WriteTextString("random");
        item.WriteByteString(new byte[16]);
        item.WriteTextString("elementIdentifier");
        item.WriteTextString("value");
        item.WriteEndMap();
        var tagged = new CborWriter();
        tagged.WriteTag(CborTag.EncodedCborDataItem);
        tagged.WriteByteString(item.Encode());
        return tagged.Encode();
    }

    [Fact]
    public void An_integer_beyond_long_is_refused() =>
        // 18446744073709551615
        Refusal("1BFFFFFFFFFFFFFFFF");

    [Fact]
    public void A_map_key_that_is_neither_text_nor_an_integer_is_refused() =>
        // {h'01': 1}
        Refusal("A1410101");

    [Theory]
    [InlineData("F6", null)]      // null stays null
    [InlineData("F5", true)]
    [InlineData("6161", "a")]     // a plain text value is unchanged
    public void Values_that_were_reported_before_still_are(string hex, object? expected) =>
        Assert.Equal(expected, ParsedValue(hex));
}
