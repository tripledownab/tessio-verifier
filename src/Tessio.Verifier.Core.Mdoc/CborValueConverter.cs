using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Converts a CBOR data item to the plain .NET shape used in
/// <see cref="VerificationResult.DisclosedClaims"/>: string, long, double, bool, byte[],
/// List&lt;object?&gt;, Dictionary&lt;string, object?&gt; or null for CBOR null. Dates (tag 0 tdate,
/// tag 1004 full-date) surface as their RFC 3339 strings, an integer map key as its decimal text and a string sent
/// in chunks as the chunks joined. Anything else that shape cannot carry is refused rather than approximated: text
/// that is not UTF-8, a date tag whose text is no date .NET can hold (a leap second among them), any other tag, an
/// integer outside long, NaN or infinity, a key that is neither text nor an integer, two keys that become one and a
/// simple value other than true, false and null. Each throws an exception that
/// <see cref="CborFailure.IsMalformed"/> makes a structure error.
/// </summary>
internal static partial class CborValueConverter
{
    /// <summary>
    /// How deeply arrays and maps may nest in one value. Recursion is bounded so that a hostile value cannot
    /// overflow the stack; mdoc element values nest a few levels at most. It is the bound disclosed SD-JWT claims
    /// are held to (<see cref="Tessio.Verifier.Core.JsonValueConverter.MaxDepth"/>), so a result's claims share one
    /// depth whichever format they came from.
    /// </summary>
    internal const int MaxDepth = Tessio.Verifier.Core.JsonValueConverter.MaxDepth;

    public static object? Read(CborReader reader) => Read(reader, 0);

    private static object? Read(CborReader reader, int depth)
    {
        if (depth > MaxDepth)
        {
            // InvalidOperationException is what CborFailure.IsMalformed maps to a structure error.
            throw new InvalidOperationException($"A CBOR value nests deeper than {MaxDepth} levels.");
        }

        CborTag? date = null;
        while (reader.PeekState() == CborReaderState.Tag)
        {
            // A tag gives its content a meaning the result's shape has no room for: a bignum's bytes mean a number,
            // tag 4's array means a decimal. Reporting the content alone would report something else, so a tag is
            // refused unless the result can carry its meaning. That is this library's choice, not a rule of RFC 8949:
            // for a tag a decoder does not recognise, section 5.4 permits the error while discouraging it, and its
            // other option, passing the content on marked as unrecognised, has no mark to carry it in the result.
            // Tag 55799 only marks the bytes as CBOR and changes no meaning.
            var tag = reader.ReadTag();
            if (tag == CborTag.SelfDescribeCbor)
            {
                continue;
            }

            if (date is not null || tag is not (CborTag.DateTimeString or FullDate))
            {
                throw new InvalidOperationException(
                    $"A claim value holds CBOR tag {(ulong)tag}, which the result cannot represent.");
            }

            date = tag;
        }

        if (date is { } dateTag)
        {
            return ReadDate(reader, dateTag);
        }

        switch (reader.PeekState())
        {
            case CborReaderState.TextString:
            case CborReaderState.StartIndefiniteLengthTextString:
                return ReadText(reader);
            case CborReaderState.UnsignedInteger:
            case CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
            {
                // NaN and infinity have no JSON form, so a result holding one could not be written out. SD-JWT
                // claims are held to the same rule (StrictJson).
                var number = reader.ReadDouble();
                return double.IsFinite(number)
                    ? number
                    : throw new InvalidOperationException("A claim value holds a number that is not finite.");
            }
            case CborReaderState.Boolean:
                return reader.ReadBoolean();
            case CborReaderState.Null:
                reader.ReadNull();
                return null;
            case CborReaderState.ByteString:
            case CborReaderState.StartIndefiniteLengthByteString:
                // An indefinite-length byte string is read as its chunks joined (RFC 8949 section 3.2.3).
                return reader.ReadByteString();
            case CborReaderState.StartArray:
            {
                List<object?> list = [];
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    list.Add(Read(reader, depth + 1));
                }

                reader.ReadEndArray();
                return list;
            }

            case CborReaderState.StartMap:
            {
                Dictionary<string, object?> map = new(StringComparer.Ordinal);
                reader.ReadStartMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    // Non-text keys are legal CBOR; stringify so the claim survives into the result. Stringifying makes
                    // the text "4" and the integer 4 one key. Two keys distinct in CBOR that become one here are
                    // refused, not resolved by the last: RFC 8949 section 5.6.1 leaves that check to the application.
                    var key = reader.PeekState() is CborReaderState.TextString or CborReaderState.StartIndefiniteLengthTextString
                        ? ReadText(reader)
                        : reader.ReadInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
                    if (!map.TryAdd(key, Read(reader, depth + 1)))
                    {
                        throw new InvalidOperationException($"A claim value's map gives the key '{key}' twice.");
                    }
                }

                reader.ReadEndMap();
                return map;
            }

            default:
                // undefined and other simple values have no place in the result's shape. Reporting them as null
                // would say the issuer signed null, so they are refused.
                throw new InvalidOperationException(
                    $"A claim value holds a CBOR {reader.PeekState()}, which the result cannot represent.");
        }
    }

    // SPEC: RFC 8943 section 2.1 registers tag 1004 as a text string holding an RFC 3339 full-date.
    private const CborTag FullDate = (CborTag)1004;

    // SPEC: RFC 8949 section 3.4.1 requires tag 0's text to be an RFC 3339 date-time as refined by RFC 4287
    // section 3.3, which makes the "T" and the "Z" uppercase. The seconds stop at 59: RFC 3339 allows a leap
    // second, but whether DateTimeOffset accepts one depends on the operating system, and a presentation must not
    // verify on one host and fail on another. The pattern matches in time linear in the text, so it is given no
    // timeout: one would throw an exception that CborFailure.IsMalformed does not map.
    [System.Text.RegularExpressions.GeneratedRegex(
        @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})\z",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant, System.Threading.Timeout.Infinite)]
    private static partial System.Text.RegularExpressions.Regex DateTimeText();

    // A date is reported as its text, so the text must be the date its tag says it is. Text that is no date would
    // reach the result as a date nobody can read. Text that RFC 3339 allows but DateTimeOffset and DateOnly cannot
    // hold, such as the year 0000 or an offset beyond 14 hours, is refused too.
    private static string ReadDate(CborReader reader, CborTag tag)
    {
        if (reader.PeekState() is not (CborReaderState.TextString or CborReaderState.StartIndefiniteLengthTextString))
        {
            throw new InvalidOperationException(
                $"A claim value's CBOR tag {(ulong)tag} holds a {reader.PeekState()}, where it requires text.");
        }

        var text = ReadText(reader);
        var valid = tag == FullDate
            ? DateOnly.TryParseExact(text, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out _)
            : DateTimeText().IsMatch(text) && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out _);
        return valid
            ? text
            : throw new InvalidOperationException($"A claim value's CBOR tag {(ulong)tag} holds text that is not its date.");
    }

    private static readonly System.Text.UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // Text as the issuer signed it. The reader's own decoding depends on its mode: Lax puts U+FFFD where bytes are
    // not UTF-8, so the result would report text the issuer never signed. Each chunk of an indefinite-length
    // string is decoded alone: RFC 8949 section 3.2.3 lets no code point span two chunks.
    private static string ReadText(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.StartIndefiniteLengthTextString)
        {
            return Decode(reader.ReadDefiniteLengthTextStringBytes().Span);
        }

        var text = new System.Text.StringBuilder();
        reader.ReadStartIndefiniteLengthTextString();
        while (reader.PeekState() != CborReaderState.EndIndefiniteLengthTextString)
        {
            text.Append(Decode(reader.ReadDefiniteLengthTextStringBytes().Span));
        }

        reader.ReadEndIndefiniteLengthTextString();
        return text.ToString();
    }

    private static string Decode(ReadOnlySpan<byte> utf8)
    {
        try
        {
            return Utf8.GetString(utf8);
        }
        catch (System.Text.DecoderFallbackException)
        {
            throw new InvalidOperationException("A claim value holds text that is not UTF-8.");
        }
    }
}
