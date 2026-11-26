// What belongs here: the reader for CBOR whose maps a presenter or an issuer wrote, so a map that gives a key twice is
// refused instead of being read as whichever copy the reader met last. Readers of arrays and single values make
// their own readers, as does the platform's COSE decoder: MdocCborTests lists which files may.

using System.Formats.Cbor;
using System.Numerics;

namespace Tessio.Verifier.Core.Mdoc;

internal static class MdocCbor
{
    /// <summary>
    /// A reader over <paramref name="cbor"/>, after every map in it has been checked for a key given twice. Lax by
    /// default, because wallets are not required to emit canonical CBOR and digests are computed over the bytes as
    /// sent. <see cref="CborConformanceMode.Strict"/> where a caller also wants text refused that is not UTF-8.
    /// </summary>
    /// <remarks>
    /// Keys are compared by what they decode to, not by their bytes. <see cref="CborConformanceMode.Strict"/>
    /// compares encodings. So it accepts <c>{"a": 1, (_ "a"): 2}</c>, its second key an indefinite-length string,
    /// as it accepts <c>{4: 1, 4_0: 2}</c>, its second key a longer integer encoding (RFC 8949 section 8.1). A
    /// parser decodes both copies to the same key and keeps the last. Text keys compare as strings, integer keys as
    /// numbers and byte string keys as bytes. Any other key compares by its encoding. A map used as a key is not
    /// walked. Where the library itself turns keys of different kinds into one, as <see cref="CborValueConverter"/>
    /// turns the integer 4 into the text "4", it refuses its own collisions.
    /// Byte strings are not opened: CBOR carried inside one, such as a tag 24 item, is checked when its own
    /// reader is made here.
    /// </remarks>
    /// <exception cref="CborContentException">A map gives a key twice or the CBOR is not well formed.</exception>
    internal static CborReader Reader(ReadOnlyMemory<byte> cbor, CborConformanceMode mode = CborConformanceMode.Lax)
    {
        RefuseRepeatedKeys(new CborReader(cbor, mode));
        return new CborReader(cbor, mode);
    }

    // Recursion follows arrays and maps only, which CborReader refuses past its own nesting limit. Tags are not
    // under that limit, so they are read in a loop: one recursion per tag let a value under a million tags end the
    // process with a stack overflow.
    private static void RefuseRepeatedKeys(CborReader reader)
    {
        while (reader.PeekState() == CborReaderState.Tag)
        {
            reader.ReadTag();
        }

        switch (reader.PeekState())
        {
            case CborReaderState.StartMap:
                reader.ReadStartMap();
                HashSet<string> seen = new(StringComparer.Ordinal);
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    var key = KeyOf(reader);
                    if (!seen.Add(key))
                    {
                        throw new CborContentException($"A map gives the key {key[2..]} twice.");
                    }

                    RefuseRepeatedKeys(reader);
                }

                reader.ReadEndMap();
                break;
            case CborReaderState.StartArray:
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    RefuseRepeatedKeys(reader);
                }

                reader.ReadEndArray();
                break;
            default:
                reader.SkipValue();
                break;
        }
    }

    // A key's decoded value, prefixed by its kind so the text "4" and the integer 4 stay apart. The refusal prints
    // it from the third character on. MessageText makes that message one line of bounded length where it leaves
    // the library.
    private static string KeyOf(CborReader reader) => reader.PeekState() switch
    {
        CborReaderState.TextString or CborReaderState.StartIndefiniteLengthTextString =>
            "t:'" + reader.ReadTextString() + "'",
        CborReaderState.UnsignedInteger =>
            "i:" + reader.ReadUInt64().ToString(System.Globalization.CultureInfo.InvariantCulture),
        // CBOR's negative integer n stands for -1 - n, whose range reaches below long's.
        CborReaderState.NegativeInteger =>
            "i:" + (-1 - (BigInteger)reader.ReadCborNegativeIntegerRepresentation())
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
        CborReaderState.ByteString or CborReaderState.StartIndefiniteLengthByteString =>
            "b:" + Convert.ToHexString(reader.ReadByteString()),
        _ => "e:" + Convert.ToHexString(reader.ReadEncodedValue().Span),
    };
}
