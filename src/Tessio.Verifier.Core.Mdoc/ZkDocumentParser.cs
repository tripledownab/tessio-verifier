using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

// SPEC: the shape follows the example of a zero knowledge response in the age verification technical
// specification 1.1.0, Annex A, A.11: ZkDocument = {proof: bstr, documentData: #6.24(bstr .cbor
// {zkSystemId, docType, timestamp: #6.0(tdate), issuerSigned, deviceSigned, msoX5chain})}. ISO/IEC
// 18013-5 second edition §10.2.7 defines it normatively; that text is not freely available.

/// <summary>One zero knowledge presentation from a DeviceResponse's <c>zkDocuments</c>.</summary>
internal sealed record ParsedZkDocument
{
    public required byte[] Proof { get; init; }

    /// <summary>Names the proof system and circuit, for example <c>longfellow-libzk-v1_6_1_4096_2945_137e…</c>.</summary>
    public required string ZkSystemId { get; init; }

    public required string DocType { get; init; }

    /// <summary>
    /// The wallet's timestamp exactly as transported. The proof is bound to these characters, so the
    /// verifier passes them on unchanged and checks <see cref="Timestamp"/> against its own clock.
    /// </summary>
    public required string TimestampText { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Disclosed items per namespace, each value kept as its encoded CBOR.</summary>
    public required IReadOnlyDictionary<string, IReadOnlyList<ZkDisclosedItem>> NameSpaces { get; init; }

    /// <summary>The issuer's certificate chain, document signer first.</summary>
    public required ReadOnlyMemory<byte>[] MsoX5Chain { get; init; }
}

/// <summary>One disclosed element of a zero knowledge presentation: its value decoded and as encoded CBOR.</summary>
internal sealed record ZkDisclosedItem(string ElementIdentifier, object? Value, byte[] EncodedValue);

/// <summary>Reads one <c>zkDocuments</c> entry. Malformed input becomes <see cref="MdocErrorCodes.StructureInvalid"/>.</summary>
internal static class ZkDocumentParser
{
    /// <summary>The shortest docType Longfellow does not bind as given.</summary>
    internal const int MaxDocTypeBytes = 256;

    public static ParsedZkDocument Parse(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            return Read(new CborReader(encoded, CborConformanceMode.Lax));
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            throw Invalid($"A zkDocuments entry is malformed: {e.Message}");
        }
    }

    private static ParsedZkDocument Read(CborReader reader)
    {
        byte[]? proof = null;
        byte[]? documentData = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "proof":
                    proof = reader.ReadByteString();
                    break;
                case "documentData":
                    if (reader.PeekState() == CborReaderState.Tag)
                    {
                        reader.ReadTag();
                    }

                    documentData = reader.ReadByteString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();
        if (proof is not { Length: > 0 } || documentData is null)
        {
            throw Invalid("A zkDocuments entry lacks its proof or documentData.");
        }

        return ReadDocumentData(new CborReader(documentData, CborConformanceMode.Lax), proof);
    }

    private static ParsedZkDocument ReadDocumentData(CborReader reader, byte[] proof)
    {
        string? zkSystemId = null, docType = null, timestamp = null;
        Dictionary<string, IReadOnlyList<ZkDisclosedItem>>? nameSpaces = null;
        ReadOnlyMemory<byte>[]? chain = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "zkSystemId":
                    zkSystemId = reader.ReadTextString();
                    break;
                case "docType":
                    docType = reader.ReadTextString();
                    break;
                case "timestamp":
                    if (reader.PeekState() == CborReaderState.Tag)
                    {
                        reader.ReadTag();
                    }

                    timestamp = reader.ReadTextString();
                    break;
                case "issuerSigned":
                    nameSpaces = ReadIssuerSigned(reader);
                    break;
                case "msoX5chain":
                    chain = ReadChain(reader);
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();
        if (zkSystemId is null || docType is null || timestamp is null || nameSpaces is null || chain is not { Length: > 0 })
        {
            throw Invalid("A zero knowledge documentData lacks zkSystemId, docType, timestamp, issuerSigned or msoX5chain.");
        }

        // SPEC: the circuit compares the first 20 bytes of the timestamp, byte by byte, with the MSO's validFrom
        // and validUntil (longfellow-zk v0.9, mdoc_zk.cc fill_bit_string(..., now, 20, ...) and mdoc_hash.h CMP.leq
        // with kDateLen = 20). Only the exact form yyyy-MM-ddTHH:mm:ssZ means the same instant to that comparison as
        // to this verifier's clock; any other text could pass the clock check here while proving validity at
        // another time.
        if (!DateTimeOffset.TryParseExact(timestamp, "yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            throw Invalid("A zero knowledge presentation's timestamp is not of the form yyyy-MM-ddTHH:mm:ssZ.");
        }

        // The library reads the docType as a C string, so a NUL would cut what the proof covers short of what is
        // reported. It also binds a docType of 256 bytes or more as the mDL docType instead (longfellow-zk v0.9,
        // mdoc_witness.h compute_transcript_hash), so a long one would be reported without being proved.
        if (docType.Contains('\0', StringComparison.Ordinal) || System.Text.Encoding.UTF8.GetByteCount(docType) >= MaxDocTypeBytes)
        {
            throw Invalid($"A zero knowledge presentation's docType contains a NUL or is {MaxDocTypeBytes} bytes or longer.");
        }

        return new ParsedZkDocument
        {
            Proof = proof,
            ZkSystemId = zkSystemId,
            DocType = docType,
            TimestampText = timestamp,
            Timestamp = parsed,
            NameSpaces = nameSpaces,
            MsoX5Chain = chain,
        };
    }

    private static Dictionary<string, IReadOnlyList<ZkDisclosedItem>> ReadIssuerSigned(CborReader reader)
    {
        var result = new Dictionary<string, IReadOnlyList<ZkDisclosedItem>>(StringComparer.Ordinal);
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            var nameSpace = reader.ReadTextString();
            List<ZkDisclosedItem> items = [];
            reader.ReadStartArray();
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                var item = ReadItem(reader);
                if (items.Exists(i => i.ElementIdentifier == item.ElementIdentifier))
                {
                    throw Invalid($"A zero knowledge presentation discloses '{item.ElementIdentifier}' more than once.");
                }

                items.Add(item);
            }

            reader.ReadEndArray();
            if (!result.TryAdd(nameSpace, items))
            {
                throw Invalid($"A zero knowledge presentation lists namespace '{nameSpace}' more than once.");
            }
        }

        reader.ReadEndMap();
        return result;
    }

    private static ZkDisclosedItem ReadItem(CborReader reader)
    {
        string? identifier = null;
        byte[]? value = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "elementIdentifier":
                    identifier = reader.ReadTextString();
                    break;
                case "elementValue":
                    value = reader.ReadEncodedValue().ToArray();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();
        return identifier is null || value is null
            ? throw Invalid("A zero knowledge disclosed item lacks elementIdentifier or elementValue.")
            // Strict, so text that is not valid UTF-8 is refused. The library sees the raw bytes while the result
            // reports their decoding, and the two must not differ.
            : new ZkDisclosedItem(identifier, CborValueConverter.Read(new CborReader(value, CborConformanceMode.Strict)), value);
    }

    // SPEC: as for issuerAuth's x5chain (RFC 9360 §2), one certificate is a bstr and several are an array.
    private static ReadOnlyMemory<byte>[] ReadChain(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.ByteString)
        {
            return [reader.ReadByteString()];
        }

        List<ReadOnlyMemory<byte>> certificates = [];
        reader.ReadStartArray();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            certificates.Add(reader.ReadByteString());
        }

        reader.ReadEndArray();
        return [.. certificates];
    }

    private static MdocProcessingException Invalid(string message) => new(MdocErrorCodes.StructureInvalid, message);
}
