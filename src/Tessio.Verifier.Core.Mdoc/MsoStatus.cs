using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Which kind of MSO revocation list a reference points to.</summary>
internal enum RevocationListKind
{
    /// <summary>A Token Status List: the credential's bit at an index.</summary>
    StatusList,

    /// <summary>An identifier list: the credential is revoked when its identifier is listed.</summary>
    IdentifierList,
}

/// <summary>
/// One reference from the MSO's <c>status</c> element to an MSO revocation list. <see cref="Index"/> is set
/// for a status list and <see cref="Id"/> for an identifier list.
/// </summary>
/// <param name="Kind">The mechanism.</param>
/// <param name="Uri">Where the list is published; its token's <c>sub</c> must equal it.</param>
/// <param name="Index">The credential's index in a status list.</param>
/// <param name="Id">The credential's identifier on an identifier list.</param>
/// <param name="Certificate">
/// The optional <c>certificate</c> element: when present, the trust anchor for the list's x5chain.
/// </param>
internal sealed record RevocationListReference(
    RevocationListKind Kind, string Uri, long Index, byte[]? Id, byte[]? Certificate);

/// <summary>
/// Reads the MSO's <c>status</c> element. Kept as encoded bytes by the MSO parser and read only here, so a
/// verifier configured not to check status is not refused for a status it never reads.
/// </summary>
// SPEC: Implementing Regulation (EU) 2024/2979, Annex II as replaced by Implementing Regulation (EU) 2026/1731 (its
// Annex IV), adaptation (6), which replaces clause
// 6.2.10.1 of ETSI TS 119 472-1 V1.2.1. Requirement numbers below are that clause's, "EAA-6.2.10.1-NN".
// The ISO/IEC 18013-5 second edition working draft of 2025-09-14 has an earlier version of these rules in clause
// 12.3.6, with the same structures but a different draft of the status list and a different algorithm set.
// Where the two differ, the regulation governs.
internal static class MsoStatus
{
    /// <summary>
    /// Every reference the element carries, or the reason it is unusable. Both mechanisms may be present,
    /// and each one present is checked.
    /// </summary>
    public static (IReadOnlyList<RevocationListReference> References, string? Problem) Read(byte[] encoded)
    {
        try
        {
            // STRICT, so a duplicated key is refused rather than resolved by whichever copy came last.
            var reader = new CborReader(encoded, CborConformanceMode.Strict);
            List<RevocationListReference> references = [];

            // SPEC: EAA-6.2.10.1-17, Status = { ? 'identifier_list' : IdentifierListInfo,
            // ? 'status_list' : StatusListInfo, * tstr => RFU }.
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "status_list":
                        references.Add(ReadReference(reader, RevocationListKind.StatusList));
                        break;
                    case "identifier_list":
                        references.Add(ReadReference(reader, RevocationListKind.IdentifierList));
                        break;
                    default:
                        // RFU: a mechanism defined after this code was written. Ignored here, and if it is
                        // the only one present the element is refused below for naming nothing checkable.
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();
            return references.Count == 0
                ? ([], "The MSO status element names neither a status_list nor an identifier_list.")
                : (references, null);
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            return ([], $"The MSO status element is malformed: {e.Message}");
        }
    }

    private static RevocationListReference ReadReference(CborReader reader, RevocationListKind kind)
    {
        string? uri = null;
        long? index = null;
        byte[]? id = null, certificate = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                // SPEC: EAA-6.2.10.1-13.1 and draft-ietf-oauth-status-list-20 section 6.3, idx is an unsigned
                // integer. Read as one, then narrowed, so a value past a long is refused rather than wrapped.
                case "idx" when kind == RevocationListKind.StatusList:
                    var idx = reader.ReadUInt64();
                    index = idx <= long.MaxValue
                        ? (long)idx
                        : throw new FormatException($"The status_list idx {idx} is out of range.");
                    break;
                // SPEC: EAA-6.2.10.1-11.1, IdentifierListInfo = { 'id': Identifier, 'uri': URI,
                // ? 'certificate': Certificate * tstr => RFU }, Identifier = bstr.
                case "id" when kind == RevocationListKind.IdentifierList:
                    id = reader.ReadByteString();
                    break;
                case "uri":
                    uri = reader.ReadTextString();
                    break;
                // SPEC: EAA-6.2.10.1-06 and -13.1, both structures may carry the certificate element.
                case "certificate":
                    certificate = reader.ReadByteString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        var name = kind == RevocationListKind.StatusList ? "status_list" : "identifier_list";
        if (uri is null)
        {
            throw new FormatException($"The {name} element carries no uri.");
        }

        return kind == RevocationListKind.StatusList
            ? new RevocationListReference(kind, uri, index ?? throw new FormatException("The status_list element carries no idx."), null, certificate)
            : new RevocationListReference(kind, uri, -1, id ?? throw new FormatException("The identifier_list element carries no id."), certificate);
    }
}
