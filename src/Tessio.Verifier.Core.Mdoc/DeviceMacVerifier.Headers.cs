// What belongs in this file: which deviceMac header buckets are accepted. The rest of the check is in
// DeviceMacVerifier.cs.
using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

internal static partial class DeviceMacVerifier
{
    /// <summary>Why the two header buckets cannot be accepted, or null when they can.</summary>
    // SPEC: RFC 9052 section 3: "Labels in each of the maps MUST be unique. When processing messages, if a label
    // appears multiple times, the message MUST be rejected as malformed." The same label in both buckets is only a
    // SHOULD NOT there, but the platform's COSE_Sign1 decoder refuses it for a deviceSignature, so it is refused
    // here too. Section 3.1, crit: "When present, the "crit" header parameter MUST be placed in the
    // protected-header-parameters bucket. The array MUST have at least one value in it." The only label this
    // verifier processes is alg.
    private static string? HeaderProblem(Mac0 mac)
    {
        try
        {
            return HeaderProblem(
                mac.ProtectedHeader.Length == 0 ? [] : IntegerLabels(mac.ProtectedHeader),
                IntegerLabels(mac.UnprotectedHeader));
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            return $"The deviceMac's headers are malformed: {e.Message}";
        }
    }

    private static string? HeaderProblem(Dictionary<long, byte[]> protectedLabels, Dictionary<long, byte[]> unprotectedLabels)
    {
        if (protectedLabels.Keys.Intersect(unprotectedLabels.Keys).Any())
        {
            return "The deviceMac names one header label in both its protected and unprotected headers.";
        }

        if (unprotectedLabels.ContainsKey(CritLabel))
        {
            return "The deviceMac marks headers critical in its unprotected header, where crit may not be.";
        }

        if (protectedLabels.TryGetValue(CritLabel, out var crit) && !CritNamesOnlyAlg(crit))
        {
            return "The deviceMac's crit header is empty, malformed, or marks a header critical that this verifier "
                + "does not process.";
        }

        return protectedLabels.TryGetValue(AlgLabel, out var alg) && IsInteger(alg, Hmac256)
            ? null
            : "The deviceMac's protected header does not give alg 5, HMAC 256/256, the only one ISO/IEC 18013-5 allows.";
    }

    /// <summary>A header map's integer labels and their encoded values. Text labels are never read, so not kept.</summary>
    /// <exception cref="CborContentException">The map is malformed, repeats a label or has bytes after it.</exception>
    private static Dictionary<long, byte[]> IntegerLabels(byte[] encodedMap)
    {
        // MdocCbor refuses a repeated label, which RFC 9052 section 3 requires, also when its copies are encoded
        // differently: Strict alone compares encodings and lets {1: 5, 1_0: -7} through. Strict is kept for text
        // that is not UTF-8.
        var reader = MdocCbor.Reader(encodedMap, CborConformanceMode.Strict);
        var labels = new Dictionary<long, byte[]>();
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.PeekState() is CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger)
            {
                var label = reader.ReadInt64();
                labels[label] = reader.ReadEncodedValue().ToArray();
            }
            else
            {
                reader.SkipValue();
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The header map has bytes after it.");
        }

        return labels;
    }

    /// <summary>Whether a crit value is an array of at least one label, every one of them alg.</summary>
    private static bool CritNamesOnlyAlg(byte[] crit)
    {
        try
        {
            var reader = new CborReader(crit, CborConformanceMode.Lax);
            reader.ReadStartArray();
            var named = 0;
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                if (!IsInteger(reader, AlgLabel))
                {
                    return false;
                }

                named++;
            }

            return named > 0;
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            return false;
        }
    }

    private static bool IsInteger(byte[] encoded, long expected) =>
        IsInteger(new CborReader(encoded, CborConformanceMode.Lax), expected);

    // False, and nothing consumed, for anything but an integer: every caller then refuses.
    private static bool IsInteger(CborReader reader, long expected) =>
        reader.PeekState() is CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger
        && reader.ReadInt64() == expected;
}
