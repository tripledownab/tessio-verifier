using System.Globalization;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>A Longfellow <c>zkSystemId</c>, read into the circuit parameters it names.</summary>
// SPEC: no text this library could read requires this form; see ZkRequest for the text that governs the request.
// The form is a convention. The Longfellow wallet libraries and the informative A.11 example build each zkSystemId
// as longfellow-libzk-v1_{version}_{num_attributes}_{block_enc_hash}_{block_enc_sig}_{circuit_hash}. The example
// carries the same five values under "params".
internal sealed record LongfellowSystemId(
    string Value, int Version, int NumAttributes, int BlockEncHash, int BlockEncSig, string CircuitHash)
{
    /// <summary>The only zero knowledge system Annex A, A.8 puts in scope.</summary>
    internal const string System = "longfellow-libzk-v1";

    /// <summary>
    /// Whether <see cref="Value"/> is the one spelling of these parameters, with the hash in lowercase as the A.11
    /// example writes it. Only that spelling agrees with the lowercase <c>circuit_hash</c> a request writes beside it.
    /// </summary>
    internal bool IsCanonical =>
        Value == string.Create(
            CultureInfo.InvariantCulture, $"{System}_{Version}_{NumAttributes}_{BlockEncHash}_{BlockEncSig}_{CircuitHash}");

    /// <summary>
    /// The circuit hash a presented <c>zkSystemId</c> names in lowercase. Null when it names none. Two spellings name
    /// a circuit: this form and the bare circuit hash. The bare hash is what Longfellow's documentation recommends
    /// a reader set as the identifier ("zkSystemId: &lt;any value, we recommend using circuit_hash to avoid
    /// confusion&gt;", docs/content/en/docs/zk-system-spec.md at the commit the zero knowledge package pins).
    /// </summary>
    internal static string? CircuitHashNamedBy(string? zkSystemId) =>
        Parse(zkSystemId)?.CircuitHash ?? (IsHash(zkSystemId) ? zkSystemId!.ToLowerInvariant() : null);

    private static bool IsHash(string? text) => text is { Length: 64 } && text.All(char.IsAsciiHexDigit);

    /// <summary>
    /// Reads <paramref name="zkSystemId"/>, or returns null when it is null, names another system or is not of this form.
    /// Hex is case insensitive, so an uppercase hash names the same circuit and comes back lowercase.
    /// </summary>
    internal static LongfellowSystemId? Parse(string? zkSystemId)
    {
        if (zkSystemId is null)
        {
            return null;
        }

        var parts = zkSystemId.Split('_');
        if (parts.Length != 6 || parts[0] != System
            || Number(parts[1]) is not { } version || Number(parts[2]) is not { } attributes
            || Number(parts[3]) is not { } blockEncHash || Number(parts[4]) is not { } blockEncSig
            || !IsHash(parts[5]))
        {
            return null;
        }

        return new LongfellowSystemId(
            zkSystemId, version, attributes, blockEncHash, blockEncSig, parts[5].ToLowerInvariant());
    }

    // Digits only: no sign, no space, no leading zero, so each value has one spelling. At most nine, so it fits an int.
    private static int? Number(string text) =>
        text.Length is > 0 and <= 9 && text.All(char.IsAsciiDigit) && (text.Length == 1 || text[0] != '0')
            ? int.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture)
            : null;
}
