// What belongs here: the one definition of which exceptions mean "this CBOR is malformed", so every
// reader that turns them into a typed error catches the same set.

using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

internal static class CborFailure
{
    /// <summary>
    /// Whether an exception from <see cref="CborReader"/> means the input is malformed. One list,
    /// because each reader kept its own and one omission let hostile input escape as an untyped
    /// exception: <see cref="OverflowException"/> is what <c>ReadInt64</c> throws for an integer outside
    /// the range of <see cref="long"/>.
    /// </summary>
    internal static bool IsMalformed(Exception e) =>
        e is CborContentException or InvalidOperationException or FormatException or OverflowException;
}
