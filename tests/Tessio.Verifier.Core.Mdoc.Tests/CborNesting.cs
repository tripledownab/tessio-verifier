// What belongs here: CBOR values nested to a chosen depth, for the tests of CborValueConverter's cap.
using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc.Tests;

internal static class CborNesting
{
    /// <summary>Writes <paramref name="levels"/> arrays inside one another around a true, which is
    /// <paramref name="levels"/> levels of nesting to the converter.</summary>
    public static void Write(CborWriter writer, int levels)
    {
        for (var i = 0; i < levels; i++)
        {
            writer.WriteStartArray(1);
        }

        writer.WriteBoolean(true);
        for (var i = 0; i < levels; i++)
        {
            writer.WriteEndArray();
        }
    }
}
