namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Decoding for hex test vectors kept as wrapped raw string literals. Keeps only hex digits,
/// because git checkout rewrites a raw string's line endings per platform.
/// </summary>
internal static class WrappedHex
{
    public static byte[] Decode(string wrappedHex) =>
        Convert.FromHexString(string.Concat(wrappedHex.Where(char.IsAsciiHexDigit)));
}
