namespace Tessio.Verifier.Core;

/// <summary>
/// Reads a NumericDate (RFC 7519 §2) from a credential. <see cref="DateTimeOffset.FromUnixTimeSeconds"/>
/// throws outside years 1 to 9999. A signed claim can name any second count a long holds, so every
/// read in this assembly goes through here. A value outside the range reads as the nearer end of it, so an
/// <c>exp</c> that far ahead does not expire and one that far behind has expired. Larger values, from
/// about 2^63 up, never get here: the JWT parser refuses the whole token first.
/// </summary>
internal static class UnixTime
{
    private static readonly long MinSeconds = DateTimeOffset.MinValue.ToUnixTimeSeconds();
    private static readonly long MaxSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

    public static DateTimeOffset FromSeconds(long seconds) =>
        DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(seconds, MinSeconds, MaxSeconds));

    public static DateTimeOffset FromSeconds(double seconds) =>
        seconds <= MinSeconds ? DateTimeOffset.MinValue
            : seconds >= MaxSeconds ? DateTimeOffset.MaxValue
            : DateTimeOffset.FromUnixTimeSeconds((long)seconds);
}
