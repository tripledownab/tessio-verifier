using System.Text;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Makes a message this library returns safe to write as one line: the single rule for every failure
/// message and trust reason the library hands to a caller.
/// </summary>
/// <remarks>
/// <para>
/// Messages quote what the presenter sent: certificate subjects and issuers from an <c>x5c</c> chain, an
/// <c>iss</c>, a <c>vct</c>, a <c>docType</c>, an element identifier. .NET keeps a line break or other
/// control character in all of them, so a caller that logs a message as it stands would let the
/// presenter end the log line and start one of their own.
/// </para>
/// <para>
/// Applied where a message LEAVES the library, not where it is written:
/// <c>VerificationResult.Invalid</c> for failures, the trust resolver's refusal for reasons, and
/// the constructors of the public exceptions (<c>WalletResponseException</c>, <c>MdocProcessingException</c>),
/// which <c>PublicExceptionMessageTests</c> finds by reflection so a new one cannot skip the rule. Each
/// message site quoting its own values would leave the next new site free to forget, and there are many.
/// </para>
/// <para>
/// Each character that could break the line becomes U+FFFD, so the message still shows that something was
/// there. That covers what <see cref="char.IsControl(char)"/> calls a control character with the C1 range
/// included. It covers U+2028 and U+2029 too: they are not control characters to .NET but are line breaks to
/// many log viewers and JSON consumers.
/// </para>
/// <para>
/// A message longer than <see cref="MessageText.MaxLength"/> is cut there. The presenter chooses the length of
/// what a message quotes, so without a bound one presentation could put megabytes into a result and a log.
/// </para>
/// </remarks>
internal static class MessageText
{
    private const char Replacement = '\uFFFD';

    // Named rather than written literally: both are invisible in a source file.
    private const char LineSeparator = '\u2028';
    private const char ParagraphSeparator = '\u2029';

    /// <summary>
    /// The most characters a message keeps. A message can quote a value of any length the presenter chose, such
    /// as an element identifier or a map key. The message ends up in a result and in logs.
    /// </summary>
    internal const int MaxLength = 1000;

    /// <summary>
    /// <paramref name="message"/> with every character that could break the line replaced, cut to
    /// <see cref="MaxLength"/> with an ellipsis where it was longer.
    /// </summary>
    public static string OneLine(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var kept = message.Length <= MaxLength ? message : Cut(message);
        if (!kept.Any(BreaksLine)) return kept;

        var line = new StringBuilder(kept.Length);
        foreach (var c in kept)
        {
            line.Append(BreaksLine(c) ? Replacement : c);
        }

        return line.ToString();
    }

    // MaxLength in all with the ellipsis included. Never half of a surrogate pair.
    private static string Cut(string message)
    {
        var end = MaxLength - 1;
        if (char.IsHighSurrogate(message[end - 1])) end--;
        return message[..end] + "…";
    }

    private static bool BreaksLine(char c) => char.IsControl(c) || c is LineSeparator or ParagraphSeparator;
}
