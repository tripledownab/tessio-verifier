// What belongs here: that a WalletResponseException message is one line whatever it quotes, made so by the
// exception itself and seen through the parser. Which characters break a line is MessageText's own tests'.

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// A message can quote what a response's sender wrote, and a caller may log it as it stands, so no line
/// break, other control character or Unicode line separator may survive into it.
/// </summary>
public sealed class WalletResponseExceptionTests
{
    public static TheoryData<string> Breaks() => new() { "\t", "\n", "\r", "\r\n", "\u0085", "\u2028", "\u2029", "\u0000" };

    [Theory]
    [MemberData(nameof(Breaks))]
    public void The_message_is_one_line_from_either_constructor(string lineBreak)
    {
        var quoted = $"before{lineBreak}after";

        foreach (var e in new[] { new WalletResponseException(quoted), new WalletResponseException(quoted, new FormatException()) })
        {
            Assert.DoesNotContain(lineBreak, e.Message, StringComparison.Ordinal);
            // Kept the same length, so it still shows that something was there.
            Assert.Equal(quoted.Length, e.Message.Length);
            Assert.StartsWith("before", e.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [MemberData(nameof(Breaks))]
    public async Task A_content_type_the_sender_wrote_reaches_the_message_on_one_line(string lineBreak)
    {
        // The parser quotes the request's content type when it refuses one. A multipart form passes a host's
        // form check and fails the parser's, and its boundary is whatever the sender wrote.
        var contentType = $"multipart/form-data; boundary=\"a{lineBreak}forged\"";
        var parser = new WalletResponseParser(new WalletResponseParserOptions());

        var e = await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDetailedAsync(new WalletResponseData
        {
            ContentType = contentType,
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal),
            Body = ReadOnlyMemory<byte>.Empty,
        }));

        // The sender's text did reach the message, so the absence of the break is the rule at work.
        Assert.Contains("forged", e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(lineBreak, e.Message, StringComparison.Ordinal);
    }
}
