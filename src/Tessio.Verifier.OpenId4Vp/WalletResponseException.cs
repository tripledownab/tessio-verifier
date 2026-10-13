using Tessio.Verifier.Trust;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Thrown when a wallet response cannot be parsed into presented credentials.</summary>
/// <remarks>
/// The message is made one line here, by the library's one rule for messages it hands a caller
/// (<see cref="MessageText.OneLine"/>), because a message can quote what the response's sender wrote and a
/// caller may log it as it stands. Here rather than at each message site, so a new site cannot forget it.
/// <para>
/// The rule covers this exception's own message, not an <see cref="Exception.InnerException"/>: that is
/// the underlying library's exception, and its text is that library's. A caller logging the whole exception
/// rather than its message should make the line safe itself, as this library's own log lines do.
/// </para>
/// </remarks>
public sealed class WalletResponseException : Exception
{
    /// <summary>Creates the exception.</summary>
    public WalletResponseException(string message)
        : base(MessageText.OneLine(message))
    {
    }

    /// <summary>Creates the exception with an inner cause.</summary>
    public WalletResponseException(string message, Exception innerException)
        : base(MessageText.OneLine(message), innerException)
    {
    }
}
