using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// A structural failure while processing an mdoc: malformed CBOR, a missing required element or an
/// invalid COSE structure. Carries a stable error code for <see cref="VerificationError.Code"/>.
/// </summary>
public sealed class MdocProcessingException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <remarks>
    /// The message is made one line by the library's one rule for messages it hands a caller, because it can
    /// quote values from the presented mdoc and a caller may log it as it stands.
    /// </remarks>
    public MdocProcessingException(string code, string message) : base(MessageText.OneLine(message)) => Code = code;

    /// <summary>Stable error code (see <see cref="MdocErrorCodes"/>).</summary>
    public string Code { get; }
}
