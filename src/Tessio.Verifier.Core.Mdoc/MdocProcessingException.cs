namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// A structural failure while processing an mdoc: malformed CBOR, a missing required element or an
/// invalid COSE structure. Carries a stable error code for <see cref="VerificationError.Code"/>.
/// </summary>
public sealed class MdocProcessingException : Exception
{
    /// <summary>Creates the exception.</summary>
    public MdocProcessingException(string code, string message) : base(message) => Code = code;

    /// <summary>Stable error code (see <see cref="MdocErrorCodes"/>).</summary>
    public string Code { get; }
}
