namespace Tessio.Verifier.Core;

/// <summary>
/// Internal control-flow exception for RFC 9901 MUST-reject rules. Never escapes
/// <see cref="SdJwtVcVerifier"/>; it is converted into a <see cref="VerificationError"/>.
/// </summary>
internal sealed class SdJwtProcessingException : Exception
{
    public SdJwtProcessingException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }

    public VerificationError ToError() => new() { Code = Code, Message = Message };
}
