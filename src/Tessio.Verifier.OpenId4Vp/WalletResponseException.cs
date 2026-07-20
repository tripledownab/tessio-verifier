namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Thrown when a wallet response cannot be parsed into presented credentials.</summary>
public sealed class WalletResponseException : Exception
{
    /// <summary>Creates the exception.</summary>
    public WalletResponseException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with an inner cause.</summary>
    public WalletResponseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
