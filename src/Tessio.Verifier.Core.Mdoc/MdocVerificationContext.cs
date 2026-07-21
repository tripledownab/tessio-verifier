namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Per-verification context for mdoc presentations. Richer than the frozen
/// <see cref="VerificationContext"/> because the mdoc device signature covers the OpenID4VP
/// session transcript, which is built from more than a nonce.
/// </summary>
public sealed record MdocVerificationContext
{
    /// <summary>
    /// Expected document type from the DCQL query (e.g. <c>org.iso.18013.5.1.mDL</c>).
    /// When null, the docType check is skipped.
    /// </summary>
    public string? ExpectedDocType { get; init; }
}
