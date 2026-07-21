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

    /// <summary>
    /// The <c>client_id</c> of the request this presentation answers, including any client
    /// identifier prefix. First element of the session transcript's handover info.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>The nonce of the request. Second element of the handover info.</summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// RFC 7638 SHA-256 thumbprint of the verifier's response-encryption JWK, when the response was
    /// encrypted; null for unencrypted responses. Third element of the handover info.
    /// </summary>
    public byte[]? EncryptionKeyThumbprint { get; init; }

    /// <summary>The <c>response_uri</c> of the request. Fourth element of the handover info.</summary>
    public string? ResponseUri { get; init; }
}
