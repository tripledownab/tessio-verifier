namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Policy knobs for <see cref="MdocVerifier"/>.</summary>
public sealed class MdocVerifierOptions
{
    /// <summary>
    /// Tolerated clock skew for the MSO validity window. Defaults to 5 minutes, matching
    /// <see cref="SdJwtVcVerifierOptions.ClockSkew"/>.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether device authentication (the holder's signature over the session transcript) is
    /// required. Defaults to true, matching <see cref="SdJwtVcVerifierOptions.RequireKeyBinding"/>.
    /// When false, a present deviceSignature is still verified.
    /// </summary>
    public bool RequireDeviceAuth { get; set; } = true;

    /// <summary>
    /// Whether to enforce the MSO's <c>status</c> element when present: the credential's entry in the MSO
    /// revocation list it references, a status list or an identifier list. Defaults to true, matching
    /// <see cref="SdJwtVcVerifierOptions.CheckStatus"/>: a revoked credential fails verification, and so
    /// does one whose list cannot be fetched or validated. Turn off only where the list's host is
    /// unreachable by design.
    /// </summary>
    /// <remarks>
    /// A list is trusted only through the credential that referenced it: the certificate its MSO reference
    /// names, or else the certificate that signed the credential's own Document Signer, which the trust seam
    /// must vouch for on the same anchor as the Document Signer. A seam that reports no
    /// <see cref="Trust.IssuerTrustStatus.TrustAnchorThumbprint"/>, or that anchors on the Document Signer
    /// itself, cannot vouch for that certificate, so a credential whose MSO reference names no certificate
    /// fails with <see cref="ErrorCodes.StatusUnresolvable"/>. Anchor on IACA certificates, as for the
    /// Document Signer's own trust.
    /// </remarks>
    // SPEC: EAA-6.2.10.1-05 and -05.1 (Implementing Regulation (EU) 2024/2979, Annex II as replaced by
    // Implementing Regulation (EU) 2026/1731, adaptation (6)): verification is optional, but a relying party
    // that verifies revocation supports both mechanisms.
    public bool CheckStatus { get; set; } = true;

    /// <summary>
    /// How long a validated MSO revocation list may be served from cache before refetching. This is the
    /// ceiling: the list's own <c>ttl</c> shortens it and its <c>exp</c> caps it. Defaults to 5 minutes,
    /// matching <see cref="SdJwtVcVerifierOptions.StatusListCacheDuration"/>. Set to
    /// <see cref="TimeSpan.Zero"/> to fetch on every verification.
    /// </summary>
    // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 4d and section 13.7.
    public TimeSpan StatusListCacheDuration { get; set; } = TimeSpan.FromMinutes(5);
}
