namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Stable error codes for mdoc verification failures, alongside the shared codes in
/// <see cref="ErrorCodes"/> (structure_invalid, signature_invalid, issuer_untrusted, …).
/// </summary>
public static class MdocErrorCodes
{
    /// <summary>Malformed base64url, CBOR or a missing required element (shared with Core).</summary>
    public const string StructureInvalid = ErrorCodes.StructureInvalid;

    /// <summary>The credential is not an mdoc (shared with Core).</summary>
    public const string FormatUnsupported = ErrorCodes.FormatUnsupported;

    /// <summary>The COSE signature algorithm is not on the allowlist (shared with Core).</summary>
    public const string AlgorithmNotAllowed = ErrorCodes.AlgorithmNotAllowed;

    /// <summary>The issuerAuth signature does not verify (shared with Core).</summary>
    public const string SignatureInvalid = ErrorCodes.SignatureInvalid;

    /// <summary>The Document Signer key could not be resolved from x5chain (shared with Core).</summary>
    public const string IssuerKeyUnresolvable = ErrorCodes.IssuerKeyUnresolvable;

    /// <summary>The issuer does not chain to a configured trust anchor (shared with Core).</summary>
    public const string IssuerUntrusted = ErrorCodes.IssuerUntrusted;

    /// <summary>The MSO validity window has passed (shared with Core).</summary>
    public const string CredentialExpired = ErrorCodes.CredentialExpired;

    /// <summary>The MSO validity window has not started (shared with Core).</summary>
    public const string CredentialNotYetValid = ErrorCodes.CredentialNotYetValid;

    /// <summary>A disclosed item's digest does not appear in the MSO's valueDigests.</summary>
    public const string DigestMismatch = "mdoc_digest_mismatch";

    /// <summary>The MSO is malformed or carries unsupported values.</summary>
    public const string MsoInvalid = "mdoc_mso_invalid";

    /// <summary>The document's docType does not match the requested doctype.</summary>
    public const string DocTypeMismatch = "mdoc_doctype_mismatch";

    /// <summary>The device signature over the session transcript does not verify.</summary>
    public const string DeviceAuthInvalid = "mdoc_device_auth_invalid";
}
