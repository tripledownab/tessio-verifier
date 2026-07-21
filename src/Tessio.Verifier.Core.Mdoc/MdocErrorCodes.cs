namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Stable error codes for mdoc verification failures, alongside the shared codes in
/// <see cref="ErrorCodes"/> (structure_invalid, signature_invalid, issuer_untrusted, …).
/// </summary>
public static class MdocErrorCodes
{
    /// <summary>Malformed base64url, CBOR or a missing required element (shared code with Core).</summary>
    public const string StructureInvalid = "structure_invalid";

    /// <summary>The credential is not an mdoc (shared code with Core).</summary>
    public const string FormatUnsupported = "format_unsupported";

    /// <summary>The COSE signature algorithm is not on the allowlist (shared code with Core).</summary>
    public const string AlgorithmNotAllowed = "algorithm_not_allowed";

    /// <summary>The issuerAuth signature does not verify (shared code with Core).</summary>
    public const string SignatureInvalid = "signature_invalid";

    /// <summary>The Document Signer key could not be resolved from x5chain (shared code with Core).</summary>
    public const string IssuerKeyUnresolvable = "issuer_key_unresolvable";

    /// <summary>The issuer does not chain to a configured trust anchor (shared code with Core).</summary>
    public const string IssuerUntrusted = "issuer_untrusted";

    /// <summary>The MSO validity window has passed (shared code with Core).</summary>
    public const string CredentialExpired = "credential_expired";

    /// <summary>The MSO validity window has not started (shared code with Core).</summary>
    public const string CredentialNotYetValid = "credential_not_yet_valid";

    /// <summary>A disclosed item's digest does not appear in the MSO's valueDigests.</summary>
    public const string DigestMismatch = "mdoc_digest_mismatch";

    /// <summary>The MSO is malformed or carries unsupported values.</summary>
    public const string MsoInvalid = "mdoc_mso_invalid";

    /// <summary>The document's docType does not match the requested doctype.</summary>
    public const string DocTypeMismatch = "mdoc_doctype_mismatch";

    /// <summary>The device signature over the session transcript does not verify.</summary>
    public const string DeviceAuthInvalid = "mdoc_device_auth_invalid";
}
