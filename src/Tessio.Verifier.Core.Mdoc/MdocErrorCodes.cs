namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Stable error codes for mdoc verification failures, alongside the shared codes in
/// <see cref="ErrorCodes"/> (structure_invalid, signature_invalid, issuer_untrusted, …).
/// </summary>
public static class MdocErrorCodes
{
    /// <summary>Malformed base64url, CBOR or a missing required element (shared code with Core).</summary>
    public const string StructureInvalid = "structure_invalid";

    /// <summary>A disclosed item's digest does not appear in the MSO's valueDigests.</summary>
    public const string DigestMismatch = "mdoc_digest_mismatch";

    /// <summary>The MSO is malformed or carries unsupported values.</summary>
    public const string MsoInvalid = "mdoc_mso_invalid";

    /// <summary>The document's docType does not match the requested doctype.</summary>
    public const string DocTypeMismatch = "mdoc_doctype_mismatch";

    /// <summary>The device signature over the session transcript does not verify.</summary>
    public const string DeviceAuthInvalid = "mdoc_device_auth_invalid";
}
