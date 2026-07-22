namespace Tessio.Verifier.Core;

/// <summary>
/// Stable machine-readable error codes carried in <see cref="VerificationError.Code"/>.
/// Codes are part of the observable behavior (log/metric grouping) — treat as append-only.
/// Public so application logic can branch on codes without magic strings.
/// </summary>
public static class ErrorCodes
{
    public const string FormatUnsupported = "format_unsupported";
    public const string StructureInvalid = "structure_invalid";
    public const string TypInvalid = "typ_invalid";
    public const string AlgorithmNotAllowed = "algorithm_not_allowed";
    public const string SignatureInvalid = "signature_invalid";
    public const string IssuerKeyUnresolvable = "issuer_key_unresolvable";
    public const string IssuerMetadataInvalid = "issuer_metadata_invalid";
    public const string IssuerCertificateMismatch = "issuer_certificate_mismatch";
    public const string SdAlgUnsupported = "sd_alg_unsupported";
    public const string DisclosureInvalid = "disclosure_invalid";
    public const string DisclosureUnreferenced = "disclosure_unreferenced";
    public const string DigestDuplicated = "digest_duplicated";
    public const string ClaimNameReserved = "claim_name_reserved";
    public const string ClaimNameDuplicated = "claim_name_duplicated";
    public const string ClaimNotDisclosable = "claim_not_disclosable";
    public const string VctMissing = "vct_missing";
    public const string VctMismatch = "vct_mismatch";
    public const string CredentialExpired = "credential_expired";
    public const string CredentialNotYetValid = "credential_not_yet_valid";
    public const string KeyBindingMissing = "key_binding_missing";
    public const string KeyBindingInvalid = "key_binding_invalid";
    public const string NonceMismatch = "nonce_mismatch";
    public const string AudienceMismatch = "audience_mismatch";
    public const string SdHashMismatch = "sd_hash_mismatch";
    public const string ConfirmationKeyMissing = "confirmation_key_missing";
    public const string IssuerUntrusted = "issuer_untrusted";
    public const string StatusInvalid = "status_invalid";
    public const string StatusUnresolvable = "status_unresolvable";
    public const string CredentialRevoked = "credential_revoked";
    public const string CredentialSuspended = "credential_suspended";
    public const string CredentialStatusUnknown = "credential_status_unknown";
}
