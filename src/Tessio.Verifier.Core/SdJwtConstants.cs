namespace Tessio.Verifier.Core;

/// <summary>Wire-format constants for SD-JWT VC verification.</summary>
internal static class SdJwtConstants
{
    // SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.1 — the JOSE typ MUST be "dc+sd-jwt"
    // (changed from the legacy "vc+sd-jwt" in Nov 2024 to avoid a W3C media-type conflict).
    public const string Typ = "dc+sd-jwt";
    public const string LegacyTyp = "vc+sd-jwt";

    // SPEC: RFC 9901 (SD-JWT) §4.3 — the Key Binding JWT typ MUST be "kb+jwt".
    public const string KbJwtTyp = "kb+jwt";

    // SPEC: RFC 9901 §4.1.1 — default hash algorithm when _sd_alg is absent.
    public const string DefaultSdAlg = "sha-256";

    public const char Separator = '~';

    public const string SdClaim = "_sd";
    public const string SdAlgClaim = "_sd_alg";
    public const string ArrayDigestKey = "...";

    public const string KeyResolutionMetadata = "jwt-vc-issuer-metadata";
    public const string KeyResolutionX5c = "x5c";

    // SPEC: draft-ietf-oauth-sd-jwt-vc §3 — well-known segment inserted between host and path of iss.
    public const string WellKnownSegment = "/.well-known/jwt-vc-issuer";

    /// <summary>
    /// Claims that MUST NOT be selectively disclosable at the top level of an SD-JWT VC.
    /// </summary>
    // SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.2.2 — iss, nbf, exp, cnf, vct, vct#integrity, status.
    public static readonly IReadOnlySet<string> NeverSelectivelyDisclosable = new HashSet<string>(StringComparer.Ordinal)
    {
        "iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status",
    };

    /// <summary>
    /// Registered/structural claims excluded from <c>VerificationResult.DisclosedClaims</c>.
    /// Everything else — selectively disclosed or plainly visible — is surfaced to the caller.
    /// </summary>
    public static readonly IReadOnlySet<string> NonClaimKeys = new HashSet<string>(StringComparer.Ordinal)
    {
        "iss", "iat", "nbf", "exp", "cnf", "vct", "vct#integrity", "status", "aud", "jti",
        SdClaim, SdAlgClaim,
    };

    /// <summary>
    /// Permitted JWS algorithms for the issuer signature and the KB-JWT — asymmetric only.
    /// </summary>
    // SPEC: HAIP constrains EUDI credentials to ES256; the broader list keeps the verifier usable
    // against other conformant ecosystems. "none" and all HMAC algorithms are rejected outright.
    public static readonly IReadOnlySet<string> AllowedAlgorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256",
    };
}
