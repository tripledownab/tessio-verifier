namespace Tessio.Verifier.Core;

/// <summary>Policy knobs for <see cref="SdJwtVcVerifier"/>.</summary>
public sealed class SdJwtVcVerifierOptions
{
    /// <summary>
    /// Whether a Key Binding JWT is required. Defaults to true — HAIP-profile EUDI presentations are
    /// holder-bound. When false, a KB-JWT is still verified if present.
    /// </summary>
    public bool RequireKeyBinding { get; set; } = true;

    /// <summary>
    /// Accepts the legacy <c>vc+sd-jwt</c> typ (pre-Nov-2024 credentials) in addition to the
    /// standard <c>dc+sd-jwt</c>. Off by default.
    /// </summary>
    // SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.1 — typ MUST be dc+sd-jwt; legacy readable behind this flag only.
    public bool AcceptLegacyVcSdJwtTyp { get; set; }

    /// <summary>
    /// Tolerated clock skew for <c>exp</c> / <c>nbf</c> evaluation. Defaults to 5 minutes
    /// (the Microsoft.IdentityModel ecosystem default).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether to resolve and enforce the credential's <c>status</c> claim (Token Status List) when
    /// present. Defaults to true — a revoked or suspended credential fails verification. Turn off
    /// only for offline scenarios where the status host is unreachable by design.
    /// </summary>
    // SPEC: draft-ietf-oauth-status-list §8.3 — Relying Parties validate the referenced status.
    public bool CheckStatus { get; set; } = true;
}
