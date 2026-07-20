using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// Verifies SD-JWT VC credentials (<c>dc+sd-jwt</c>): issuer signature (JWT VC Issuer Metadata or
/// X.509 <c>x5c</c> key resolution), selective-disclosure reconstruction, Key Binding, time claims,
/// and issuer trust via <see cref="ITrustListResolver"/>.
/// </summary>
/// <remarks>
/// Structural violations (malformed credential, failed signature, RFC 9901 MUST-reject rules) yield a
/// single-error invalid result; policy failures (expiry, nonce/audience, trust, vct) are accumulated
/// so callers see every problem at once. All cryptography is delegated to
/// Microsoft.IdentityModel and <c>System.Security.Cryptography</c> — nothing custom.
/// </remarks>
public sealed class SdJwtVcVerifier : ICredentialVerifier
{
    private static readonly HttpClient DefaultHttpClient = new();

    private readonly ITrustListResolver _trustListResolver;
    private readonly SdJwtVcVerifierOptions _options;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly TimeProvider _clock;

    /// <summary>Creates a verifier.</summary>
    /// <param name="trustListResolver">Trust seam deciding whether the issuer is trusted.</param>
    /// <param name="options">Policy options; defaults are HAIP-aligned.</param>
    /// <param name="httpClient">HTTP client for JWT VC Issuer Metadata resolution; a shared default is used when null.</param>
    /// <param name="clock">Time source for exp/nbf evaluation; system clock when null.</param>
    public SdJwtVcVerifier(
        ITrustListResolver trustListResolver,
        SdJwtVcVerifierOptions? options = null,
        HttpClient? httpClient = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(trustListResolver);
        _trustListResolver = trustListResolver;
        _options = options ?? new SdJwtVcVerifierOptions();
        _keyResolver = new IssuerKeyResolver(httpClient ?? DefaultHttpClient);
        _clock = clock ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<VerificationResult> VerifyAsync(
        PresentedCredential credential,
        VerificationContext context,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            return await VerifyCoreAsync(credential, context, ct).ConfigureAwait(false);
        }
        catch (SdJwtProcessingException e)
        {
            return Invalid(e.ToError());
        }
    }

    private async Task<VerificationResult> VerifyCoreAsync(
        PresentedCredential credential,
        VerificationContext context,
        CancellationToken ct)
    {
        // 1. Format identifier. SPEC: OpenID4VP/SD-JWT VC format is "dc+sd-jwt" (not "vc+sd-jwt").
        var formatOk = credential.Format == SdJwtConstants.Typ
                       || (_options.AcceptLegacyVcSdJwtTyp && credential.Format == SdJwtConstants.LegacyTyp);
        if (!formatOk)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.FormatUnsupported, $"Unsupported credential format '{credential.Format}'; expected '{SdJwtConstants.Typ}'.");
        }

        // 2. Compact-serialization structure.
        if (!SdJwtPresentation.TryParse(credential.RawValue, out var presentation))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.StructureInvalid, "The credential is not a valid SD-JWT compact serialization (<jwt>~<disclosures…>~[kb-jwt]).");
        }

        JsonWebToken issuerJwt;
        try
        {
            issuerJwt = new JsonWebToken(presentation.IssuerJwt);
        }
        catch (ArgumentException)
        {
            throw new SdJwtProcessingException(ErrorCodes.StructureInvalid, "The issuer-signed JWT is malformed.");
        }

        // 3. typ header. SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.1.
        var typOk = string.Equals(issuerJwt.Typ, SdJwtConstants.Typ, StringComparison.Ordinal)
                    || (_options.AcceptLegacyVcSdJwtTyp
                        && string.Equals(issuerJwt.Typ, SdJwtConstants.LegacyTyp, StringComparison.Ordinal));
        if (!typOk)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.TypInvalid, $"Issuer JWT typ is '{issuerJwt.Typ}'; expected '{SdJwtConstants.Typ}'.");
        }

        // 4. Algorithm allowlist (asymmetric only; rejects "none" and HMAC outright).
        if (!SdJwtConstants.AllowedAlgorithms.Contains(issuerJwt.Alg))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.AlgorithmNotAllowed, $"Issuer JWT algorithm '{issuerJwt.Alg}' is not permitted.");
        }

        // 5. Issuer key resolution (x5c or JWT VC Issuer Metadata).
        var resolution = await _keyResolver.ResolveAsync(issuerJwt, ct).ConfigureAwait(false);

        // 6. Issuer signature.
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(presentation.IssuerJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            IssuerSigningKeys = resolution.Keys,
            TryAllIssuerSigningKeys = true,
        }).ConfigureAwait(false);

        if (!validation.IsValid)
        {
            return Invalid(
                new VerificationError { Code = ErrorCodes.SignatureInvalid, Message = "The issuer signature does not verify against the resolved key." },
                new IssuerInfo { Identifier = resolution.Issuer, Trusted = false, KeyResolutionMethod = resolution.Method });
        }

        // 7. Payload reconstruction per RFC 9901 §7.1 (throws on MUST-reject violations).
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(issuerJwt.EncodedPayload))!;
        var vctIsPlain = payload.ContainsKey("vct");
        var processed = DisclosureProcessor.Process(payload, presentation.Disclosures);

        // 8. Policy checks — accumulated so the caller sees every failure at once.
        var errors = new List<VerificationError>();
        CheckVct(processed, vctIsPlain, context, errors);
        CheckTimeClaims(processed, errors);
        await CheckKeyBindingAsync(presentation, processed, context, errors, ct).ConfigureAwait(false);

        // 9. Issuer trust via the pluggable trust seam.
        var trust = await _trustListResolver.ResolveAsync(resolution.Issuer, resolution.CertificateChain, ct).ConfigureAwait(false);
        if (!trust.Trusted)
        {
            errors.Add(new VerificationError
            {
                Code = ErrorCodes.IssuerUntrusted,
                Message = trust.Reason ?? $"Issuer '{resolution.Issuer}' does not chain to a trusted list.",
            });
        }

        var issuerInfo = new IssuerInfo
        {
            Identifier = resolution.Issuer,
            Trusted = trust.Trusted,
            KeyResolutionMethod = resolution.Method,
        };

        return errors.Count > 0
            ? Invalid(errors, issuerInfo)
            : new VerificationResult
            {
                IsValid = true,
                DisclosedClaims = ExtractClaims(processed),
                Issuer = issuerInfo,
                Errors = [],
            };
    }

    private static void CheckVct(JsonObject processed, bool vctIsPlain, VerificationContext context, List<VerificationError> errors)
    {
        // SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.2.1 — vct is REQUIRED and must not be selectively disclosed.
        var vct = processed.TryGetPropertyValue("vct", out var vctNode) && vctNode?.GetValueKind() == JsonValueKind.String
            ? vctNode.GetValue<string>()
            : null;

        if (vct is null || !vctIsPlain)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.VctMissing, Message = "The credential carries no plain vct claim." });
            return;
        }

        if (context.ExpectedVct is not null && !string.Equals(vct, context.ExpectedVct, StringComparison.Ordinal))
        {
            errors.Add(new VerificationError
            {
                Code = ErrorCodes.VctMismatch,
                Message = $"The credential type is '{vct}'; this verification expects '{context.ExpectedVct}'.",
            });
        }
    }

    private void CheckTimeClaims(JsonObject processed, List<VerificationError> errors)
    {
        var now = _clock.GetUtcNow();

        if (ReadUnixTime(processed, "exp") is { } exp && now - _options.ClockSkew >= exp)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.CredentialExpired, Message = $"The credential expired at {exp:O}." });
        }

        if (ReadUnixTime(processed, "nbf") is { } nbf && now + _options.ClockSkew < nbf)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.CredentialNotYetValid, Message = $"The credential is not valid before {nbf:O}." });
        }
    }

    private async Task CheckKeyBindingAsync(
        SdJwtPresentation presentation,
        JsonObject processed,
        VerificationContext context,
        List<VerificationError> errors,
        CancellationToken ct)
    {
        if (presentation.KbJwt is null)
        {
            if (_options.RequireKeyBinding)
            {
                errors.Add(new VerificationError
                {
                    Code = ErrorCodes.KeyBindingMissing,
                    Message = "The presentation carries no KB-JWT, but key binding is required.",
                });
            }

            return;
        }

        // SPEC: RFC 9901 §4.1.2 / §7.3 — the holder key comes from the credential's cnf claim (jwk).
        var jwkNode = processed.TryGetPropertyValue("cnf", out var cnfNode) && cnfNode is JsonObject cnf
            ? cnf.TryGetPropertyValue("jwk", out var jwk) ? jwk as JsonObject : null
            : null;

        if (jwkNode is null)
        {
            errors.Add(new VerificationError
            {
                Code = ErrorCodes.ConfirmationKeyMissing,
                Message = "A KB-JWT was presented but the credential carries no cnf.jwk holder key.",
            });
            return;
        }

        SecurityKey holderKey;
        try
        {
            holderKey = new JsonWebKey(jwkNode.ToJsonString());
        }
        catch (ArgumentException)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.ConfirmationKeyMissing, Message = "The credential's cnf.jwk is not a valid JWK." });
            return;
        }

        errors.AddRange(await KeyBindingVerifier.VerifyAsync(
            presentation.KbJwt, holderKey, context, presentation.PresentationWithoutKbJwt, ct).ConfigureAwait(false));
    }

    private static Dictionary<string, object> ExtractClaims(JsonObject processed)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var property in processed)
        {
            if (!SdJwtConstants.NonClaimKeys.Contains(property.Key))
            {
                claims[property.Key] = JsonValueConverter.ToClrValue(property.Value)!;
            }
        }

        return claims;
    }

    private static DateTimeOffset? ReadUnixTime(JsonObject payload, string claim)
    {
        if (!payload.TryGetPropertyValue(claim, out var node) || node?.GetValueKind() != JsonValueKind.Number)
        {
            return null;
        }

        var element = node.GetValue<JsonElement>();
        return element.TryGetInt64(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : DateTimeOffset.FromUnixTimeSeconds((long)element.GetDouble());
    }

    private static VerificationResult Invalid(VerificationError error, IssuerInfo? issuer = null) =>
        Invalid([error], issuer);

    private static VerificationResult Invalid(IReadOnlyList<VerificationError> errors, IssuerInfo? issuer = null) => new()
    {
        IsValid = false,
        DisclosedClaims = new Dictionary<string, object>(),
        Issuer = issuer ?? new IssuerInfo { Identifier = "unknown", Trusted = false, KeyResolutionMethod = "none" },
        Errors = errors,
    };
}
