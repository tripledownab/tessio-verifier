using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Verifies the Key Binding JWT (KB-JWT) of an SD-JWT presentation: typ, signature against the
/// holder's <c>cnf</c> key, audience, nonce, and the <c>sd_hash</c> binding to the presented credential.
/// </summary>
// SPEC: RFC 9901 §4.3 (KB-JWT requirements) and §4.3.1 (sd_hash computation).
internal static class KeyBindingVerifier
{
    public static async Task<List<VerificationError>> VerifyAsync(
        string kbJwt,
        SecurityKey holderKey,
        VerificationContext context,
        string presentationWithoutKbJwt,
        CancellationToken ct)
    {
        var errors = new List<VerificationError>();

        JsonWebToken token;
        try
        {
            token = new JsonWebToken(kbJwt);
        }
        catch (ArgumentException)
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT is not a well-formed JWT."));
            return errors;
        }

        // SPEC: RFC 9901 §4.3 — typ MUST be "kb+jwt" and alg MUST NOT be "none".
        if (!string.Equals(token.Typ, SdJwtConstants.KbJwtTyp, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, $"KB-JWT typ is '{token.Typ}'; expected '{SdJwtConstants.KbJwtTyp}'."));
        }

        if (!SdJwtConstants.AllowedAlgorithms.Contains(token.Alg))
        {
            errors.Add(Error(ErrorCodes.AlgorithmNotAllowed, $"KB-JWT algorithm '{token.Alg}' is not permitted."));
            return errors; // Do not attempt signature validation with a forbidden algorithm.
        }

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(kbJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            IssuerSigningKey = holderKey,
        }).ConfigureAwait(false);

        if (!validation.IsValid)
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT signature does not verify against the credential's cnf key."));
            return errors;
        }

        // SPEC: RFC 9901 §4.3 — aud, nonce, and iat are REQUIRED; nonce/aud bind the presentation
        // to this verifier's challenge (replay protection).
        if (!token.Audiences.Contains(context.Audience, StringComparer.Ordinal))
        {
            errors.Add(Error(ErrorCodes.AudienceMismatch, "The KB-JWT aud does not match this verifier."));
        }

        var nonce = token.TryGetClaim("nonce", out var nonceClaim) ? nonceClaim.Value : null;
        if (!string.Equals(nonce, context.Nonce, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.NonceMismatch, "The KB-JWT nonce does not match the challenge issued for this session."));
        }

        if (!token.TryGetClaim("iat", out _))
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT is missing the required iat claim."));
        }

        // SPEC: RFC 9901 §4.3.1 — sd_hash = base64url(sha-256(US-ASCII(<presentation without KB-JWT>))),
        // using the credential's _sd_alg hash (sha-256 enforced earlier in the pipeline).
        var expectedSdHash = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(presentationWithoutKbJwt)));
        var sdHash = token.TryGetClaim("sd_hash", out var sdHashClaim) ? sdHashClaim.Value : null;
        if (!string.Equals(sdHash, expectedSdHash, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.SdHashMismatch, "The KB-JWT sd_hash does not match the presented credential and disclosures."));
        }

        return errors;
    }

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
