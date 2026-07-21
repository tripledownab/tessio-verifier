using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Resolves and enforces a credential's <c>status</c> claim against a Token Status List: fetches the
/// status list token, validates it (typ, signature, sub↔uri binding, expiry), decompresses the
/// bitstring, and maps the referenced index to a verification outcome. Validated lists are cached
/// per uri for min(cache duration, the token's <c>ttl</c> claim, its <c>exp</c>); failures are
/// never cached, so an unresolvable status stays fail-closed on every attempt.
/// </summary>
// SPEC: draft-ietf-oauth-status-list-18 — §6.2 (status claim), §5.1 (status list token in JWT
// format), §8.3 (Relying Party validation rules), §4.1/§4.2 (bit packing and compression),
// §11.2 (ttl-driven caching).
internal sealed class StatusListChecker
{
    private const string StatusListTyp = "statuslist+jwt";

    private sealed record CachedList(int Bits, byte[] List, string Issuer, DateTimeOffset Until);

    private readonly ConcurrentDictionary<string, CachedList> _cache = new(StringComparer.Ordinal);
    private readonly HttpClient _httpClient;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _clockSkew;
    private readonly TimeSpan _cacheDuration;

    public StatusListChecker(
        HttpClient httpClient, IssuerKeyResolver keyResolver, TimeProvider clock, TimeSpan clockSkew, TimeSpan cacheDuration)
    {
        _httpClient = httpClient;
        _keyResolver = keyResolver;
        _clock = clock;
        _clockSkew = clockSkew;
        _cacheDuration = cacheDuration;
    }

    /// <summary>
    /// Checks the credential's status when a <c>status</c> claim is present. Returns accumulated
    /// policy errors; an empty list means valid (or no status claim to check).
    /// </summary>
    /// <param name="payload">The processed credential payload.</param>
    /// <param name="credentialIssuer">The verified credential issuer identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<List<VerificationError>> CheckAsync(JsonObject payload, string credentialIssuer, CancellationToken ct)
    {
        if (!payload.TryGetPropertyValue("status", out var statusNode))
        {
            return [];
        }

        // SPEC: §6.2 — "status": {"status_list": {"idx": <non-negative int>, "uri": <string>}}.
        var statusList = statusNode is JsonObject statusObj
                         && statusObj.TryGetPropertyValue("status_list", out var listNode)
            ? listNode as JsonObject
            : null;
        var idx = statusList?.TryGetPropertyValue("idx", out var idxNode) == true
                  && idxNode?.GetValueKind() == JsonValueKind.Number
            ? idxNode.GetValue<long>()
            : -1;
        var uri = statusList?.TryGetPropertyValue("uri", out var uriNode) == true
                  && uriNode?.GetValueKind() == JsonValueKind.String
            ? uriNode.GetValue<string>()
            : null;

        if (idx < 0 || uri is null)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status claim carries no valid status_list.idx/uri.")];
        }

        if (_cache.TryGetValue(uri, out var cached)
            && cached.Until > _clock.GetUtcNow()
            && string.Equals(cached.Issuer, credentialIssuer, StringComparison.Ordinal))
        {
            return EvaluateIndex(cached.Bits, cached.List, idx);
        }

        string statusListJwt;
        try
        {
            // SPEC: §8.1 — request the JWT representation.
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/statuslist+jwt");
            using var response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            statusListJwt = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException or UriFormatException)
        {
            // Fail closed: an unreachable status list means the revocation state is unknown.
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list at '{uri}' could not be retrieved: {e.Message}")];
        }

        return await ValidateStatusListTokenAsync(statusListJwt, uri, idx, credentialIssuer, ct).ConfigureAwait(false);
    }

    private async Task<List<VerificationError>> ValidateStatusListTokenAsync(
        string statusListJwt, string uri, long idx, string credentialIssuer, CancellationToken ct)
    {
        JsonWebToken token;
        try
        {
            token = new JsonWebToken(statusListJwt);
        }
        catch (ArgumentException)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list response is not a well-formed JWT.")];
        }

        // SPEC: §5.1 — typ MUST be statuslist+jwt.
        if (!string.Equals(token.Typ, StatusListTyp, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status list token typ is '{token.Typ}'; expected '{StatusListTyp}'.")];
        }

        if (!SdJwtConstants.AllowedAlgorithms.Contains(token.Alg))
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status list token algorithm '{token.Alg}' is not permitted.")];
        }

        // Defense in depth beyond the spec: the status list URI is chosen by the credential issuer
        // (it rides inside the issuer-signed credential), so a status list token signed by any other
        // issuer indicates a compromised status host. EUDI deployments use same-issuer status lists.
        IssuerKeyResolution resolution;
        try
        {
            resolution = await _keyResolver.ResolveAsync(token, ct).ConfigureAwait(false);
        }
        catch (SdJwtProcessingException e)
        {
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's key could not be resolved: {e.Message}")];
        }

        if (!string.Equals(resolution.Issuer, credentialIssuer, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token is not issued by the credential's issuer.")];
        }

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(statusListJwt, new TokenValidationParameters
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
            return [Error(ErrorCodes.StatusInvalid, "The status list token signature does not verify.")];
        }

        // SPEC: §8.3 — sub MUST equal the uri referenced by the credential.
        if (!token.TryGetClaim("sub", out var subClaim) || !string.Equals(subClaim.Value, uri, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token sub does not match the referenced uri.")];
        }

        // SPEC: §8.3 — when exp is present, an expired status list token MUST be rejected.
        DateTimeOffset? expiresAt = null;
        if (token.TryGetClaim("exp", out var expClaim)
            && long.TryParse(expClaim.Value, System.Globalization.CultureInfo.InvariantCulture, out var expSeconds))
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            if (_clock.GetUtcNow() - _clockSkew >= expiresAt)
            {
                return [Error(ErrorCodes.StatusUnresolvable, "The status list token is expired; current status is unknown.")];
            }
        }

        // SPEC: §4.2 — status_list: { "bits": 1|2|4|8, "lst": base64url(zlib-deflate(bytes)) }.
        using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedPayload));
        if (!payloadDoc.RootElement.TryGetProperty("status_list", out var statusListProp)
            || !statusListProp.TryGetProperty("bits", out var bitsProp)
            || !statusListProp.TryGetProperty("lst", out var lstProp)
            || !bitsProp.TryGetInt32(out var bits)
            || bits is not (1 or 2 or 4 or 8)
            || lstProp.ValueKind != JsonValueKind.String)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token carries no valid status_list claim.")];
        }

        byte[] decompressed;
        try
        {
            using var compressed = new MemoryStream(Base64UrlEncoder.DecodeBytes(lstProp.GetString()!));
            using var zlib = new ZLibStream(compressed, CompressionMode.Decompress);
            using var output = new MemoryStream();
            zlib.CopyTo(output);
            decompressed = output.ToArray();
        }
        catch (Exception e) when (e is InvalidDataException or FormatException)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list bitstring could not be decompressed.")];
        }

        CacheList(token, uri, credentialIssuer, bits, decompressed, expiresAt);
        return EvaluateIndex(bits, decompressed, idx);
    }

    /// <summary>
    /// Caches the validated, decompressed list. Lifetime is the configured cache duration, shortened
    /// by the token's <c>ttl</c> claim (the issuer's cache ceiling, SPEC §11.2) and capped by its
    /// <c>exp</c>. A non-positive lifetime disables caching for this list.
    /// </summary>
    private void CacheList(
        JsonWebToken token, string uri, string credentialIssuer, int bits, byte[] list, DateTimeOffset? expiresAt)
    {
        var lifetime = _cacheDuration;
        if (token.TryGetClaim("ttl", out var ttlClaim)
            && long.TryParse(ttlClaim.Value, System.Globalization.CultureInfo.InvariantCulture, out var ttlSeconds)
            && TimeSpan.FromSeconds(ttlSeconds) < lifetime)
        {
            lifetime = TimeSpan.FromSeconds(ttlSeconds);
        }

        var now = _clock.GetUtcNow();
        var until = now + lifetime;
        if (expiresAt is { } exp && exp < until)
        {
            until = exp;
        }

        if (until <= now)
        {
            return;
        }

        // Opportunistic eviction keeps the cache bounded to live lists (one entry per status uri).
        foreach (var (key, entry) in _cache)
        {
            if (entry.Until <= now)
            {
                _cache.TryRemove(key, out _);
            }
        }

        _cache[uri] = new CachedList(bits, list, credentialIssuer, until);
    }

    private static List<VerificationError> EvaluateIndex(int bits, byte[] list, long idx)
    {
        // SPEC: §4.1 — blocks are packed into bytes starting at the least significant bit.
        var byteIndex = idx * bits / 8;
        if (byteIndex >= list.Length)
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status index {idx} is outside the status list.")];
        }

        var shift = (int)(idx * bits % 8);
        var value = (list[byteIndex] >> shift) & ((1 << bits) - 1);

        // SPEC: §7.1 — registered status values.
        return value switch
        {
            0x00 => [],
            0x01 => [Error(ErrorCodes.CredentialRevoked, "The issuer has revoked this credential.")],
            0x02 => [Error(ErrorCodes.CredentialSuspended, "The issuer has suspended this credential.")],
            _ => [Error(ErrorCodes.CredentialStatusUnknown, $"The credential carries unrecognized status value 0x{value:X2}.")],
        };
    }

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
