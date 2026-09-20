using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// Resolves and enforces a credential's <c>status</c> claim against a Token Status List: fetches the
/// status list token, validates it (typ, signature, sub↔uri binding, signer trust, expiry),
/// decompresses the bitstring, and maps the referenced index to a verification outcome. The signer is
/// judged by the same <see cref="ITrustListResolver"/> as the credential's own issuer, because the
/// Status Issuer may be a party the issuer authorised rather than the issuer itself. Validated lists are cached
/// per uri for min(cache duration, the token's <c>ttl</c> claim, its <c>exp</c>); failures are
/// never cached, so an unresolvable status stays fail-closed on every attempt.
/// </summary>
// SPEC: draft-ietf-oauth-status-list-18 — §6.2 (status claim), §5.1 (status list token in JWT
// format), §8.3 (Relying Party validation rules), §4.1/§4.2 (bit packing and compression),
// §11.2 (ttl-driven caching).
internal sealed class StatusListChecker
{
    private const string StatusListTyp = "statuslist+jwt";

    /// <summary>A validated, decompressed status list, keyed by the uri it was fetched from.</summary>
    /// <remarks>
    /// It carries NO credential issuer. What validation established is that this token is authentic,
    /// anchors on a configured anchor, and names this uri in its <c>sub</c>. None of those depend on
    /// which credential pointed here, and the index being read comes from the credential rather than
    /// from the cache. Keeping an issuer here while keying the dictionary on the uri alone also made
    /// the cache useless the moment a Status Issuer served one list for several credential issuers:
    /// each one missed the other's entry and then overwrote it, so every check re-fetched.
    /// </remarks>
    private sealed record CachedList(int Bits, byte[] List, DateTimeOffset Until);

    private readonly ConcurrentDictionary<string, CachedList> _cache = new(StringComparer.Ordinal);
    private readonly HttpClient _httpClient;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly ITrustListResolver _trustListResolver;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _clockSkew;
    private readonly TimeSpan _cacheDuration;

    public StatusListChecker(
        HttpClient httpClient,
        IssuerKeyResolver keyResolver,
        ITrustListResolver trustListResolver,
        TimeProvider clock,
        TimeSpan clockSkew,
        TimeSpan cacheDuration)
    {
        _httpClient = httpClient;
        _keyResolver = keyResolver;
        _trustListResolver = trustListResolver;
        _clock = clock;
        _clockSkew = clockSkew;
        _cacheDuration = cacheDuration;
    }

    /// <summary>
    /// Checks the credential's status when a <c>status</c> claim is present. Returns accumulated
    /// policy errors; an empty list means valid (or no status claim to check).
    /// </summary>
    /// <param name="payload">The processed credential payload.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <remarks>
    /// It deliberately takes NO credential issuer. Nothing here is decided by who issued the
    /// credential: the issuer's say in which list speaks for it is the uri inside the credential it
    /// signed, and the rest is the token's own authenticity. The parameter that used to be here fed a
    /// same-issuer comparison that has been removed.
    /// <para>
    /// Trust here is per SIGNER, not per purpose, because that is what
    /// <see cref="ITrustListResolver"/> answers. So configure anchors on the understanding that one
    /// entry covers every question this library asks about that party, status signing included, and
    /// scope the trust list to signers the deployment means to accept for all of them. Where an
    /// ecosystem publishes issuance and revocation anchors separately, keep that separation by giving
    /// the resolver only what belongs to the deployment's own purpose.
    /// </para>
    /// </remarks>
    public async Task<List<VerificationError>> CheckAsync(JsonObject payload, CancellationToken ct)
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

        // HTTPS, which is the bar JWT VC Issuer Metadata resolution already holds in IssuerKeyResolver.
        // A status list says whether a credential is still valid, so fetching one in clear lets anyone
        // on the path answer that question. SPEC: draft-ietf-oauth-status-list section 11.4 on the fetch.
        //
        // Checked BEFORE the cache, so a cleartext uri cannot be answered from a previously cached list
        // either, and checked here rather than left to the handler, because the failure it prevents is
        // silent: an http:// list is retrieved perfectly well and the answer is whatever the network said.
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var statusUri) || statusUri.Scheme != Uri.UriSchemeHttps)
        {
            return [Error(ErrorCodes.StatusInvalid, $"The status list uri '{uri}' is not an HTTPS URI.")];
        }

        if (_cache.TryGetValue(uri, out var cached) && cached.Until > _clock.GetUtcNow())
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

        return await ValidateStatusListTokenAsync(statusListJwt, uri, idx, ct).ConfigureAwait(false);
    }

    private async Task<List<VerificationError>> ValidateStatusListTokenAsync(
        string statusListJwt, string uri, long idx, CancellationToken ct)
    {
        if (!CompactJwt.TryParse(statusListJwt, out var token))
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

        IssuerKeyResolution resolution;
        try
        {
            resolution = await _keyResolver.ResolveAsync(token, ct).ConfigureAwait(false);
        }
        catch (SdJwtProcessingException e)
        {
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's key could not be resolved: {e.Message}")];
        }

        // Two things make a status list token ours to believe, and neither is its issuer identifier.
        // BINDING is the sub check below: sub MUST equal the uri, and that uri rides inside the
        // ISSUER-SIGNED credential, so the issuer chose which list speaks for it. AUTHENTICITY is this
        // call: the token's own chain goes through the same trust seam as the credential's, so a
        // self-signed token served from that uri does not anchor and is refused.
        //
        // WHAT THE SPECIFICATIONS REQUIRE, and the normative weight of each.
        //
        // draft-ietf-oauth-status-list section 8.3 is the Relying Party's MUST list. Signer identity is
        // not on it. The only binding it requires to the referenced token is "The subject claim (sub or
        // 2) of the Status List Token MUST be equal to the uri claim in the status_list object".
        //
        // Section 5.1 does not define iss for this token at all, so omitting it is conformant. The
        // sentence that the Status Issuer "can be either the Issuer or an entity that has been
        // authorized by the Issuer" is section 1, the Introduction: narrative, not a requirement. The
        // working group DELETED the rule this code used to enforce, per the changelog at -04, "remove
        // requirement for matching iss claim in Referenced Token and Status List Token".
        //
        // The NORMATIVE requirement for this call is HAIP 1.0 Final section 6.1, which CONTRIBUTING.md
        // makes authoritative where the IETF drafts are ambiguous: the status token's verifying key
        // "MUST be included in the x5c JOSE header", its trust anchor "MUST NOT be included", and it
        // "MUST NOT be self-signed". That mandates anchoring the token's own chain and nowhere says the
        // anchor is the credential's. EUDI ARF section 6.3.2.4 says the same in the other direction: the
        // two anchor sets "may be the same. However, they also may be different", because revocation can
        // be outsourced.
        //
        // THIS REPLACED an equality check against the credential's issuer, labelled "defense in depth
        // beyond the spec". That check stopped an honest third-party Status Issuer and stopped no
        // attacker: it compared resolution.Issuer, which is iss ?? leaf.Subject and therefore chosen by
        // whoever serves the token, against a credential value that same party can read. Nothing
        // anchored the token's chain, so a self-signed certificate satisfied it.
        //
        // It was also UNSATISFIABLE, but only on one path, and the qualifier matters: when the
        // credential's issuer is an HTTPS URI and the status token omits iss, a subject DN is compared
        // to a URI. Where both resolve to DNs it could pass. Found 2026-09-20 against the EUDI Wallet
        // Reference Implementation, whose lists are served by another host under another CA with no iss.
        IssuerTrustStatus trust;
        try
        {
            trust = await _trustListResolver.ResolveAsync(resolution.Issuer, resolution.CertificateChain, ct)
                .ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            // A trust seam may do network I/O (a LOTL-backed resolver does). VerifyAsync promises it
            // "never throws on input", and it catches only three types, so an escaping resolver failure
            // would break that promise from inside a status check. Fail closed and name the cause.
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's trust could not be resolved: {e.Message}")];
        }

        if (!trust.Trusted)
        {
            return
            [
                Error(
                    ErrorCodes.StatusInvalid,
                    trust.Reason is null
                        ? $"The status list token's signer '{resolution.Issuer}' is not trusted."
                        : $"The status list token's signer is not trusted: {trust.Reason}"),
            ];
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

        CacheList(token, uri, bits, decompressed, expiresAt);
        return EvaluateIndex(bits, decompressed, idx);
    }

    /// <summary>
    /// Caches the validated, decompressed list. Lifetime is the configured cache duration, shortened
    /// by the token's <c>ttl</c> claim (the issuer's cache ceiling, SPEC §11.2) and capped by its
    /// <c>exp</c>. A non-positive lifetime disables caching for this list.
    /// </summary>
    private void CacheList(
        JsonWebToken token, string uri, int bits, byte[] list, DateTimeOffset? expiresAt)
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

        _cache[uri] = new CachedList(bits, list, until);
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
