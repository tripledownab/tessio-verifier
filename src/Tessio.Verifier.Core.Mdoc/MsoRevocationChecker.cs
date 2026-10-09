using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Enforces an mdoc's MSO <c>status</c> element: fetches each MSO revocation list it references, validates
/// the list's token and its trust for this credential, and maps the credential's entry to a verdict. Both
/// mechanisms are supported, the status list and the identifier list, because a relying party that checks
/// revocation at all must support both. A list is cached per uri once it has been trusted for some credential,
/// and its trust is decided again for every credential it answers: the cache holds what a list says, never
/// whom it may speak for. Failures are never cached, so an unresolvable list stays fail-closed on every attempt.
/// </summary>
// SPEC: Implementing Regulation (EU) 2024/2979, Annex II as replaced by Implementing Regulation (EU) 2026/1731
// (its Annex IV), adaptation (6), replacing clause 6.2.10.1 of ETSI TS 119 472-1 V1.2.1 ("EAA-6.2.10.1-NN"
// below). -05.1: a relying party verifying revocation "shall support both the attestation status list mechanism
// and the attestation revocation list mechanism". -07: the list is "a status list token in CWT format", per
// draft-ietf-oauth-status-list-20, the version the annex pins.
internal sealed class MsoRevocationChecker
{
    private sealed record ValidatedList(MsoRevocationListToken Token, byte[]? List);

    private readonly StatusListCache<ValidatedList> _cache = new();
    private readonly HttpClient _httpClient;
    private readonly ITrustListResolver _trustListResolver;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _clockSkew;
    private readonly TimeSpan _cacheDuration;

    public MsoRevocationChecker(
        HttpClient httpClient, ITrustListResolver trustListResolver, TimeProvider clock, TimeSpan clockSkew, TimeSpan cacheDuration)
    {
        _httpClient = httpClient;
        _trustListResolver = trustListResolver;
        _clock = clock;
        _clockSkew = clockSkew;
        _cacheDuration = cacheDuration;
    }

    /// <summary>
    /// The errors the MSO's <c>status</c> element produces; empty means not revoked. Call it only for a
    /// credential that has passed every other check: draft-ietf-oauth-status-list-20 section 8.3 says list
    /// procedures "MUST NOT be performed, e.g. fetching a Status List Token" for a credential already found
    /// invalid, unless the use case requires it, and this one does not.
    /// </summary>
    public async Task<List<VerificationError>> CheckAsync(
        byte[] statusEncoded, MsoRevocationTrust.Credential credential, CancellationToken ct)
    {
        var (references, problem) = MsoStatus.Read(statusEncoded);
        if (problem is not null)
        {
            return [Error(ErrorCodes.StatusInvalid, problem)];
        }

        List<VerificationError> errors = [];
        foreach (var reference in references)
        {
            errors.AddRange(await CheckOneAsync(reference, credential, ct).ConfigureAwait(false));
        }

        return errors;
    }

    private async Task<List<VerificationError>> CheckOneAsync(
        RevocationListReference reference, MsoRevocationTrust.Credential credential, CancellationToken ct)
    {
        // HTTPS, for the reason the SD-JWT VC status check gives: a list fetched in clear is whatever the
        // network says. Checked before the cache, so a cleartext uri is never answered from it either.
        if (!Uri.TryCreate(reference.Uri, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return [Error(ErrorCodes.StatusInvalid, $"The MSO revocation list uri '{reference.Uri}' is not an HTTPS URI.")];
        }

        var cacheKey = $"{reference.Kind}|{reference.Uri}";
        // A cached list not trusted for THIS credential is fetched afresh rather than refused: another credential's
        // list served at this uri once must not stand in for the one this credential's issuer publishes.
        if (_cache.Get(cacheKey, _clock.GetUtcNow()) is { } cached
            && await UntrustedAsync(cached, reference, credential, ct).ConfigureAwait(false) is null)
        {
            return Evaluate(cached, reference);
        }

        byte[] body;
        try
        {
            // SPEC: draft-ietf-oauth-status-list-20 section 8.2 and EAA-6.2.10.1-10.3, the media types.
            body = await OutboundFetch.GetBoundedAsync(
                _httpClient, uri, MsoRevocationListToken.TypeOf(reference.Kind), "MSO revocation list",
                OutboundFetch.MaxMsoRevocationListBytes, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException or UriFormatException)
        {
            // The caller's own cancellation propagates, even when it lands while a fetch is already failing: it
            // asks to stop, and is not an unreachable list.
            ct.ThrowIfCancellationRequested();
            // Fail closed: an unreachable list means the revocation state is unknown.
            return [Error(ErrorCodes.StatusUnresolvable, $"The MSO revocation list at '{reference.Uri}' could not be retrieved: {e.Message}")];
        }

        var (token, problem) = MsoRevocationListToken.Decode(body, reference.Kind);
        if (token is null)
        {
            return [Error(ErrorCodes.StatusInvalid, problem!)];
        }

        // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 4a, the subject MUST equal the referenced uri.
        if (!string.Equals(token.Subject, reference.Uri, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, "The MSO revocation list's sub does not match the uri the MSO references.")];
        }

        // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 4c, exp "MUST be checked", and section 13.7, an
        // expired list "MUST NOT be relied upon any longer".
        var now = _clock.GetUtcNow();
        if (now - _clockSkew >= token.ExpiresAt)
        {
            return [Error(ErrorCodes.StatusUnresolvable, "The MSO revocation list is expired; the current status is unknown.")];
        }

        // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 3a validates the token per RFC 8392 section 7.2,
        // and RFC 8392 section 3.1.5 gives nbf the processing rules of RFC 7519: not accepted before it.
        if (token.NotBefore is { } notBefore && now + _clockSkew < notBefore)
        {
            return [Error(ErrorCodes.StatusUnresolvable, "The MSO revocation list is not valid yet; the current status is unknown.")];
        }

        byte[]? list = null;
        if (reference.Kind == RevocationListKind.StatusList)
        {
            var (decompressed, failure) = await StatusListValues.DecompressAsync(token.CompressedList!, ct).ConfigureAwait(false);
            if (decompressed is null)
            {
                return [failure!];
            }

            list = decompressed;
        }

        var validated = new ValidatedList(token, list);
        if (await UntrustedAsync(validated, reference, credential, ct).ConfigureAwait(false) is { } untrusted)
        {
            // Not cached: a list served once that is not trusted for this credential never stands in later.
            return [untrusted];
        }

        _cache.Set(cacheKey, validated, StatusListValues.CacheUntil(now, _cacheDuration, token.TtlSeconds, token.ExpiresAt), now);
        return Evaluate(validated, reference);
    }

    /// <summary>Why <paramref name="list"/> may not speak for THIS credential, or null when it may.</summary>
    private Task<VerificationError?> UntrustedAsync(
        ValidatedList list, RevocationListReference reference, MsoRevocationTrust.Credential credential, CancellationToken ct) =>
        MsoRevocationTrust.CheckAsync(list.Token, reference, credential, _trustListResolver, _clock, ct);

    private static List<VerificationError> Evaluate(ValidatedList list, RevocationListReference reference) =>
        reference.Kind == RevocationListKind.StatusList
            ? StatusListValues.Evaluate(list.Token.Bits, list.List!, reference.Index)
            // SPEC: EAA-6.2.10.1-10.1, "Where the identifier in the IdentifierList is present the MSO that
            // contains the identifier in the status element is revoked."
            : list.Token.Identifiers!.Contains(Convert.ToHexString(reference.Id!))
                ? [Error(ErrorCodes.CredentialRevoked, "The issuer has revoked this credential: its identifier is on the identifier list.")]
                : [];

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
