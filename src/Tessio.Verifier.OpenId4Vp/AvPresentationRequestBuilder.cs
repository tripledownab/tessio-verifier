using System.Text;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds EU Age Verification authorization requests: DCQL in plain query parameters, no request object.
/// </summary>
/// <remarks>
/// <para>
/// Not a relaxed <see cref="SignedPresentationRequestBuilder"/>. That one always produces a JAR and
/// delivers it as <c>request</c> or <c>request_uri</c>; this one produces no request object at all. Two
/// implementations rather than a flag, because a flag on a signing builder is one misconfiguration away
/// from silently disabling signing on the profile that depends on it.
/// </para>
/// <para>
/// Why the profile drops JAR, since it reads like a weakening: JAR's integrity protection depends on a
/// trust list of relying parties. The AV solution has none, so an attacker can obtain a valid certificate
/// and substitute their own signed request. Signing would look like protection while providing none.
/// Integrity rests on TLS and the Web PKI instead.
/// </para>
/// </remarks>
// SPEC: EU AV Profile, Annex A A.6 and the A.11 worked example, from
// eu-digital-identity-wallet/av-doc-technical-specification, docs/annexes/annex-A/annex-A-av-profile.md.
// Read that markdown source rather than the rendered site: the rendered page summarises the delivery
// requirement in a way that reads as ambiguous, while the source carries the worked example that settles it.
public sealed class AvPresentationRequestBuilder : IAvPresentationRequestBuilder
{
    private readonly AvPresentationRequestBuilderOptions _options;
    private readonly TimeProvider _clock;

    /// <summary>Creates a builder from the supplied options.</summary>
    public AvPresentationRequestBuilder(AvPresentationRequestBuilderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _clock = options.Clock ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<AvPresentationRequest> BuildAsync(
        PresentationRequestOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Refuse rather than correct. Silently rewriting either of these would hand the app a request
        // shaped for a different profile and turn a config mistake into a wallet-side failure with no
        // local symptom.
        if (options.ResponseMode is not ResponseMode.DirectPost)
        {
            throw new InvalidOperationException(
                $"The AV Profile requires response_mode=direct_post; got {options.ResponseMode}. It has no " +
                "encrypted response mode, so direct_post.jwt cannot be delivered under it.");
        }

        if (options.ClientMetadataJson is not null)
        {
            throw new InvalidOperationException(
                "The AV Profile request carries no client_metadata: nothing is encrypted, and the verifier " +
                "is identified by the redirect_uri client identifier scheme. Leave ClientMetadataJson null.");
        }

        // SPEC: A.6 — "The client identifier scheme MUST be redirect_uri followed by the response_uri".
        // Checked rather than constructed here: the caller owns client_id, and a builder quietly rewriting
        // it would hide a caller that disagrees with itself about who the verifier is.
        var expectedClientId = $"redirect_uri:{options.ResponseUri}";
        if (!string.Equals(options.ClientId, expectedClientId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The AV Profile requires client_id '{expectedClientId}' (the redirect_uri scheme followed " +
                $"by the response_uri); got '{options.ClientId}'.");
        }

        var now = _clock.GetUtcNow();
        var expiresAt = now + (options.RequestLifetime ?? _options.DefaultRequestLifetime);

        // Values come from the one place that already knows how to render them, so the two builders cannot
        // drift on response_mode or on how a DCQL string becomes JSON. The JWT-only claims it adds (iat,
        // exp, aud) are dropped below: they are request-object claims, and there is no request object.
        var claims = RequestObjectClaims.Build(options, now, expiresAt);

        var query = new StringBuilder()
            .Append("response_type=").Append(Uri.EscapeDataString(Claim(claims, "response_type")))
            .Append("&response_mode=").Append(Uri.EscapeDataString(Claim(claims, "response_mode")))
            .Append("&client_id=").Append(Uri.EscapeDataString(Claim(claims, "client_id")))
            .Append("&response_uri=").Append(Uri.EscapeDataString(Claim(claims, "response_uri")))
            .Append("&dcql_query=").Append(Uri.EscapeDataString(claims["dcql_query"]!.ToJsonString()))
            .Append("&nonce=").Append(Uri.EscapeDataString(Claim(claims, "nonce")));

        if (options.State is not null)
        {
            query.Append("&state=").Append(Uri.EscapeDataString(options.State));
        }

        return Task.FromResult(new AvPresentationRequest
        {
            ClientId = options.ClientId,
            Nonce = options.Nonce,
            State = options.State,
            AuthorizationRequestUri = new Uri($"{_options.AuthorizationEndpoint}?{query}"),
            ExpiresAt = expiresAt,
        });
    }

    private static string Claim(JsonObject claims, string name) =>
        claims[name]?.GetValue<string>()
        ?? throw new InvalidOperationException($"The request object claims are missing '{name}'.");
}
