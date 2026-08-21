using System.Text.Json;
using System.Web;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// Pins the request against the EU AV Profile's own worked example (Annex A, A.11) rather than against a
/// reading of the requirements list. A.6's delivery sentence leaves it open whether a request object is
/// sent at all; the A.11 example does not. Source: eu-digital-identity-wallet/
/// av-doc-technical-specification, docs/annexes/annex-A/annex-A-av-profile.md.
/// </summary>
public sealed class AvPresentationRequestBuilderTests
{
    // The example's response_uri, truncated. Its trailing segment is identical to the example's `state`,
    // which suggests the reference implementation correlates by URI; that is an observation of the
    // example, not something A.6 requires. A.6 requires only that client_id be `redirect_uri` followed by
    // the response_uri, so a fixed response_uri is equally conformant. We correlate by state.
    private const string ResponseUriText =
        "https://verifier-backend.ageverification.dev/wallet/direct_post/X2b8D86wXoyQIzFcIC3o8vpq";

    // SPEC: A.11 — mso_mdoc, singular doctype_value, and a two-element [namespace, element] claim path.
    private const string AvDcql =
        """{"credentials":[{"id":"proof_of_age","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.av.1"},"claims":[{"path":["eu.europa.ec.av.1","age_over_18"]}]}]}""";

    private static AvPresentationRequestBuilder Builder(string? endpoint = null) => new(
        new AvPresentationRequestBuilderOptions
        {
            Clock = new FakeTimeProvider(),
            AuthorizationEndpoint = endpoint ?? "av://",
        });

    private static PresentationRequestOptions Options() => new()
    {
        ClientId = $"redirect_uri:{ResponseUriText}",
        Nonce = "a541f48f-e31c-4244-9b10-86af3150d454",
        State = "X2b8D86wXoyQIzFcIC3o8vpq",
        DcqlQueryJson = AvDcql,
        ResponseUri = new Uri(ResponseUriText),
        ResponseMode = ResponseMode.DirectPost,
    };

    private static Dictionary<string, string> QueryOf(Uri uri)
    {
        var parsed = HttpUtility.ParseQueryString(uri.Query);
        return parsed.AllKeys.Where(k => k is not null)
            .ToDictionary(k => k!, k => parsed[k]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// The whole reason this builder exists. If a `request` parameter ever appears here, the app is being
    /// sent a JAR under a profile that does not use JAR.
    /// </summary>
    [Fact]
    public async Task Carries_no_request_object_at_all()
    {
        var request = await Builder().BuildAsync(Options());
        var query = QueryOf(request.AuthorizationRequestUri);

        Assert.DoesNotContain("request", query.Keys);
        Assert.DoesNotContain("request_uri", query.Keys);
        Assert.DoesNotContain("client_metadata", query.Keys);
    }

    /// <summary>Every parameter A.11 shows, and nothing else.</summary>
    [Fact]
    public async Task Sends_exactly_the_parameters_the_profile_example_shows()
    {
        var request = await Builder().BuildAsync(Options());

        Assert.Equal(
            ["client_id", "dcql_query", "nonce", "response_mode", "response_type", "response_uri", "state"],
            QueryOf(request.AuthorizationRequestUri).Keys.OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public async Task Sends_the_values_the_profile_example_shows()
    {
        var query = QueryOf((await Builder().BuildAsync(Options())).AuthorizationRequestUri);

        Assert.Equal("vp_token", query["response_type"]);
        Assert.Equal("direct_post", query["response_mode"]);
        Assert.Equal($"redirect_uri:{ResponseUriText}", query["client_id"]);
        Assert.Equal(ResponseUriText, query["response_uri"]);
        Assert.Equal("a541f48f-e31c-4244-9b10-86af3150d454", query["nonce"]);

        // Compared as JSON: the profile fixes the shape, not the byte-for-byte encoding of the parameter.
        using var expected = JsonDocument.Parse(AvDcql);
        using var actual = JsonDocument.Parse(query["dcql_query"]);
        Assert.Equal(expected.RootElement.ToString(), actual.RootElement.ToString());
    }

    [Fact]
    public async Task Invokes_the_app_on_the_av_scheme()
    {
        var request = await Builder().BuildAsync(Options());

        Assert.Equal("av", request.AuthorizationRequestUri.Scheme);
    }

    /// <summary>
    /// Pins a <see cref="Uri"/> normalisation that changes the string the app receives, so it cannot
    /// surprise anyone later: .NET always inserts a path slash before the query. The profile's
    /// <c>av://?...</c> becomes <c>av:///?...</c>, and <c>av://authorize?...</c> becomes
    /// <c>av://authorize/?...</c>.
    /// </summary>
    /// <remarks>
    /// Unavoidable while the request exposes a <see cref="Uri"/>, so it is pinned rather than left to be
    /// discovered. The evidence that wallets tolerate it is limited to the <c>openid4vp</c> scheme: the EU
    /// reference wallet has parsed <c>openid4vp://authorize/?...</c> deeplinks carrying the same inserted
    /// slash. Whether the AV app accepts the equivalent on <c>av://</c> is untested. If it rejects the
    /// deeplink, this is a cheap first thing to rule out.
    /// </remarks>
    [Fact]
    public async Task Uri_normalisation_inserts_a_path_slash_before_the_query()
    {
        var pathless = await Builder().BuildAsync(Options());
        var withPath = await Builder("av://authorize").BuildAsync(Options());

        Assert.StartsWith("av:///?", pathless.AuthorizationRequestUri.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("av://authorize/?", withPath.AuthorizationRequestUri.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The pathless form is the only av:// shape the specification shows, but it is unconfirmed against
    /// the app. If it turns out to want a path, this must keep working without touching the builder.
    /// </summary>
    [Fact]
    public async Task Honours_a_configured_endpoint_path()
    {
        var request = await Builder("av://authorize").BuildAsync(Options());

        Assert.Equal("authorize", request.AuthorizationRequestUri.Authority);
        Assert.Equal("vp_token", QueryOf(request.AuthorizationRequestUri)["response_type"]);
    }

    [Fact]
    public async Task State_is_optional()
    {
        var request = await Builder().BuildAsync(Options() with { State = null });

        Assert.DoesNotContain("state", QueryOf(request.AuthorizationRequestUri).Keys);
        Assert.Null(request.State);
    }

    [Fact]
    public async Task Refuses_an_encrypted_response_mode_rather_than_correcting_it()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Builder().BuildAsync(Options() with { ResponseMode = ResponseMode.DirectPostJwt }));

        Assert.Contains("direct_post", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Refuses_client_metadata_rather_than_dropping_it_silently()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Builder().BuildAsync(Options() with { ClientMetadataJson = """{"client_name":"x"}""" }));

        Assert.Contains("client_metadata", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A client_id that is not the redirect_uri scheme over this exact response_uri is a caller
    /// disagreeing with itself about who the verifier is. Refuse, do not rewrite.
    /// </summary>
    [Theory]
    [InlineData("tessio-cloud")]
    [InlineData("x509_san_dns:verifier.example.com")]
    [InlineData("redirect_uri:https://somewhere.else/callback")]
    public async Task Refuses_a_client_id_that_is_not_the_response_uri(string clientId)
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Builder().BuildAsync(Options() with { ClientId = clientId }));

        Assert.Contains("redirect_uri:", ex.Message, StringComparison.Ordinal);
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    }
}
