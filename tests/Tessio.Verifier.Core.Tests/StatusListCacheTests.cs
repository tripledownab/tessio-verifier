namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Status list caching (draft-ietf-oauth-status-list §11.2): validated lists are reused within the
/// cache window, the token's ttl shortens the window, failures are never cached and revocation
/// verdicts stay per-index correct when served from cache.
/// </summary>
public class StatusListCacheTests
{
    private const string StatusUri = "https://issuer.example/statuslists/1";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static (SdJwtVcVerifier Verifier, FakeHttpHandler Http) VerifierFor(
        TestCredentialBuilder builder, string statusListJwt, SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, statusListJwt);

        return (new SdJwtVcVerifier(new FakeTrustListResolver(), options, new HttpClient(http)), http);
    }

    private static int StatusFetches(FakeHttpHandler http) =>
        http.Requested.Count(url => url == StatusUri);

    [Fact]
    public async Task SecondVerification_ServesTheListFromCache()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 1]));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);

        Assert.Equal(1, StatusFetches(http));
    }

    [Fact]
    public async Task CachedList_StillRevokes_PerIndex()
    {
        // Two credentials referencing the same list at different indices; the second verdict comes
        // from the cached bitstring and must still be evaluated per index.
        var valid = new TestCredentialBuilder { Status = (0, StatusUri) };
        var statusList = valid.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 1]);
        var (verifier, http) = VerifierFor(valid, statusList);

        var validResult = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = valid.Build() }, Context(), CancellationToken.None);
        Assert.True(validResult.IsValid);

        valid.Status = (1, StatusUri);
        var revokedResult = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = valid.Build() }, Context(), CancellationToken.None);

        Assert.False(revokedResult.IsValid);
        Assert.Contains(revokedResult.Errors, e => e.Code == "credential_revoked");
        Assert.Equal(1, StatusFetches(http));
    }

    [Fact]
    public async Task ZeroCacheDuration_FetchesEveryTime()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder,
            builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]),
            new SdJwtVcVerifierOptions { StatusListCacheDuration = TimeSpan.Zero });
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);
        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.Equal(2, StatusFetches(http));
    }

    [Fact]
    public async Task TokenTtlZero_OverridesTheCacheDuration()
    {
        // The issuer's ttl claim is the cache ceiling; ttl=0 means do not cache at all.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: 0));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);
        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.Equal(2, StatusFetches(http));
    }

    [Fact]
    public async Task FailedResolution_IsNotCached_AndStaysFailClosed()
    {
        // No mapping for the status uri: both verifications must attempt the fetch and fail closed.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        var first = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);
        var second = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Contains(second.Errors, e => e.Code == "status_unresolvable");
        Assert.Equal(2, StatusFetches(http));
    }
}
