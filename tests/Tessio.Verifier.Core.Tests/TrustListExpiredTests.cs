using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// A refusal whose cause is the trust list itself is reported as <c>trust_list_expired</c>, not as an
/// untrusted issuer, on both SD-JWT VC routes.
/// </summary>
/// <remarks>
/// SPEC: ETSI TS 119 612 V2.4.1 section 5.3.15: "TL with a Next update occurring in the past shall be
/// discarded as expired". A resolver that follows it says so with <see cref="IssuerTrustStatus.TrustListExpired"/>.
/// </remarks>
public class TrustListExpiredTests
{
    private const string Lapsed = "The trust list was due to be reissued and has not been.";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static PresentedCredential Credential(string raw) => new() { Format = "dc+sd-jwt", RawValue = raw };

    [Fact]
    public async Task MetadataRoute_ALapsedList_IsReportedAsTheList_WithoutFetchingTheKey()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new LapsedListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        var error = Assert.Single(result.Errors);
        Assert.Equal(ErrorCodes.TrustListExpired, error.Code);
        Assert.Equal(Lapsed, error.Message);
        Assert.Empty(http.Requested);
    }

    [Fact]
    public async Task X5cRoute_ALapsedList_IsReportedAsTheList_NotAsTheIssuer()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new LapsedListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains(ErrorCodes.TrustListExpired, codes);
        Assert.DoesNotContain(ErrorCodes.IssuerUntrusted, codes);
    }

    [Fact]
    public async Task ARefusalWithoutTheFlag_IsStillAnUntrustedIssuer()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new LapsedListResolver(listExpired: false))
            .VerifyAsync(Credential(builder.Build()), Context());

        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains(ErrorCodes.IssuerUntrusted, codes);
        Assert.DoesNotContain(ErrorCodes.TrustListExpired, codes);
    }

    [Fact]
    public async Task OnATrustedVerdict_TheFlagChangesNothing()
    {
        // Trusted keeps the meaning its frozen contract gave it: the flag explains a refusal and never makes one.
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new TrustedButFlaggedResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid);
        Assert.True(result.Issuer.Trusted);
    }

    private sealed class TrustedButFlaggedResolver : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "flagged", TrustListExpired = true });
    }

    private sealed class LapsedListResolver(bool listExpired = true) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus
            {
                Trusted = false,
                TrustListSource = "lapsed-list",
                Reason = Lapsed,
                TrustListExpired = listExpired,
            });
    }
}
