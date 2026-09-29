namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// A trust seam that cannot answer becomes a result, never an exception, on every route.
/// </summary>
/// <remarks>
/// What belongs here: the verifier's promise to return a result for any input, held while the trust
/// source is down. A forged credential must not turn an outage into an exception either.
/// </remarks>
public class TrustSeamFailureTests
{
    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static PresentedCredential Credential(string raw) => new() { Format = "dc+sd-jwt", RawValue = raw };

    private static FakeHttpHandler MetadataFor(TestCredentialBuilder builder) => new FakeHttpHandler().Map(
        "https://issuer.example/.well-known/jwt-vc-issuer",
        $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");

    [Fact]
    public async Task MetadataRoute_WithTheTrustSourceDown_FailsClosed_WithoutFetchingTheKey()
    {
        using var builder = new TestCredentialBuilder();
        var http = MetadataFor(builder);
        var trust = new FailingTrustListResolver();

        var result = await new SdJwtVcVerifier(trust, httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal(["issuer_trust_unresolvable"], result.Errors.Select(e => e.Code));
        Assert.Contains("trust source unreachable", result.Errors[0].Message, StringComparison.Ordinal);
        Assert.False(result.Issuer.Trusted);
        Assert.Empty(http.Requested);
    }

    [Fact]
    public async Task X5cRoute_WithTheTrustSourceDown_FailsClosed_AndKeepsItsOtherErrors()
    {
        using var builder = new TestCredentialBuilder { KbNonce = "wrong-nonce" };
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new FailingTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains("issuer_trust_unresolvable", codes);
        Assert.Contains("nonce_mismatch", codes);
        Assert.DoesNotContain("issuer_untrusted", codes);
        Assert.False(result.IsValid);
    }

    /// <summary>Every kind of trust source failure the seam converts, each on its own.</summary>
    [Theory]
    [InlineData("http")]
    [InlineData("io")]
    [InlineData("timeout")]
    [InlineData("self-imposed timeout")]
    [InlineData("not ready")]
    public async Task EachTrustSourceFailure_BecomesIssuerTrustUnresolvable(string kind)
    {
        Func<Exception> failure = kind switch
        {
            "http" => () => new HttpRequestException("trust source unreachable"),
            "io" => () => new IOException("trust source unreachable"),
            "timeout" => () => new TimeoutException("trust source unreachable"),
            "not ready" => () => new InvalidOperationException("trust source unreachable"),
            _ => () => new TaskCanceledException("trust source unreachable"),
        };
        using var builder = new TestCredentialBuilder();

        var result = await new SdJwtVcVerifier(new FailingTrustListResolver(failure), httpClient: new HttpClient(MetadataFor(builder)))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.Equal(["issuer_trust_unresolvable"], result.Errors.Select(e => e.Code));
        Assert.Contains("trust source unreachable", result.Errors[0].Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A cancellation the caller asked for is not the trust source failing, so it still propagates.
    /// </summary>
    [Fact]
    public async Task ACallerCancellation_StillPropagates()
    {
        using var builder = new TestCredentialBuilder();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SdJwtVcVerifier(new CancellationObservingResolver(), httpClient: new HttpClient(MetadataFor(builder)))
                .VerifyAsync(Credential(builder.Build()), Context(), cancelled.Token));
    }

    private sealed class CancellationObservingResolver : Tessio.Verifier.Trust.ITrustListResolver
    {
        public Task<Tessio.Verifier.Trust.IssuerTrustStatus> ResolveAsync(
            string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new Tessio.Verifier.Trust.IssuerTrustStatus { Trusted = true });
        }
    }
}
