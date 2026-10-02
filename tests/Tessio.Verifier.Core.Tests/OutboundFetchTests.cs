// What belongs here: the rules for requests a credential can cause, tested through the verifier a
// caller actually constructs as well as through the pieces, because a guard nothing uses passes its
// own unit tests.

using System.Net;

namespace Tessio.Verifier.Core.Tests;

public class OutboundFetchTests
{
    private const string Refused = "outside the public internet";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    /// <summary>
    /// The WIRING test. A verifier built with no client, as the ASP.NET Core registration builds it,
    /// must refuse an issuer whose metadata host is internal. Asserting the refusal message rather than
    /// the error code matters: nothing listens on these addresses, so without the guard the request
    /// still fails, as a connection error with the same code.
    /// </summary>
    [Theory]
    [InlineData("https://127.0.0.1")]
    [InlineData("https://localhost")]
    [InlineData("https://169.254.169.254")]
    public async Task The_default_client_refuses_an_internal_metadata_host(string issuer)
    {
        using var builder = new TestCredentialBuilder { Issuer = issuer };
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver());

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == "issuer_key_unresolvable");
        Assert.Contains(Refused, error.Message, StringComparison.Ordinal);
    }

    /// <summary>The same wiring for the status list, which the verifier fetches with the same client.</summary>
    [Fact]
    public async Task The_default_client_refuses_an_internal_status_list_host()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();                            // x5c: the issuer key needs no fetch
        builder.Status = (0, "https://127.0.0.1/statuslists/1");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver());

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == "status_unresolvable");
        Assert.Contains(Refused, error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The size limit is enforced by the reader, so it holds for a client the caller supplies too.
    /// </summary>
    [Fact]
    public async Task Issuer_metadata_over_the_limit_is_refused()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().MapBytes(
            "https://issuer.example/.well-known/jwt-vc-issuer", new byte[OutboundFetch.MaxMetadataBytes + 1]);
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == "issuer_key_unresolvable");
        Assert.Contains("limit", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A declared length over the limit is refused before the body is read at all. The body here throws
    /// if anything reads it, so only the Content-Length check can produce this result.
    /// </summary>
    [Fact]
    public async Task A_declared_length_over_the_limit_is_refused_unread()
    {
        using var client = new HttpClient(new DeclaredLengthHandler(1025));

        await Assert.ThrowsAsync<OutboundFetch.TooLargeException>(() => OutboundFetch.GetBoundedAsync(
            client, new Uri("https://issuer.example/x"), accept: null, "body", limit: 1024, CancellationToken.None));
    }

    /// <summary>
    /// Headers promptly, then a body that never finishes. The client's own timeout stops at the headers
    /// once the body is streamed, so only the reader's deadline ends this. It runs at the real deadline,
    /// because a shorter one would pass with the production value unwired.
    /// </summary>
    [Fact]
    public async Task A_body_that_stalls_after_the_headers_hits_the_deadline()
    {
        using var client = new HttpClient(new StallingBodyHandler()) { Timeout = Timeout.InfiniteTimeSpan };

        await Assert.ThrowsAsync<OutboundFetch.TimedOutException>(() => OutboundFetch.GetBoundedAsync(
            client, new Uri("https://issuer.example/x"), accept: null, "body", limit: 1024, CancellationToken.None));
    }

    /// <summary>
    /// A body with no declared length, which the Content-Length check cannot see, is still cut off.
    /// </summary>
    [Fact]
    public async Task A_stream_over_the_limit_is_refused_while_reading()
    {
        await using var body = new UnseekableStream(new byte[1025]);

        await Assert.ThrowsAsync<OutboundFetch.TooLargeException>(
            () => OutboundFetch.ReadBoundedAsync(body, "body", limit: 1024, CancellationToken.None));
    }

    [Fact]
    public async Task A_stream_at_the_limit_is_read_whole()
    {
        await using var body = new UnseekableStream(new byte[1024]);

        var read = await OutboundFetch.ReadBoundedAsync(body, "body", limit: 1024, CancellationToken.None);

        Assert.Equal(1024, read.Length);
    }

    /// <summary>
    /// Redirects and the proxy are decided by the handler, which no fake can exercise without replacing
    /// it, and the process proxy is read once per process, so a test cannot set it. This reads the
    /// handler out of the client CreateClient builds, not out of a fresh handler, so a client built some
    /// other way fails here. That the verifier's default IS this client is pinned by the address tests
    /// above. The field is private: if the framework renames it this fails loudly.
    /// </summary>
    [Fact]
    public void The_default_client_refuses_redirects_ignores_the_proxy_and_checks_every_connection()
    {
        using var client = OutboundFetch.CreateClient();
        var field = typeof(HttpMessageInvoker).GetField(
            "_handler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var handler = Assert.IsType<SocketsHttpHandler>(field?.GetValue(client));

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseProxy);
        Assert.NotNull(handler.ConnectCallback);
    }

    /// <summary>
    /// A connection that drops mid-body surfaces as IOException once the body is streamed. It must fail
    /// the credential, not escape the verifier, which promises never to throw on input.
    /// </summary>
    [Fact]
    public async Task A_body_that_breaks_mid_read_fails_the_credential_closed()
    {
        using var builder = new TestCredentialBuilder();
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(new BreakingBodyHandler()));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "issuer_key_unresolvable");
    }

    /// <summary>
    /// A byte order mark before the JSON is ignored, as the buffered read this replaced ignored it.
    /// The control is the credential verifying at all: without the strip, parsing fails.
    /// </summary>
    [Fact]
    public async Task Issuer_metadata_with_a_byte_order_mark_still_verifies()
    {
        using var builder = new TestCredentialBuilder();
        var json = $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""";
        var http = new FakeHttpHandler().MapBytes(
            "https://issuer.example/.well-known/jwt-vc-issuer", [0xEF, 0xBB, 0xBF, .. System.Text.Encoding.UTF8.GetBytes(json)]);
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
    }

    /// <summary>
    /// The caller cancelling is not a timeout. The fetch rethrows it as cancellation rather than as a
    /// report that the issuer was slow. What the verifier then does with a cancelled fetch is decided by
    /// its callers, which map it to an unresolvable result, and is not tested here.
    /// </summary>
    [Fact]
    public async Task A_caller_cancelling_is_not_reported_as_a_timeout()
    {
        using var client = new HttpClient(new StallingBodyHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => OutboundFetch.GetBoundedAsync(
            client, new Uri("https://issuer.example/x"), accept: null, "body", limit: 1024, cancel.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(thrown);
    }
}
