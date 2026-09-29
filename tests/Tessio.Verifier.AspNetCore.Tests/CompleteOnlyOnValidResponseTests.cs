using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// What a response that fails verification does to its session, with
/// <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> off (the default) and on. Everything about
/// failed attempts, as opposed to a session's outcome, belongs here.
/// </summary>
public sealed class CompleteOnlyOnValidResponseTests
{
    /// <summary>A nonce no session was issued, so the presentation parses and then fails verification.</summary>
    private const string ForeignNonce = "a-nonce-this-session-never-issued";

    private static IHost StartHost(bool completeOnlyOnValid, Func<IServiceProvider, ISessionStore>? store = null) => new HostBuilder()
        .ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(services =>
            {
                if (store is not null)
                {
                    services.AddSingleton<ISessionStore>(store);
                }

                services.AddRouting().AddTessioVerifier(options =>
                {
                    options.Mode = VerifierMode.Mock;
                    options.ResponseMode = ResponseMode.DirectPost;
                    options.RequestedClaims = ["age_over_18"];
                    options.CompleteOnlyOnValidResponse = completeOnlyOnValid;
                });
            })
            .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
        .Start();

    private static async Task<VerificationSession> CreateSessionAsync(IHost host) =>
        await host.Services.GetRequiredService<ISessionStore>().CreateAsync(DemoRequestOptionsFactory.Create(
            host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value,
            new Uri("http://localhost/verify/callback")));

    private static FormUrlEncodedContent Presentation(IHost host, VerificationSession session, string nonce)
    {
        var options = host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var presentation = host.Services.GetRequiredService<MockCredentialIssuer>().IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, nonce, options.ClientId);
        return new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
            ["state"] = session.Request.State!,
        });
    }

    private static async Task<VerificationSession> ReadAsync(IHost host, string sessionId) =>
        (await host.Services.GetRequiredService<ISessionStore>().GetAsync(sessionId))!;

    [Fact]
    public async Task Off_ByDefault_AFailingResponseCompletesTheSession_AsBefore()
    {
        Assert.False(new VerifierOptions().CompleteOnlyOnValidResponse);
        using var host = StartHost(completeOnlyOnValid: false);
        var client = host.GetTestClient();
        var session = await CreateSessionAsync(host);

        var response = await client.PostAsync("/verify/callback", Presentation(host, session, ForeignNonce));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var after = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, after.Status);
        Assert.False(after.Result!.IsValid);
        Assert.Null(after.LastFailure);
        Assert.Equal(0, after.FailedAttempts);
    }

    [Fact]
    public async Task On_AFailingResponseIsRefused_AndRecorded_AndAValidOneStillCompletes()
    {
        using var host = StartHost(completeOnlyOnValid: true);
        var client = host.GetTestClient();
        var session = await CreateSessionAsync(host);

        var failing = await client.PostAsync("/verify/callback", Presentation(host, session, ForeignNonce));

        Assert.Equal(HttpStatusCode.BadRequest, failing.StatusCode);
        Assert.Contains("invalid_response", await failing.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var kept = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Pending, kept.Status);
        Assert.Null(kept.Result);
        Assert.False(kept.LastFailure!.IsValid);
        Assert.NotEmpty(kept.LastFailure.Errors);
        Assert.Equal(1, kept.FailedAttempts);

        var valid = await client.PostAsync("/verify/callback", Presentation(host, session, session.Request.Nonce));

        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        var done = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, done.Status);
        Assert.True(done.Result!.IsValid);
        Assert.Equal(1, done.FailedAttempts);
    }

    [Fact]
    public async Task On_TheStatusResourceCarriesTheFailure_NarrowedLikeTheResult()
    {
        using var host = StartHost(completeOnlyOnValid: true);
        var client = host.GetTestClient();
        var session = await CreateSessionAsync(host);
        await client.PostAsync("/verify/callback", Presentation(host, session, ForeignNonce));

        using var status = JsonDocument.Parse(await client.GetStringAsync($"/verify/{session.SessionId}"));

        Assert.Equal("pending", status.RootElement.GetProperty("status").GetString());
        Assert.Equal(1, status.RootElement.GetProperty("failedAttempts").GetInt32());
        var error = status.RootElement.GetProperty("lastFailure").GetProperty("errors")[0];
        Assert.False(string.IsNullOrEmpty(error.GetProperty("code").GetString()));
        Assert.Equal(VerifierOptions.UndisclosedErrorMessage, error.GetProperty("message").GetString());
    }

    [Theory]
    [InlineData(false)] // the in-memory store, which pushes changes
    [InlineData(true)]  // a store the stream can only poll
    public async Task On_TheStreamSendsAttemptFailed_ThenCompleted(bool polledStore)
    {
        using var host = StartHost(completeOnlyOnValid: true, polledStore
            ? sp => new AttemptRecordingStoreWrapper(new InMemorySessionStore(
                sp.GetRequiredService<IPresentationRequestBuilder>(), TimeProvider.System))
            : null);
        var client = host.GetTestClient();
        var session = await CreateSessionAsync(host);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var stream = await client.GetAsync($"/verify/{session.SessionId}/stream",
            HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        using var reader = new StreamReader(await stream.Content.ReadAsStreamAsync(timeout.Token));
        var events = new List<string>();

        // Each failure is read off the stream before the next is posted, so none can merge with another,
        // and the exact list also catches a stream that repeats an event it already sent.
        await ReadUntilAsync(reader, "pending", events, timeout.Token);
        await client.PostAsync("/verify/callback", Presentation(host, session, ForeignNonce), timeout.Token);
        await ReadUntilAsync(reader, "attempt_failed", events, timeout.Token);
        await client.PostAsync("/verify/callback", Presentation(host, session, ForeignNonce), timeout.Token);
        await ReadUntilAsync(reader, "attempt_failed", events, timeout.Token);
        await client.PostAsync("/verify/callback", Presentation(host, session, session.Request.Nonce), timeout.Token);
        await ReadUntilAsync(reader, "completed", events, timeout.Token);

        Assert.Equal(["pending", "attempt_failed", "attempt_failed", "completed"], events);
    }

    [Fact]
    public async Task TheStream_EndsAtExpiry_EvenIfAHostStoreStillSaysPending()
    {
        // A host store that never moves a session out of pending. The stream must end at the session's
        // expiry, as it did before failed attempts existed, rather than keep re-reading the store.
        EverPendingStore? store = null;
        using var host = StartHost(completeOnlyOnValid: true, sp => store = new EverPendingStore(
            new InMemorySessionStore(sp.GetRequiredService<IPresentationRequestBuilder>(), TimeProvider.System),
            TimeSpan.FromSeconds(1)));
        var session = await CreateSessionAsync(host);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var stream = await host.GetTestClient().GetAsync($"/verify/{session.SessionId}/stream",
            HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        using var reader = new StreamReader(await stream.Content.ReadAsStreamAsync(timeout.Token));
        var events = new List<string>();
        await ReadUntilAsync(reader, "expired", events, timeout.Token);

        Assert.Equal(["pending", "expired"], events);
        Assert.InRange(store!.Reads, 1, 20);
    }

    [Fact]
    public void On_AStoreThatCannotRecordAFailure_StopsTheCallbackFromStarting()
    {
        static ISessionStore StateOnly(IServiceProvider sp) => new StateCorrelatingOnlyWrapper(new InMemorySessionStore(
            sp.GetRequiredService<IPresentationRequestBuilder>(), TimeProvider.System));

        // The control: the same store is fine with the option off.
        using var off = StartHost(completeOnlyOnValid: false, StateOnly);
        Assert.NotNull(off.Services.GetRequiredService<WalletCallbackProcessor>());

        // With it on, the callback cannot be built. In mock mode the mock wallet builds it at startup, so
        // the host refuses to start. A live host meets the same exception at its first callback.
        var refused = Assert.Throws<InvalidOperationException>(() => StartHost(completeOnlyOnValid: true, StateOnly).Dispose());
        Assert.Contains(nameof(IAttemptRecordingSessionStore), refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFailureRecordedAfterCompletion_ChangesNothing()
    {
        using var host = StartHost(completeOnlyOnValid: true);
        var store = host.Services.GetRequiredService<InMemorySessionStore>();
        var session = await CreateSessionAsync(host);
        var valid = VerificationResult.Invalid(new VerificationError { Code = "x", Message = "x" }) with { IsValid = true };
        await store.CompleteAsync(session.SessionId, valid);

        await store.RecordFailedAttemptAsync(session.SessionId,
            VerificationResult.Invalid(new VerificationError { Code = "late", Message = "late" }));

        var after = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, after.Status);
        Assert.Same(valid, after.Result);
        Assert.Null(after.LastFailure);
        Assert.Equal(0, after.FailedAttempts);
    }

    private static async Task ReadUntilAsync(StreamReader reader, string eventName, List<string> events, CancellationToken ct)
    {
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.StartsWith("event: ", StringComparison.Ordinal))
            {
                events.Add(line["event: ".Length..]);
                if (events[^1] == eventName)
                {
                    return;
                }
            }
        }

        throw new InvalidOperationException($"The stream ended before '{eventName}'. Saw: {string.Join(", ", events)}.");
    }

    /// <summary>
    /// A store that is not <see cref="InMemorySessionStore"/>, so the stream has to poll it, and that can
    /// record failures. Delegates everything, so the only thing under test is the stream's polling.
    /// </summary>
    private sealed class AttemptRecordingStoreWrapper(InMemorySessionStore inner) : IStateCorrelatingSessionStore, IAttemptRecordingSessionStore
    {
        public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) => inner.CreateAsync(options, ct);
        public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => inner.GetAsync(sessionId, ct);
        public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) => inner.CompleteAsync(sessionId, result, ct);
        public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) => inner.FindByStateAsync(state, ct);
        public Task RecordFailedAttemptAsync(string sessionId, VerificationResult failure, CancellationToken ct = default) => inner.RecordFailedAttemptAsync(sessionId, failure, ct);
    }

    /// <summary>
    /// Reports every session as pending on every read, however far past its expiry, gives each a short
    /// lifetime, and counts the reads. Implements both interfaces only so the callback can be built.
    /// </summary>
    private sealed class EverPendingStore(InMemorySessionStore inner, TimeSpan lifetime) : IStateCorrelatingSessionStore, IAttemptRecordingSessionStore
    {
        private readonly DateTimeOffset _expiresAt = DateTimeOffset.UtcNow + lifetime;
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public async Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
            (await inner.CreateAsync(options, ct)) with { ExpiresAt = _expiresAt };

        public async Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _reads);
            return await inner.GetAsync(sessionId, ct) is { } session
                ? session with { Status = VerificationSessionStatus.Pending, ExpiresAt = _expiresAt }
                : null;
        }

        public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) => inner.CompleteAsync(sessionId, result, ct);
        public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) => inner.FindByStateAsync(state, ct);
        public Task RecordFailedAttemptAsync(string sessionId, VerificationResult failure, CancellationToken ct = default) => inner.RecordFailedAttemptAsync(sessionId, failure, ct);
    }

    /// <summary>A store written against the frozen contract only: it can correlate, and cannot record a failure.</summary>
    private sealed class StateCorrelatingOnlyWrapper(InMemorySessionStore inner) : IStateCorrelatingSessionStore
    {
        public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) => inner.CreateAsync(options, ct);
        public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => inner.GetAsync(sessionId, ct);
        public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) => inner.CompleteAsync(sessionId, result, ct);
        public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) => inner.FindByStateAsync(state, ct);
    }
}
