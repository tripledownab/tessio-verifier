using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Proves the session-store seam the going-live guide documents: a custom
/// <see cref="IStateCorrelatingSessionStore"/> registered before AddTessioVerifier carries the full
/// MOCK-mode pipeline (create → wallet response → state correlation → verify → complete), a store
/// implementing only the base <see cref="ISessionStore"/> fails fast with a clear message, and a store
/// that kept less than the whole request has its callbacks refused rather than verified.
/// </summary>
public sealed class CustomSessionStoreTests
{
    /// <summary>
    /// A minimal external-store stand-in: same semantics a Redis/SQL-backed store would have, no
    /// reuse of InMemorySessionStore.
    /// </summary>
    private sealed class DictionarySessionStore : IStateCorrelatingSessionStore
    {
        private readonly IPresentationRequestBuilder _requestBuilder;
        private readonly Func<PresentationRequest, PresentationRequest>? _rewriteRequest;
        private readonly ConcurrentDictionary<string, VerificationSession> _sessions = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, string> _sessionIdByState = new(StringComparer.Ordinal);

        /// <param name="requestBuilder">Builds the request a created session carries.</param>
        /// <param name="rewriteRequest">
        /// What this store keeps of the built request. A parameter rather than a second store class, so
        /// the store that persists less than the whole request cannot drift from the one that persists
        /// all of it.
        /// </param>
        public DictionarySessionStore(
            IPresentationRequestBuilder requestBuilder,
            Func<PresentationRequest, PresentationRequest>? rewriteRequest = null)
        {
            _requestBuilder = requestBuilder;
            _rewriteRequest = rewriteRequest;
        }

        public async Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default)
        {
            var built = await _requestBuilder.BuildAsync(options, ct);
            var request = _rewriteRequest is null ? built : _rewriteRequest(built);
            var session = new VerificationSession
            {
                SessionId = Guid.NewGuid().ToString("N"),
                Request = request,
                Status = VerificationSessionStatus.Pending,
                Result = null,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = request.ExpiresAt,
            };
            _sessions[session.SessionId] = session;
            if (request.State is { } state)
            {
                _sessionIdByState[state] = session.SessionId;
            }

            return session;
        }

        public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) =>
            Task.FromResult(_sessions.TryGetValue(sessionId, out var session) ? session : null);

        public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) =>
            _sessionIdByState.TryGetValue(state, out var sessionId)
                ? GetAsync(sessionId, ct)
                : Task.FromResult<VerificationSession?>(null);

        public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default)
        {
            _sessions[sessionId] = _sessions[sessionId] with
            {
                Status = VerificationSessionStatus.Completed,
                Result = result,
            };
            return Task.CompletedTask;
        }
    }

    private sealed class NonCorrelatingStore : ISessionStore
    {
        public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) =>
            throw new NotSupportedException();

        public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    [Fact]
    public async Task MockMode_WithCustomStore_RunsFullPipeline()
    {
        var services = new ServiceCollection();
        // Register the replacement before AddTessioVerifier, exactly as the guide instructs.
        services.AddSingleton<ISessionStore>(
            sp => new DictionarySessionStore(sp.GetRequiredService<IPresentationRequestBuilder>()));
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);

        await using var provider = services.BuildServiceProvider();
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        try
        {
            var store = provider.GetRequiredService<ISessionStore>();
            Assert.IsType<DictionarySessionStore>(store);

            var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;

            // DirectPostJwt is the default, so the request needs an advertised encryption key. Through
            // the store, as MapTessioVerifier's /start does, because keys are ephemeral per request.
            var encryptionJwk = provider.GetRequiredService<ResponseEncryptionKeyStore>()
                .CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk;
            var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
                options, new Uri("https://verifier.example/verify/callback"), encryptionJwk));

            await provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);

            // No push notification on a custom store — poll, as the SSE endpoint does.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            VerificationSession? terminal;
            do
            {
                await Task.Delay(50, timeout.Token);
                terminal = await store.GetAsync(session.SessionId, timeout.Token);
            }
            while (terminal!.Status == VerificationSessionStatus.Pending);

            Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
            Assert.True(terminal.Result!.IsValid,
                string.Join("; ", terminal.Result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        }
        finally
        {
            foreach (var hosted in provider.GetServices<IHostedService>())
            {
                await hosted.StopAsync(CancellationToken.None);
            }
        }
    }

    /// <summary>
    /// What a host store looks like when it kept the session but not the request that created it: the
    /// authorization URI reduced to a bare start URL and no request object.
    /// </summary>
    private static PresentationRequest.ByValue Forget(PresentationRequest request) => new()
    {
        ClientId = request.ClientId,
        Nonce = request.Nonce,
        State = request.State,
        AuthorizationRequestUri = new Uri("https://verifier.example/start"),
        SignedRequestObject = "",
        ExpiresAt = request.ExpiresAt,
    };

    [Fact]
    public async Task Callback_WithAnUnreadableStoredRequest_RefusesInsteadOfVerifying()
    {
        // The credential here is a real, well-signed SD-JWT VC of a type this session never asked for.
        // Verifying it would not fail cleanly, it would accept it: the forgotten request yields no
        // ExpectedVct, and SdJwtVcVerifier compares the type only when one is set. Remove the guard in
        // WalletCallbackProcessor and this session completes VALID on the wrong credential.
        // Local, not a fixture field: minting an issuer costs a key pair and a certificate, and the other
        // tests in this class have no credential to sign.
        using var wallet = new MockWalletResponses();

        var services = new ServiceCollection();
        services.AddSingleton<ITrustListResolver>(
            new StaticTrustListResolver([MockWalletResponses.IssuerId], "test", [wallet.IssuerCertificate]));
        services.AddSingleton<ISessionStore>(sp => new DictionarySessionStore(
            sp.GetRequiredService<IPresentationRequestBuilder>(), Forget));
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);

        await using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ISessionStore>();
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            provider.GetRequiredService<IOptions<VerifierOptions>>().Value,
            new Uri("https://verifier.example/verify/callback")));

        var response = wallet.CreateSdJwtResponse(session, vct: "https://attacker.example/vct/anything");
        var outcome = await provider.GetRequiredService<WalletCallbackProcessor>()
            .ProcessAsync(response, CancellationToken.None);

        Assert.Equal(CallbackOutcome.SessionNotVerifiable, outcome.Outcome);

        // Still pending: a refusal must not spend the session's one completion.
        var after = await store.GetAsync(session.SessionId);
        Assert.Equal(VerificationSessionStatus.Pending, after!.Status);
    }

    [Fact]
    public void Store_WithoutStateCorrelation_FailsFastWithClearMessage()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISessionStore, NonCorrelatingStore>();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);

        using var provider = services.BuildServiceProvider();
        var ex = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<WalletCallbackProcessor>);
        Assert.Contains(nameof(IStateCorrelatingSessionStore), ex.Message, StringComparison.Ordinal);
    }
}
