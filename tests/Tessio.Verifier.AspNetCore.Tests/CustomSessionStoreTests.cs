using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Proves the session-store seam the going-live guide documents: a custom
/// <see cref="IStateCorrelatingSessionStore"/> registered before AddTessioVerifier carries the full
/// MOCK-mode pipeline (create → wallet response → state correlation → verify → complete), and a store
/// implementing only the base <see cref="ISessionStore"/> fails fast with a clear message.
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
        private readonly ConcurrentDictionary<string, VerificationSession> _sessions = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, string> _sessionIdByState = new(StringComparer.Ordinal);

        public DictionarySessionStore(IPresentationRequestBuilder requestBuilder) => _requestBuilder = requestBuilder;

        public async Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default)
        {
            var request = await _requestBuilder.BuildAsync(options, ct);
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
            var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
                options, new Uri("https://verifier.example/verify/callback")));

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
