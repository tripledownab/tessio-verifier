using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The callback pipeline leaves an operator-usable trace: rejections log a warning with the cause,
/// completions log the outcome with error codes. Never disclosed claims.
/// </summary>
public sealed class LoggingTests
{
    private sealed record LogRecord(string Category, LogLevel Level, string Message);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<LogRecord> Records { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Records);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(string category, ConcurrentQueue<LogRecord> records) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                records.Enqueue(new LogRecord(category, logLevel, formatter(state, exception)));
        }
    }

    private static (ServiceProvider Provider, CapturingLoggerProvider Logs) BuildProvider()
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(logs));
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        return (services.BuildServiceProvider(), logs);
    }

    [Fact]
    public async Task RejectedCallback_LogsWarning_WithUnknownState()
    {
        var (provider, logs) = BuildProvider();
        await using var _ = provider;

        var processor = provider.GetRequiredService<WalletCallbackProcessor>();
        await processor.ProcessAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { """{"credential":["a.b.c~"]}""" },
                ["state"] = new[] { "no-such-state" },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        }, CancellationToken.None);

        var warning = Assert.Single(logs.Records, r => r.Level == LogLevel.Warning);
        Assert.Contains("no-such-state", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidCredential_LogsWarning_WithErrorCodes_ButNoClaims()
    {
        var (provider, logs) = BuildProvider();
        await using var _ = provider;

        var store = provider.GetRequiredService<InMemorySessionStore>();
        var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();
        var processor = provider.GetRequiredService<WalletCallbackProcessor>();

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // Wrong nonce → verification fails with nonce_mismatch.
        var replayed = issuer.IssuePresentation(
            ["given_name"], DemoRequestOptionsFactory.DefaultVct, nonce: "wrong-nonce", audience: options.ClientId);

        await processor.ProcessAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{replayed}}"]}""" },
                ["state"] = new[] { session.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        }, CancellationToken.None);

        var failure = Assert.Single(logs.Records, r => r.Level == LogLevel.Warning);
        Assert.Contains("nonce_mismatch", failure.Message, StringComparison.Ordinal);
        Assert.Contains(session.SessionId, failure.Message, StringComparison.Ordinal);
        // The disclosed claim value ("Erika") must never reach the logs.
        Assert.DoesNotContain(logs.Records, r => r.Message.Contains("Erika", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ValidCredential_LogsCompletion_AtInformation()
    {
        var (provider, logs) = BuildProvider();
        await using var _ = provider;

        var store = provider.GetRequiredService<InMemorySessionStore>();
        var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();
        var processor = provider.GetRequiredService<WalletCallbackProcessor>();

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, session.Request.Nonce, options.ClientId);

        await processor.ProcessAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                ["state"] = new[] { session.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        }, CancellationToken.None);

        var completion = Assert.Single(logs.Records,
            r => r.Level == LogLevel.Information && r.Message.Contains("valid", StringComparison.Ordinal));
        Assert.Contains(session.SessionId, completion.Message, StringComparison.Ordinal);
        Assert.Contains(MockCredentialIssuer.Issuer, completion.Message, StringComparison.Ordinal);
    }
}
