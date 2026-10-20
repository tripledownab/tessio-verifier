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

        var encryptionJwk = options.ResponseMode == ResponseMode.DirectPostJwt
            ? provider.GetRequiredService<ResponseEncryptionKeyStore>()
                .CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk
            : null;
        // This test posts a plaintext form, so its request asks for a plaintext response: a callback in
        // the wrong mode is refused before it can end the session.
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback"), encryptionJwk) with { ResponseMode = ResponseMode.DirectPost });

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

        var encryptionJwk = options.ResponseMode == ResponseMode.DirectPostJwt
            ? provider.GetRequiredService<ResponseEncryptionKeyStore>()
                .CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk
            : null;
        // This test posts a plaintext form, so its request asks for a plaintext response: a callback in
        // the wrong mode is refused before it can end the session.
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback"), encryptionJwk) with { ResponseMode = ResponseMode.DirectPost });
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

    // Line feed, carriage return, NEL (a C1 control), and the two Unicode line separators.
    private const string Hostile = "Evil\nINFO: forged\r\u0085next\u2028and\u2029end";

    private static void AssertOneLine(string message)
    {
        Assert.DoesNotContain(message, c => char.IsControl(c) || c is '\u2028' or '\u2029');
        Assert.Contains("Evil" + "\uFFFD" + "INFO: forged", message, StringComparison.Ordinal);
    }

    private static (ILogger Logger, CapturingLoggerProvider Logs) Capture(Func<LogLevel, bool>? enabled = null)
    {
        var logs = new CapturingLoggerProvider(enabled);
        return (logs.CreateLogger("test"), logs);
    }

    [Fact]
    public async Task AnUnknownStateIsLoggedOnOneLine()
    {
        var (provider, logs) = BuildProvider();
        await using var _ = provider;

        await provider.GetRequiredService<WalletCallbackProcessor>().ProcessAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { """{"credential":["a.b.c~"]}""" },
                ["state"] = new[] { Hostile },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        }, CancellationToken.None);

        AssertOneLine(Assert.Single(logs.Records, r => r.Level == LogLevel.Warning).Message);
    }

    /// <summary>
    /// The three events that name the issuer. The mock issuer's identifier is fixed, so these call the
    /// wrappers the processor calls rather than drive a presentation through it.
    /// </summary>
    [Fact]
    public void AnIssuerIdentifierIsLoggedOnOneLine()
    {
        var (logger, logs) = Capture();

        Log.VerificationSucceeded(logger, "session", Hostile, "x5c");
        Log.VerificationFailed(logger, "session", Hostile, "code");
        Log.VerificationFailedSessionKept(logger, "session", Hostile, "code");

        Assert.Equal(3, logs.Records.Count);
        foreach (var record in logs.Records)
        {
            AssertOneLine(record.Message);
        }

        // The wrapped events keep the names they had before they were wrapped, which a sink may key on.
        Assert.Equal(["VerificationSucceeded", "VerificationFailed", "VerificationFailedSessionKept"], logs.Records.Select(r => r.EventName));
    }

    /// <summary>
    /// A parse failure logs the parser's message on one line and not the exception: a sink renders an
    /// exception's own message outside the template, raw.
    /// </summary>
    [Fact]
    public void AParseFailureIsLoggedOnOneLine_WithoutTheException()
    {
        var (logger, logs) = Capture();

        Log.CallbackParseFailed(logger, new WalletResponseException($"Unsupported content encryption '{Hostile}'."));

        var record = Assert.Single(logs.Records);
        AssertOneLine(record.Message);
        Assert.Null(record.Exception);
        Assert.Equal("CallbackParseFailed", record.EventName);
    }

    /// <summary>
    /// A decryption failure is reported under one fixed sentence, and only the exception it wraps says why,
    /// so the inner exceptions are kept: their types and messages, on the same line.
    /// </summary>
    [Fact]
    public void AParseFailureKeepsTheCauseItWraps()
    {
        var (logger, logs) = Capture();

        Log.CallbackParseFailed(logger, new WalletResponseException(
            "The response could not be decrypted with the configured key.",
            new System.Security.Cryptography.CryptographicException($"The tag did not match: {Hostile}")));

        var record = Assert.Single(logs.Records);
        AssertOneLine(record.Message);
        Assert.Contains("(CryptographicException: The tag did not match: Evil", record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Each wrapper asks the logger about its own event's level. A logger that enables that level and no
    /// other must receive the event, so a wrapper that asked about a different level fails here.
    /// </summary>
    [Fact]
    public void EachWrapperLogsAtItsOwnEventsLevel()
    {
        (LogLevel Level, Action<ILogger> Write)[] events =
        [
            (LogLevel.Warning, l => Log.CallbackParseFailed(l, new WalletResponseException("x"))),
            (LogLevel.Warning, l => Log.CallbackUnknownState(l, "state")),
            (LogLevel.Information, l => Log.VerificationSucceeded(l, "session", "issuer", "x5c")),
            (LogLevel.Warning, l => Log.VerificationFailed(l, "session", "issuer", "code")),
            (LogLevel.Warning, l => Log.VerificationFailedSessionKept(l, "session", "issuer", "code")),
        ];

        foreach (var (level, write) in events)
        {
            var (logger, logs) = Capture(enabled => enabled == level);
            write(logger);
            Assert.Equal(level, Assert.Single(logs.Records).Level);
        }
    }

    /// <summary>
    /// Every log event a call site can reach directly takes only values this library chose. An event that
    /// carries a presenter's value is generated private and reached through a wrapper that makes the value
    /// one line, so a new event taking anything else fails here until it is one or the other. Internal
    /// counts as reachable: the class itself is internal, so internal and public reach the same callers.
    /// </summary>
    [Fact]
    public void EveryReachableLogEvent_TakesOnlyTheLibrarysOwnValues()
    {
        // The library's own: ids it minted, codes and methods it named, words it wrote.
        // storeType is the host's, not a presenter's: the name of the session store type it registered.
        string[] ownStrings = ["sessionId", "errorCodes", "keyResolutionMethod", "arrived", "asked", "storeType"];
        // The mock wallet's exception comes from its own credential and its own pipeline, not a presenter.
        string[] ownExceptions = ["MockWalletFailed"];

        bool Allowed(System.Reflection.MethodInfo method, System.Reflection.ParameterInfo p) =>
            p.ParameterType == typeof(ILogger)
            || p.ParameterType.IsEnum
            || p.ParameterType == typeof(DateTimeOffset)
            || (p.ParameterType == typeof(string) && ownStrings.Contains(p.Name))
            || (typeof(Exception).IsAssignableFrom(p.ParameterType) && ownExceptions.Contains(method.Name));

        var generated = typeof(Log)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
            .Where(m => m.GetCustomAttributes(typeof(LoggerMessageAttribute), false).Length > 0)
            .ToList();
        Assert.NotEmpty(generated);

        var offenders = generated
            .Where(m => !m.IsPrivate)
            .SelectMany(m => m.GetParameters().Where(p => !Allowed(m, p)).Select(p => $"{m.Name}({p.Name})"))
            .ToList();

        Assert.True(offenders.Count == 0,
            "These log events take a value the library did not choose. Make the generated method private "
            + "and add a wrapper that passes the value through MessageText.OneLine: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// Log.cs is the only place in the library that logs, so its rule covers every log line. A direct logger
    /// call or a generated event declared elsewhere would bypass it.
    /// </summary>
    [Fact]
    public void NothingInTheLibraryLogsExceptThroughLog()
    {
        var src = Path.Combine(RepositoryRoot(), "src");
        var logging = new System.Text.RegularExpressions.Regex(
            @"\b(Log(Trace|Debug|Information|Warning|Error|Critical)|BeginScope)\s*(<[^>]*>)?\s*\(|\[LoggerMessage\b");
        var offenders = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => Path.GetRelativePath(src, f) != Path.Combine("Tessio.Verifier.AspNetCore", "Log.cs"))
            .Where(f => logging.IsMatch(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(src, f))
            .ToList();

        Assert.True(offenders.Count == 0,
            "These log other than through Log.cs, so a presenter's value in them is not made one line: "
            + string.Join(", ", offenders));
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Tessio.Verifier.sln"))) return dir.FullName;
        }

        throw new InvalidOperationException("Tessio.Verifier.sln not found above the test assembly.");
    }
}
