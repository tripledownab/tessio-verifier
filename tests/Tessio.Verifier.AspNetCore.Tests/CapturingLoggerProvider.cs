using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Tessio.Verifier.AspNetCore.Tests;

// A logger provider that keeps every record, for tests that assert on what was logged.
internal sealed record LogRecord(string Category, LogLevel Level, string Message, Exception? Exception = null, string? EventName = null);

internal sealed class CapturingLoggerProvider(Func<LogLevel, bool>? enabled = null) : ILoggerProvider
{
    public ConcurrentQueue<LogRecord> Records { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Records, enabled ?? (_ => true));

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(string category, ConcurrentQueue<LogRecord> records, Func<LogLevel, bool> enabled) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => enabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            records.Enqueue(new LogRecord(category, logLevel, formatter(state, exception), exception, eventId.Name));
    }
}
