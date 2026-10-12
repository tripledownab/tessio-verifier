using Microsoft.Extensions.Logging;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Structured log messages for the verifier pipeline. Session ids, states and error codes only;
/// never disclosed claims or credential contents (PII).
/// </summary>
/// <remarks>
/// A VALUE THE PRESENTER CHOSE IS MADE ONE LINE HERE, before it reaches a sink: a wallet's <c>state</c>,
/// an issuer identifier (an <c>iss</c>, or the subject of a presented certificate), a parser's message.
/// A plain-text sink would otherwise let a line break in one of them end the log line and start another.
/// The generated method for such an event is private and its public wrapper applies the rule, so a call
/// site cannot pass a raw value. Tests fail if a generated method that is not private takes anything but
/// this library's own values (a session id, error codes, a key-resolution method, its own words, an enum,
/// a time), and if anything in <c>src</c> logs other than through this class. What they cannot see is a
/// wrapper that forgets the rule, or a presenter's value passed under one of those names: a new event
/// carrying one needs a wrapper here and a test of its own.
/// </remarks>
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "Verification session {SessionId} created ({Mode} mode, expires {ExpiresAt:o})")]
    public static partial void SessionCreated(ILogger logger, string sessionId, VerifierMode mode, DateTimeOffset expiresAt);

    [LoggerMessage(EventId = 2, EventName = "CallbackParseFailed", Level = LogLevel.Warning,
        Message = "Wallet response could not be parsed and was rejected: {Reason}")]
    private static partial void CallbackParseFailedCore(ILogger logger, string reason);

    /// <summary>
    /// The parser's message rather than the exception. A sink renders an exception's own message
    /// separately from the template, raw, and the message can quote what the response declared.
    /// </summary>
    /// <remarks>
    /// The inner exceptions' types and messages are kept, made one line with the rest: a decryption
    /// failure is reported under one fixed sentence, and only the exception it wraps says whether the key,
    /// the tag or the sender's key was wrong. The stack is not kept; it is the parser's own frames.
    /// </remarks>
    public static void CallbackParseFailed(ILogger logger, Exception exception)
    {
        if (!logger.IsEnabled(LogLevel.Warning)) return;
        var reason = new System.Text.StringBuilder(exception.Message);
        for (var inner = exception.InnerException; inner is not null; inner = inner.InnerException)
        {
            reason.Append(" (").Append(inner.GetType().Name).Append(": ").Append(inner.Message).Append(')');
        }

        var oneLine = MessageText.OneLine(reason.ToString());
        CallbackParseFailedCore(logger, oneLine);
    }

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning,
        Message = "Wallet response carried no state parameter and was rejected")]
    public static partial void CallbackMissingState(ILogger logger);

    [LoggerMessage(EventId = 4, EventName = "CallbackUnknownState", Level = LogLevel.Warning,
        Message = "Wallet response state {State} matches no session (expired, evicted or forged) and was rejected")]
    private static partial void CallbackUnknownStateCore(ILogger logger, string state);

    /// <summary>The state is the wallet's, so it is made one line.</summary>
    public static void CallbackUnknownState(ILogger logger, string state)
    {
        if (!logger.IsEnabled(LogLevel.Warning)) return;
        var oneLine = MessageText.OneLine(state);
        CallbackUnknownStateCore(logger, oneLine);
    }

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning,
        Message = "Wallet response for session {SessionId} arrived while the session was {Status}; sessions complete once (replay protection)")]
    public static partial void CallbackNotPending(ILogger logger, string sessionId, VerificationSessionStatus status);

    [LoggerMessage(EventId = 6, EventName = "VerificationSucceeded", Level = LogLevel.Information,
        Message = "Session {SessionId} completed: credential valid (issuer {Issuer}, key via {KeyResolutionMethod})")]
    private static partial void VerificationSucceededCore(ILogger logger, string sessionId, string issuer, string keyResolutionMethod);

    /// <summary>The issuer identifier is the presenter's, so it is made one line.</summary>
    public static void VerificationSucceeded(ILogger logger, string sessionId, string issuer, string keyResolutionMethod)
    {
        if (!logger.IsEnabled(LogLevel.Information)) return;
        var oneLine = MessageText.OneLine(issuer);
        VerificationSucceededCore(logger, sessionId, oneLine, keyResolutionMethod);
    }

    [LoggerMessage(EventId = 7, EventName = "VerificationFailed", Level = LogLevel.Warning,
        Message = "Session {SessionId} completed: credential INVALID (issuer {Issuer}, errors: {ErrorCodes})")]
    private static partial void VerificationFailedCore(ILogger logger, string sessionId, string issuer, string errorCodes);

    /// <summary>The issuer identifier is the presenter's, so it is made one line.</summary>
    public static void VerificationFailed(ILogger logger, string sessionId, string issuer, string errorCodes)
    {
        if (!logger.IsEnabled(LogLevel.Warning)) return;
        var oneLine = MessageText.OneLine(issuer);
        VerificationFailedCore(logger, sessionId, oneLine, errorCodes);
    }

    [LoggerMessage(EventId = 8, Level = LogLevel.Error,
        Message = "Session {SessionId} carries no readable request parameters, so a wallet response cannot be checked against what was asked for")]
    public static partial void CallbackSessionNotVerifiable(ILogger logger, string sessionId);

    [LoggerMessage(EventId = 9, Level = LogLevel.Warning,
        Message = "Wallet response for session {SessionId} arrived {Arrived} but the request asked for {Asked}, so it was rejected without ending the session")]
    public static partial void CallbackWrongResponseMode(ILogger logger, string sessionId, string arrived, string asked);

    [LoggerMessage(EventId = 10, EventName = "VerificationFailedSessionKept", Level = LogLevel.Warning,
        Message = "Session {SessionId} stays pending: credential INVALID (issuer {Issuer}, errors: {ErrorCodes}), recorded as a failed attempt")]
    private static partial void VerificationFailedSessionKeptCore(ILogger logger, string sessionId, string issuer, string errorCodes);

    /// <summary>The issuer identifier is the presenter's, so it is made one line.</summary>
    public static void VerificationFailedSessionKept(ILogger logger, string sessionId, string issuer, string errorCodes)
    {
        if (!logger.IsEnabled(LogLevel.Warning)) return;
        var oneLine = MessageText.OneLine(issuer);
        VerificationFailedSessionKeptCore(logger, sessionId, oneLine, errorCodes);
    }

    [LoggerMessage(Level = LogLevel.Error,
        Message = "Mock wallet failed for session {SessionId}.")]
    public static partial void MockWalletFailed(ILogger logger, Exception exception, string sessionId);
}
