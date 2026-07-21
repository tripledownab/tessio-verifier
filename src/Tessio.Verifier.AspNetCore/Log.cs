using Microsoft.Extensions.Logging;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Structured log messages for the verifier pipeline. Session ids, states and error codes only;
/// never disclosed claims or credential contents (PII).
/// </summary>
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "Verification session {SessionId} created ({Mode} mode, expires {ExpiresAt:o})")]
    public static partial void SessionCreated(ILogger logger, string sessionId, VerifierMode mode, DateTimeOffset expiresAt);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning,
        Message = "Wallet response could not be parsed and was rejected")]
    public static partial void CallbackParseFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning,
        Message = "Wallet response carried no state parameter and was rejected")]
    public static partial void CallbackMissingState(ILogger logger);

    [LoggerMessage(EventId = 4, Level = LogLevel.Warning,
        Message = "Wallet response state {State} matches no session (expired, evicted or forged) and was rejected")]
    public static partial void CallbackUnknownState(ILogger logger, string state);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning,
        Message = "Wallet response for session {SessionId} arrived while the session was {Status}; sessions complete once (replay protection)")]
    public static partial void CallbackNotPending(ILogger logger, string sessionId, VerificationSessionStatus status);

    [LoggerMessage(EventId = 6, Level = LogLevel.Information,
        Message = "Session {SessionId} completed: credential valid (issuer {Issuer}, key via {KeyResolutionMethod})")]
    public static partial void VerificationSucceeded(ILogger logger, string sessionId, string issuer, string keyResolutionMethod);

    [LoggerMessage(EventId = 7, Level = LogLevel.Warning,
        Message = "Session {SessionId} completed: credential INVALID (issuer {Issuer}, errors: {ErrorCodes})")]
    public static partial void VerificationFailed(ILogger logger, string sessionId, string issuer, string errorCodes);
}
