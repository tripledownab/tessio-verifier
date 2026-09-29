using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// An <see cref="ISessionStore"/> that can record a response which failed verification without completing
/// the session. Everything about a session's failed attempts, as opposed to its outcome, belongs here.
/// </summary>
/// <remarks>
/// <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> requires it: with that option on, the wallet
/// callback throws when it is first built against a store without it, rather than completing sessions
/// the option says to keep open. It is a separate interface because <see cref="ISessionStore"/> is
/// frozen, so a store written against contracts-v0 keeps compiling. The built-in
/// <see cref="InMemorySessionStore"/> implements it.
/// </remarks>
public interface IAttemptRecordingSessionStore : ISessionStore
{
    /// <summary>
    /// Records <paramref name="failure"/> as the session's <see cref="VerificationSession.LastFailure"/>
    /// and increments <see cref="VerificationSession.FailedAttempts"/>, leaving the session
    /// <see cref="VerificationSessionStatus.Pending"/>. Does nothing when the session is no longer pending,
    /// so a failure that loses a race with a valid response cannot overwrite it.
    /// </summary>
    Task RecordFailedAttemptAsync(string sessionId, VerificationResult failure, CancellationToken ct = default);
}
