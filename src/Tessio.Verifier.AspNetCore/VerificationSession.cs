using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Lifecycle states for a verification session.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). A failed verification (e.g., bad signature, untrusted issuer) is still
/// modeled as <see cref="Completed"/>; consult <see cref="VerificationResult.IsValid"/> for pass/fail.
/// Unless the deployment turns on <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/>, an opt-in that
/// keeps a session <see cref="Pending"/> after a failed verification, and so can end it as
/// <see cref="Expired"/> after responses arrived.
/// </remarks>
public enum VerificationSessionStatus
{
    /// <summary>Request issued; awaiting wallet response.</summary>
    Pending = 0,

    /// <summary>
    /// Verification ran and produced a <see cref="VerificationResult"/>. Inspect
    /// <see cref="VerificationResult.IsValid"/> to know whether the credential was accepted.
    /// </summary>
    Completed = 1,

    /// <summary>Session TTL elapsed before the wallet returned a response.</summary>
    Expired = 2,
}

/// <summary>
/// A verification session tracked by <see cref="ISessionStore"/>.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0).</remarks>
public sealed record VerificationSession
{
    /// <summary>
    /// Stable opaque session identifier; used as the SSE channel key and wallet-callback correlation.
    /// </summary>
    public required string SessionId { get; init; }

    /// <summary>The presentation request issued for this session.</summary>
    public required PresentationRequest Request { get; init; }

    /// <summary>Current lifecycle state.</summary>
    public required VerificationSessionStatus Status { get; init; }

    /// <summary>
    /// Verification result; non-null only when <see cref="Status"/> is
    /// <see cref="VerificationSessionStatus.Completed"/>.
    /// </summary>
    public VerificationResult? Result { get; init; }

    /// <summary>Session creation timestamp (UTC).</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Absolute session expiration (UTC). Stores should transition stale sessions to <see cref="VerificationSessionStatus.Expired"/>.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// The most recent response that failed verification while the session stayed
    /// <see cref="VerificationSessionStatus.Pending"/>, or null when there has been none.
    /// </summary>
    /// <remarks>
    /// Set by <see cref="IAttemptRecordingSessionStore.RecordFailedAttemptAsync"/>, which the built-in wallet
    /// callback calls only when <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> is on. With it off,
    /// a failing response completes the session and is read from <see cref="Result"/> instead. The built-in
    /// store keeps it after a later valid response completes the session. Added to this frozen record as an
    /// optional init-only property, which contracts-v0 permits.
    /// </remarks>
    public VerificationResult? LastFailure { get; init; }

    /// <summary>
    /// How many responses failed verification while the session stayed pending. Zero until the first.
    /// </summary>
    /// <remarks>
    /// Counted rather than inferred from <see cref="LastFailure"/>, because two failures can carry equal
    /// results and a reader watching for a new one needs something that always moves. Added to this
    /// frozen record as an optional init-only property, which contracts-v0 permits.
    /// </remarks>
    public int FailedAttempts { get; init; }
}
