using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// JSON-friendly projection of a <see cref="VerificationSession"/> for the status endpoint and SSE stream.
/// Deliberately excludes the raw signed request object.
/// </summary>
internal sealed record SessionView
{
    public required string SessionId { get; init; }

    public required string Status { get; init; }

    public required string AuthorizationRequestUri { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public VerificationResult? Result { get; init; }

    public static SessionView From(VerificationSession session) => new()
    {
        SessionId = session.SessionId,
        Status = session.Status.ToString().ToLowerInvariant(),
        AuthorizationRequestUri = session.Request.AuthorizationRequestUri.ToString(),
        ExpiresAt = session.ExpiresAt,
        Result = session.Result,
    };
}
