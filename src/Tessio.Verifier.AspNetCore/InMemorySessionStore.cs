using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Default in-memory <see cref="ISessionStore"/>. Suitable for a single-process app, the demo, and tests.
/// Production deployments swap in a distributed store (Redis, SQL, …).
/// </summary>
public sealed class InMemorySessionStore : IStateCorrelatingSessionStore, IAttemptRecordingSessionStore
{
    /// <summary>
    /// How long a session stays readable after <see cref="VerificationSession.ExpiresAt"/> before it
    /// is evicted. Gives result-page clients time to read a terminal state.
    /// </summary>
    private static readonly TimeSpan EvictionRetention = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _sessionIdByState = new(StringComparer.Ordinal);
    private readonly IPresentationRequestBuilder _requestBuilder;
    private readonly TimeProvider _clock;

    /// <summary>Creates the store.</summary>
    public InMemorySessionStore(IPresentationRequestBuilder requestBuilder, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(requestBuilder);
        ArgumentNullException.ThrowIfNull(clock);
        _requestBuilder = requestBuilder;
        _clock = clock;
    }

    /// <inheritdoc />
    public async Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        EvictStaleSessions();

        var request = await _requestBuilder.BuildAsync(options, ct).ConfigureAwait(false);
        var session = new VerificationSession
        {
            SessionId = Tokens.NewSessionId(),
            Request = request,
            Status = VerificationSessionStatus.Pending,
            Result = null,
            CreatedAt = _clock.GetUtcNow(),
            ExpiresAt = request.ExpiresAt,
        };

        _sessions[session.SessionId] = new SessionEntry(session);
        if (request.State is { } state)
        {
            _sessionIdByState[state] = session.SessionId;
        }

        return session;
    }

    /// <inheritdoc />
    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        return _sessionIdByState.TryGetValue(state, out var sessionId)
            ? GetAsync(sessionId, ct)
            : Task.FromResult<VerificationSession?>(null);
    }

    /// <inheritdoc />
    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);

        return Task.FromResult<VerificationSession?>(_sessions.TryGetValue(sessionId, out var entry)
            ? EvaluateExpiry(entry)
            : null);
    }

    /// <inheritdoc />
    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(result);

        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            throw new KeyNotFoundException($"No verification session with id '{sessionId}'.");
        }

        entry.Complete(result);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RecordFailedAttemptAsync(string sessionId, VerificationResult failure, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(failure);

        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            throw new KeyNotFoundException($"No verification session with id '{sessionId}'.");
        }

        entry.RecordFailure(failure);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Awaits any change to the session after <paramref name="seen"/>: a recorded failure, completion or
    /// expiry. Returns at once when the session has already moved on. Used by the SSE stream.
    /// </summary>
    internal Task<VerificationSession> WaitForChangeAsync(string sessionId, VerificationSession seen, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            throw new KeyNotFoundException($"No verification session with id '{sessionId}'.");
        }

        EvaluateExpiry(entry);
        return entry.NextChangeAfter(seen).WaitAsync(ct);
    }

    /// <summary>
    /// Awaits the session reaching a terminal state (<see cref="VerificationSessionStatus.Completed"/> or
    /// <see cref="VerificationSessionStatus.Expired"/>), ignoring recorded failures. The SSE stream uses
    /// <see cref="WaitForChangeAsync"/> instead, so this serves callers that want only the outcome.
    /// </summary>
    internal async Task<VerificationSession> WaitForTerminalAsync(string sessionId, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            throw new KeyNotFoundException($"No verification session with id '{sessionId}'.");
        }

        var current = EvaluateExpiry(entry);
        if (current.Status != VerificationSessionStatus.Pending)
        {
            return current;
        }

        return await entry.Terminal.Task.WaitAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Removes sessions past their expiry plus a retention window, so a long-running process does not
    /// grow without bound. Runs opportunistically on every create; O(n) over live sessions, which is
    /// fine at the scale an in-memory store is meant for.
    /// </summary>
    private void EvictStaleSessions()
    {
        var cutoff = _clock.GetUtcNow() - EvictionRetention;
        foreach (var (sessionId, entry) in _sessions)
        {
            var session = entry.Current;
            if (session.ExpiresAt < cutoff)
            {
                _sessions.TryRemove(sessionId, out _);
                if (session.Request.State is { } state)
                {
                    _sessionIdByState.TryRemove(state, out _);
                }
            }
        }
    }

    private VerificationSession EvaluateExpiry(SessionEntry entry)
    {
        var session = entry.Current;
        if (session.Status == VerificationSessionStatus.Pending && _clock.GetUtcNow() >= session.ExpiresAt)
        {
            return entry.Expire();
        }

        return session;
    }

    private sealed class SessionEntry
    {
        private readonly object _gate = new();
        private VerificationSession _current;
        private TaskCompletionSource<VerificationSession> _changed = NewSignal();

        public SessionEntry(VerificationSession initial) => _current = initial;

        public TaskCompletionSource<VerificationSession> Terminal { get; } = NewSignal();

        public VerificationSession Current
        {
            get { lock (_gate) { return _current; } }
        }

        /// <summary>The session as it is now if it differs from <paramref name="seen"/>, else the next change.</summary>
        public Task<VerificationSession> NextChangeAfter(VerificationSession seen)
        {
            lock (_gate)
            {
                return ReferenceEquals(_current, seen) ? _changed.Task : Task.FromResult(_current);
            }
        }

        public void Complete(VerificationResult result)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending)
                {
                    return;
                }

                Publish(_current with { Status = VerificationSessionStatus.Completed, Result = result });
                Terminal.TrySetResult(_current);
            }
        }

        public void RecordFailure(VerificationResult failure)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending)
                {
                    return;
                }

                Publish(_current with { LastFailure = failure, FailedAttempts = _current.FailedAttempts + 1 });
            }
        }

        public VerificationSession Expire()
        {
            lock (_gate)
            {
                if (_current.Status == VerificationSessionStatus.Pending)
                {
                    Publish(_current with { Status = VerificationSessionStatus.Expired });
                    Terminal.TrySetResult(_current);
                }

                return _current;
            }
        }

        // Called under _gate. Replaces the signal before releasing the old one, so a waiter woken here
        // that asks again waits for the NEXT change rather than returning this one twice.
        private void Publish(VerificationSession next)
        {
            _current = next;
            var released = _changed;
            _changed = NewSignal();
            released.TrySetResult(next);
        }

        private static TaskCompletionSource<VerificationSession> NewSignal() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
