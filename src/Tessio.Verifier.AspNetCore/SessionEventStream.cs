using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The anonymous SSE stream for one session, <c>GET {prefix}/{sessionId}/stream</c>. Everything about
/// which events it sends, and how it waits for the next one, belongs here.
/// </summary>
/// <remarks>
/// Events, in order: <c>pending</c> once, <c>attempt_failed</c> each time the stream sees
/// <see cref="VerificationSession.FailedAttempts"/> rise (only with
/// <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> on), then one of <c>completed</c> or
/// <c>expired</c>. Failures close together can share one <c>attempt_failed</c>, and failures before the
/// stream opened send none, so a reader takes the count from the payload. Every event carries the same
/// <see cref="SessionView"/> as the status resource.
/// </remarks>
internal static class SessionEventStream
{
    /// <summary>
    /// How often a store without push notification is re-read. The in-memory store pushes, so this only
    /// governs a host's own store, where each poll is a read against it.
    /// </summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    public static async Task StreamAsync(string sessionId, HttpContext http, JsonSerializerOptions serializerOptions)
    {
        var store = http.RequestServices.GetRequiredService<ISessionStore>();
        var session = await store.GetAsync(sessionId, http.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        http.Response.ContentType = "text/event-stream";
        // no-store, as on the status resource: the same verdict and claims travel on this stream.
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers["X-Accel-Buffering"] = "no";

        await WriteEventAsync(http, "pending", session, serializerOptions).ConfigureAwait(false);

        while (session.Status == VerificationSessionStatus.Pending)
        {
            var (next, atDeadline) = await AwaitChangeAsync(store, session, http).ConfigureAwait(false);
            if (next is null)
            {
                return; // client disconnected, or the session is gone
            }

            if (next.Status == VerificationSessionStatus.Pending && next.FailedAttempts > session.FailedAttempts)
            {
                await WriteEventAsync(http, "attempt_failed", next, serializerOptions).ConfigureAwait(false);
            }

            session = next;
            if (atDeadline)
            {
                // The session's lifetime is over. Whatever the store reports now is the last word, even a
                // host store that has not yet moved it out of pending, so the stream ends here as before.
                break;
            }
        }

        var eventName = session.Status == VerificationSessionStatus.Completed ? "completed" : "expired";
        await WriteEventAsync(http, eventName, session, serializerOptions).ConfigureAwait(false);
    }

    /// <summary>
    /// The session once it differs from <paramref name="seen"/> by status or failed attempts, or as it
    /// reads when its lifetime ends (<c>AtDeadline</c> true). A null session means the client went away
    /// or the store no longer has it.
    /// </summary>
    private static async Task<(VerificationSession? Session, bool AtDeadline)> AwaitChangeAsync(
        ISessionStore store, VerificationSession seen, HttpContext http)
    {
        var clock = http.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;
        var remaining = seen.ExpiresAt - clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
        {
            return (await store.GetAsync(seen.SessionId, http.RequestAborted).ConfigureAwait(false), true);
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted);
        deadline.CancelAfter(remaining);

        try
        {
            // The in-memory store pushes each change. Any other store is polled.
            var changed = store is InMemorySessionStore inMemory
                ? await inMemory.WaitForChangeAsync(seen.SessionId, seen, deadline.Token).ConfigureAwait(false)
                : await PollUntilChangedAsync(store, seen, deadline.Token).ConfigureAwait(false);
            return (changed, false);
        }
        catch (OperationCanceledException) when (!http.RequestAborted.IsCancellationRequested)
        {
            // Session lifetime elapsed: re-read to surface the Expired transition.
            return (await store.GetAsync(seen.SessionId, CancellationToken.None).ConfigureAwait(false), true);
        }
        catch (OperationCanceledException)
        {
            return (null, false); // client disconnected
        }
    }

    private static async Task<VerificationSession?> PollUntilChangedAsync(ISessionStore store, VerificationSession seen, CancellationToken ct)
    {
        while (true)
        {
            var current = await store.GetAsync(seen.SessionId, ct).ConfigureAwait(false);
            if (current is null || current.Status != seen.Status || current.FailedAttempts != seen.FailedAttempts)
            {
                return current;
            }

            await Task.Delay(PollInterval, ct).ConfigureAwait(false);
        }
    }

    private static async Task WriteEventAsync(HttpContext http, string eventName, VerificationSession session, JsonSerializerOptions serializerOptions)
    {
        // The SSE stream carries the same projection as the status resource, through the same narrowing.
        // Two write paths for one view is how an anonymous surface ends up disclosing on one and not the
        // other, so both go through SessionView.From and neither serialises the result directly.
        var options = http.RequestServices.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var json = JsonSerializer.Serialize(SessionView.From(session, options.PublicTrustListSources), serializerOptions);
        await http.Response.WriteAsync($"event: {eventName}\ndata: {json}\n\n", http.RequestAborted).ConfigureAwait(false);
        await http.Response.Body.FlushAsync(http.RequestAborted).ConfigureAwait(false);
    }
}
