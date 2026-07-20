using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Maps the Tessio verifier endpoints onto an <see cref="IEndpointRouteBuilder"/>.
/// </summary>
public static class TessioVerifierEndpointRouteBuilderExtensions
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Maps, under the configured route prefix (default <c>/verify</c>):
    /// <list type="bullet">
    /// <item><description><c>GET {prefix}/start</c> — create a session and render the request page.</description></item>
    /// <item><description><c>GET {prefix}/{sessionId}</c> — session status as JSON.</description></item>
    /// <item><description><c>GET {prefix}/{sessionId}/stream</c> — result as Server-Sent Events.</description></item>
    /// <item><description><c>POST {prefix}/callback</c> — wallet response callback (live modes).</description></item>
    /// </list>
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="routePrefix">Overrides <see cref="VerifierOptions.RoutePrefix"/> when supplied.</param>
    public static IEndpointRouteBuilder MapTessioVerifier(this IEndpointRouteBuilder endpoints, string? routePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var prefix = NormalizePrefix(routePrefix ?? options.RoutePrefix);

        endpoints.MapGet($"{prefix}/start", (HttpContext http) => StartAsync(http, prefix));
        endpoints.MapGet($"{prefix}/{{sessionId}}", (string sessionId, HttpContext http) => GetStatusAsync(sessionId, http));
        endpoints.MapGet($"{prefix}/{{sessionId}}/stream", (string sessionId, HttpContext http) => StreamAsync(sessionId, http));
        endpoints.MapPost($"{prefix}/callback", CallbackAsync);

        return endpoints;
    }

    private static async Task StartAsync(HttpContext http, string prefix)
    {
        var options = http.RequestServices.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var store = http.RequestServices.GetRequiredService<ISessionStore>();

        var responseUri = new Uri($"{http.Request.Scheme}://{http.Request.Host}{prefix}/callback");
        var requestOptions = DemoRequestOptionsFactory.Create(options, responseUri);
        var session = await store.CreateAsync(requestOptions, http.RequestAborted).ConfigureAwait(false);

        if (options.Mode == VerifierMode.Demo)
        {
            var queue = http.RequestServices.GetRequiredService<DemoCompletionQueue>();
            await queue.EnqueueAsync(session.SessionId, http.RequestAborted).ConfigureAwait(false);
        }

        var html = RenderStartPage(session.SessionId, prefix, options.Mode, session.Request.AuthorizationRequestUri.ToString());
        http.Response.ContentType = "text/html; charset=utf-8";
        await http.Response.WriteAsync(html, http.RequestAborted).ConfigureAwait(false);
    }

    private static async Task GetStatusAsync(string sessionId, HttpContext http)
    {
        var store = http.RequestServices.GetRequiredService<ISessionStore>();
        var session = await store.GetAsync(sessionId, http.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await http.Response.WriteAsJsonAsync(SessionView.From(session), SerializerOptions, http.RequestAborted).ConfigureAwait(false);
    }

    private static async Task StreamAsync(string sessionId, HttpContext http)
    {
        var store = http.RequestServices.GetRequiredService<ISessionStore>();
        var session = await store.GetAsync(sessionId, http.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        http.Response.ContentType = "text/event-stream";
        http.Response.Headers.CacheControl = "no-cache";
        http.Response.Headers["X-Accel-Buffering"] = "no";

        await WriteEventAsync(http, "pending", session).ConfigureAwait(false);

        var terminal = session.Status != VerificationSessionStatus.Pending
            ? session
            : await AwaitTerminalAsync(store, sessionId, session.ExpiresAt, http).ConfigureAwait(false);

        if (terminal is null)
        {
            return; // client disconnected
        }

        var eventName = terminal.Status == VerificationSessionStatus.Completed ? "completed" : "expired";
        await WriteEventAsync(http, eventName, terminal).ConfigureAwait(false);
    }

    private static async Task<VerificationSession?> AwaitTerminalAsync(
        ISessionStore store, string sessionId, DateTimeOffset expiresAt, HttpContext http)
    {
        var clock = http.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;
        var remaining = expiresAt - clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
        {
            return await store.GetAsync(sessionId, http.RequestAborted).ConfigureAwait(false);
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted);
        deadline.CancelAfter(remaining);

        try
        {
            var inMemory = http.RequestServices.GetService<InMemorySessionStore>();
            if (inMemory is not null)
            {
                return await inMemory.WaitForTerminalAsync(sessionId, deadline.Token).ConfigureAwait(false);
            }

            return await PollUntilTerminalAsync(store, sessionId, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!http.RequestAborted.IsCancellationRequested)
        {
            // Session lifetime elapsed — re-read to surface the Expired transition.
            return await store.GetAsync(sessionId, CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null; // client disconnected
        }
    }

    private static async Task<VerificationSession> PollUntilTerminalAsync(ISessionStore store, string sessionId, CancellationToken ct)
    {
        while (true)
        {
            var session = await store.GetAsync(sessionId, ct).ConfigureAwait(false);
            if (session is null || session.Status != VerificationSessionStatus.Pending)
            {
                return session!;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
        }
    }

    private static async Task CallbackAsync(HttpContext http)
    {
        // Live wallet callback (direct_post / direct_post.jwt) requires the OpenID4VP response parser and the
        // Core verifier, which are not part of this DEMO slice. DEMO mode completes without a callback.
        http.Response.StatusCode = StatusCodes.Status501NotImplemented;
        await http.Response.WriteAsJsonAsync(
            new
            {
                error = "wallet_callback_unavailable",
                message = "Live wallet callback needs Tessio.Verifier.OpenId4Vp response parsing and " +
                          "Tessio.Verifier.Core verification (not wired in this build). DEMO mode completes automatically.",
            },
            SerializerOptions,
            http.RequestAborted).ConfigureAwait(false);
    }

    private static async Task WriteEventAsync(HttpContext http, string eventName, VerificationSession session)
    {
        var json = JsonSerializer.Serialize(SessionView.From(session), SerializerOptions);
        await http.Response.WriteAsync($"event: {eventName}\ndata: {json}\n\n", http.RequestAborted).ConfigureAwait(false);
        await http.Response.Body.FlushAsync(http.RequestAborted).ConfigureAwait(false);
    }

    private static string NormalizePrefix(string prefix)
    {
        prefix = prefix.Trim();
        if (!prefix.StartsWith('/'))
        {
            prefix = "/" + prefix;
        }

        return prefix.TrimEnd('/');
    }

    private static string RenderStartPage(string sessionId, string prefix, VerifierMode mode, string authorizationRequestUri) =>
        StartPageTemplate
            .Replace("__STREAM_URL__", $"{prefix}/{sessionId}/stream", StringComparison.Ordinal)
            .Replace("__STATUS_URL__", $"{prefix}/{sessionId}", StringComparison.Ordinal)
            .Replace("__SESSION_ID__", WebUtility.HtmlEncode(sessionId), StringComparison.Ordinal)
            .Replace("__MODE__", WebUtility.HtmlEncode(mode.ToString()), StringComparison.Ordinal)
            .Replace("__AUTH_URI__", WebUtility.HtmlEncode(authorizationRequestUri), StringComparison.Ordinal);

    private const string StartPageTemplate = """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Tessio.Verifier — verification</title>
          <style>
            :root { color-scheme: light dark; }
            body { font: 15px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
            h1 { font-size: 1.4rem; margin-bottom: .25rem; }
            .badge { display: inline-block; padding: .1rem .5rem; border-radius: 1rem; background: #5b6cff; color: #fff; font-size: .75rem; font-weight: 600; }
            .status { font-size: 1.1rem; font-weight: 600; padding: .75rem 1rem; border-radius: .5rem; background: #8883; margin: 1rem 0; }
            .status.ok { background: #2e7d3222; color: #2e7d32; }
            .status.fail { background: #c6282822; color: #c62828; }
            code { word-break: break-all; font-size: .8rem; }
            .req { background: #8881; padding: .75rem; border-radius: .5rem; }
            table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
            td { border-bottom: 1px solid #8883; padding: .35rem .5rem; }
            td:first-child { font-weight: 600; width: 40%; }
            .issuer { color: #888; font-size: .8rem; }
          </style>
        </head>
        <body>
          <h1>Tessio.Verifier <span class="badge">__MODE__ mode</span></h1>
          <p>Session <code>__SESSION_ID__</code></p>
          <div id="status" class="status pending">Starting…</div>
          <div id="claims"></div>
          <details>
            <summary>Authorization request (scan with a wallet)</summary>
            <p class="req"><code>__AUTH_URI__</code></p>
            <p><a href="__STATUS_URL__">Raw status JSON</a></p>
          </details>
          <script>
            const streamUrl = "__STREAM_URL__";
            const statusEl = document.getElementById('status');
            const claimsEl = document.getElementById('claims');
            function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = 'status ' + cls; }
            const es = new EventSource(streamUrl);
            es.addEventListener('pending', () => setStatus('Waiting for wallet…', 'pending'));
            es.addEventListener('completed', (e) => {
              const view = JSON.parse(e.data);
              const r = view.result;
              setStatus(r && r.isValid ? 'Verified ✓' : 'Verification failed ✗', r && r.isValid ? 'ok' : 'fail');
              if (r) {
                const rows = Object.entries(r.disclosedClaims || {})
                  .map(([k, v]) => `<tr><td>${k}</td><td>${String(v)}</td></tr>`).join('');
                claimsEl.innerHTML = `<table>${rows}</table>` +
                  `<p class="issuer">Issuer: ${r.issuer.identifier} · trusted: ${r.issuer.trusted} · key: ${r.issuer.keyResolutionMethod}</p>`;
              }
              es.close();
            });
            es.addEventListener('expired', () => { setStatus('Session expired', 'fail'); es.close(); });
          </script>
        </body>
        </html>
        """;
}
