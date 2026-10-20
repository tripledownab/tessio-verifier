using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

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
    /// <item><description><c>GET {prefix}/{sessionId}/return</c> — the page a wallet's redirect lands on.</description></item>
    /// <item><description><c>POST {prefix}/same-device</c>, <c>POST {prefix}/callback/same-device</c> and
    /// <c>POST {prefix}/{sessionId}/redeem</c> — the same-device flow, when the session store implements
    /// <see cref="ISameDeviceSessionStore"/> (see <see cref="SameDeviceEndpoints"/>).</description></item>
    /// </list>
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="routePrefix">Overrides <see cref="VerifierOptions.RoutePrefix"/> when supplied.</param>
    public static IEndpointRouteBuilder MapTessioVerifier(this IEndpointRouteBuilder endpoints, string? routePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var prefix = NormalizePrefix(routePrefix ?? options.RoutePrefix);

        // Fail fast rather than let a demo configuration face real wallets. See docs/going-live.md.
        if (options.Mode == VerifierMode.Live)
        {
            if (endpoints.ServiceProvider.GetRequiredService<IPresentationRequestBuilder>() is DemoPresentationRequestBuilder)
            {
                throw new InvalidOperationException(
                    "VerifierMode.Live requires signed requests: register a SignedPresentationRequestBuilder " +
                    "as IPresentationRequestBuilder before AddTessioVerifier. Wallets reject the unsigned demo requests.");
            }

            if (endpoints.ServiceProvider.GetRequiredService<Tessio.Verifier.Trust.ITrustListResolver>() is DevDefaultTrustListResolver)
            {
                throw new InvalidOperationException(
                    "VerifierMode.Live requires a real trust list: the default resolver trusts only the built-in " +
                    "demo and mock issuers. Register an ITrustListResolver before AddTessioVerifier.");
            }
        }

        endpoints.MapGet($"{prefix}/start", (HttpContext http) => SessionStartEndpoint.HandleAsync(http, prefix));
        endpoints.MapGet($"{prefix}/request/{{requestId}}", (string requestId, HttpContext http) => ServeRequestObjectAsync(requestId, http));
        endpoints.MapGet($"{prefix}/{{sessionId}}", (string sessionId, HttpContext http) => GetStatusAsync(sessionId, http));
        endpoints.MapGet($"{prefix}/{{sessionId}}/stream", (string sessionId, HttpContext http) => SessionEventStream.StreamAsync(sessionId, http, SerializerOptions));
        endpoints.MapPost($"{prefix}{WalletCallbackEndpoint.CallbackPath}", (HttpContext http) => WalletCallbackEndpoint.HandleAsync(http, prefix, SerializerOptions));

        // The return page is mapped whatever the store, because every processed callback redirects to it.
        var store = endpoints.ServiceProvider.GetRequiredService<ISessionStore>();
        var sameDevice = store is ISameDeviceSessionStore;
        SameDeviceEndpoints.MapReturnPage(endpoints, prefix, offerRedemption: sameDevice);
        if (sameDevice)
        {
            endpoints.MapPost($"{prefix}{SameDeviceRequests.CallbackPath}", (HttpContext http) => WalletCallbackEndpoint.HandleAsync(http, prefix, SerializerOptions));
            SameDeviceEndpoints.Map(endpoints, prefix, SerializerOptions);
        }
        else
        {
            // Loud rather than fatal: a store written against contracts-v0 keeps working for cross-device
            // verification, and failing its host's boot on upgrade would be a breaking change.
            Log.SameDeviceUnavailable(
                endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Tessio.Verifier.Sessions"),
                store.GetType().Name);
        }

        return endpoints;
    }

    private static async Task ServeRequestObjectAsync(string requestId, HttpContext http)
    {
        var store = http.RequestServices.GetRequiredService<RequestObjectStore>();
        var requestObject = store.Get(requestId);
        if (requestObject is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        // SPEC: RFC 9101 §4 — the request object is served as application/oauth-authz-req+jwt.
        http.Response.ContentType = "application/oauth-authz-req+jwt";
        // no-store: the request object carries its session's state, which is what a callback is matched on.
        http.Response.Headers.CacheControl = "no-store";
        await http.Response.WriteAsync(requestObject, http.RequestAborted).ConfigureAwait(false);
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

        var options = http.RequestServices.GetRequiredService<IOptions<VerifierOptions>>().Value;
        // no-store: the body carries a verdict and disclosed claims to whoever holds the id, and a shared
        // or browser cache holding it would outlive the session and answer a later reader.
        http.Response.Headers.CacheControl = "no-store";
        await http.Response.WriteAsJsonAsync(
            SessionView.From(session, options.PublicTrustListSources),
            SerializerOptions,
            http.RequestAborted).ConfigureAwait(false);
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
}
