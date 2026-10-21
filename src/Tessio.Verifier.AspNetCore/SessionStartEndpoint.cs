using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Starting a verification: <c>GET {prefix}/start</c>, which creates a session and renders the start page,
/// and the session creation it shares with the same-device route.
/// </summary>
internal static class SessionStartEndpoint
{
    public static async Task HandleAsync(HttpContext http, string prefix)
    {
        var options = http.RequestServices.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var store = http.RequestServices.GetRequiredService<ISessionStore>();
        var session = await CreateSessionAsync(http, prefix, WalletCallbackEndpoint.CallbackPath, store.CreateAsync).ConfigureAwait(false);

        switch (options.Mode)
        {
            case VerifierMode.Demo:
                await http.RequestServices.GetRequiredService<DemoCompletionQueue>()
                    .EnqueueAsync(session.SessionId, http.RequestAborted).ConfigureAwait(false);
                break;
            case VerifierMode.Mock:
                await http.RequestServices.GetRequiredService<MockWalletQueue>()
                    .EnqueueAsync(session.SessionId, http.RequestAborted).ConfigureAwait(false);
                break;
            case VerifierMode.Test:
                await http.RequestServices.GetRequiredService<TestFixtureQueue>()
                    .EnqueueAsync(session.SessionId, http.RequestAborted).ConfigureAwait(false);
                break;
            default:
                break; // Live wallets respond via the callback on their own schedule.
        }

        // Offered in Live mode only: the other modes answer the start page's own session themselves, and
        // nothing would answer a same-device one.
        var page = HostedPages.Start(session.SessionId, prefix, options.Mode,
            session.Request.AuthorizationRequestUri.ToString(),
            offerSameDevice: options.Mode == VerifierMode.Live && store is ISameDeviceSessionStore);
        await HostedPageResponses.WritePageAsync(http, page).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a session through <paramref name="create"/> with this deployment's request options, and
    /// hosts its request object when it is delivered by reference. Shared by the start page and the
    /// same-device route, so the two cannot build their requests differently: they differ only in the
    /// <paramref name="callbackPath"/> the wallet posts to.
    /// </summary>
    internal static async Task<VerificationSession> CreateSessionAsync(
        HttpContext http, string prefix, string callbackPath,
        Func<PresentationRequestOptions, CancellationToken, Task<VerificationSession>> create)
    {
        var options = http.RequestServices.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var responseUri = new Uri($"{http.Request.Scheme}://{http.Request.Host}{prefix}{callbackPath}");

        // A FRESH key per request (OpenID4VP 1.0 §8.3, HAIP 1.0 §5): reusing one is a correlation
        // handle and a single point of retrospective compromise. Held until the session expires; the
        // callback finds it again via the kid the wallet echoes in the JWE header.
        var encryptionJwk = options.ResponseMode == ResponseMode.DirectPostJwt
            ? http.RequestServices.GetRequiredService<ResponseEncryptionKeyStore>()
                .CreateForRequest(http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow() + options.SessionLifetime)
                .PublicJwk
            : null;
        var requestOptions = DemoRequestOptionsFactory.Create(options, responseUri, encryptionJwk);
        var session = await create(requestOptions, http.RequestAborted).ConfigureAwait(false);
        var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Tessio.Verifier.Sessions");
        Log.SessionCreated(logger, session.SessionId, options.Mode, session.ExpiresAt);

        // By-reference delivery: host the signed JAR where the wallet will fetch it.
        if (session.Request is PresentationRequest.ByReference byReference)
        {
            var requestId = byReference.RequestUri.Segments[^1].TrimEnd('/');
            http.RequestServices.GetRequiredService<RequestObjectStore>()
                .Put(requestId, byReference.SignedRequestObject, byReference.ExpiresAt);
        }

        return session;
    }
}
