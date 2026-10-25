using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The browser's half of the same-device flow: minting a request bound to this browser before a wallet on
/// the same device is opened, the page the wallet's redirect lands on, and redeeming the response code that
/// redirect carries.
/// </summary>
/// <remarks>
/// <para>
/// SPEC: HAIP 1.0 section 5.1, "Verifiers and Wallets MUST support the "same-device" flow. ... Verifiers
/// MUST reject presentations if Wallets do not follow the redirect back or the redirect back arrives in a
/// different user session to the one the request was initiated in." The user session is the browser
/// holding the <see cref="SameDeviceSecrets.BindingCookie"/>.
/// </para>
/// <para>
/// WHAT IT PROTECTS, exactly. A same-device request relayed to someone else's device cannot complete its
/// session, because their browser does not hold the binding. It does not protect the start page's own
/// request, the one its QR code carries, which stays unbound by necessity: OpenID4VP 1.0 section 14.2 says
/// the technique "is not applicable to cross-device scenarios because the browser used by the Wallet will
/// not have the original session". So whoever starts a request chooses whether it is bound, an attacker
/// included. This meets section 5.1's requirements for the same-device flow; it is not phishing resistance
/// while the start page also offers the cross-device request.
/// </para>
/// <para>
/// Both POST routes take JSON only. A form on another site can post here with no CORS preflight, and the
/// browser would store the binding cookie the first route answers with; a JSON body needs a preflight,
/// which these routes never grant. Like <c>/start</c>, neither is rate limited here: that is the host's
/// edge, which knows its own traffic.
/// </para>
/// </remarks>
internal static class SameDeviceEndpoints
{
    /// <summary>Maps the routes that mint and redeem a same-device request.</summary>
    public static void Map(IEndpointRouteBuilder endpoints, string prefix, JsonSerializerOptions serializerOptions)
    {
        endpoints.MapPost($"{prefix}/same-device", (HttpContext http) => CreateAsync(http, prefix, serializerOptions));
        endpoints.MapPost($"{prefix}/{{sessionId}}/redeem",
            (string sessionId, HttpContext http) => RedeemAsync(sessionId, http, serializerOptions));
    }

    /// <summary>
    /// Maps the return page. Every processed callback redirects to it, so it is mapped for every store; with
    /// <paramref name="offerRedemption"/> off it only shows the session, having nothing to redeem with.
    /// </summary>
    public static void MapReturnPage(IEndpointRouteBuilder endpoints, string prefix, bool offerRedemption) =>
        endpoints.MapGet($"{prefix}/{{sessionId}}/return",
            (string sessionId, HttpContext http) => ReturnAsync(sessionId, http, prefix, offerRedemption));

    private static async Task CreateAsync(HttpContext http, string prefix, JsonSerializerOptions serializerOptions)
    {
        if (RefusedAsNotJson(http))
        {
            return;
        }

        // One secret per browser, reused for every request it starts, so two open in one browser do not
        // overwrite each other's binding. A missing or malformed cookie gets a fresh one.
        var secret = SameDeviceSecrets.BrowserSecret(http.Request) ?? SameDeviceSecrets.NewSecret();
        var store = (ISameDeviceSessionStore)http.RequestServices.GetRequiredService<ISessionStore>();
        var binding = SameDeviceSecrets.Hash(secret);
        var session = await SessionStartEndpoint.CreateSessionAsync(
            http, prefix, SameDeviceRequests.CallbackPath, (options, ct) => store.CreateBoundAsync(options, binding, ct))
            .ConfigureAwait(false);
        if (session is null)
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        if (!SameDeviceRequests.IsSameDevice(session.Request))
        {
            // The request builder dropped or rewrote the response_uri it was given, so the request would not
            // say it was bound. Refused before the wallet sees it, rather than leave the binding the only witness.
            throw new InvalidOperationException(
                $"The registered {nameof(IPresentationRequestBuilder)} built a same-device request whose response_uri " +
                $"does not end in {SameDeviceRequests.CallbackPath}. It must carry the response URI it is given.");
        }

        http.Response.Cookies.Append(SameDeviceSecrets.BindingCookie, secret, SameDeviceSecrets.BindingCookieOptions());
        // no-store: the body opens a wallet with this session's request, and so carries its state.
        http.Response.Headers.CacheControl = "no-store";
        await http.Response.WriteAsJsonAsync(
            new SameDeviceRequestCreated(session.Request.AuthorizationRequestUri.ToString()),
            serializerOptions, http.RequestAborted).ConfigureAwait(false);
    }

    private static async Task RedeemAsync(string sessionId, HttpContext http, JsonSerializerOptions serializerOptions)
    {
        if (RefusedAsNotJson(http))
        {
            return;
        }

        if (!JsonReaderCanDecode(http.Request))
        {
            http.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }

        RedeemRequest? body;
        try
        {
            body = await http.Request.ReadFromJsonAsync<RedeemRequest>(serializerOptions, http.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (JsonException)
        {
            body = null;
        }

        if (body?.ResponseCode is not { Length: > 0 and <= SameDeviceSecrets.MaxSecretLength } code)
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            await http.Response.WriteAsJsonAsync(new { error = "invalid_request" }, serializerOptions, http.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        var redemption = await http.RequestServices.GetRequiredService<WalletCallbackProcessor>()
            .RedeemAsync(sessionId, code, SameDeviceSecrets.BrowserSecret(http.Request), http.RequestAborted)
            .ConfigureAwait(false);

        // The page shows the session as its stream reports it, so this says only what the redemption did.
        await http.Response.WriteAsJsonAsync(new RedeemResult(ResultName(redemption)), serializerOptions, http.RequestAborted)
            .ConfigureAwait(false);
    }

    private static async Task ReturnAsync(string sessionId, HttpContext http, string prefix, bool offerRedemption)
    {
        var session = await http.RequestServices.GetRequiredService<ISessionStore>()
            .GetAsync(sessionId, http.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        // The response code is in the fragment, which never reaches here.
        await HostedPageResponses.WritePageAsync(http, HostedPages.Return(session.SessionId, prefix, offerRedemption))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Answers 415 to a body that is not JSON, the defence against a cross-site post described above.
    /// Returns whether it did.
    /// </summary>
    private static bool RefusedAsNotJson(HttpContext http)
    {
        if (http.Request.HasJsonContentType())
        {
            return false;
        }

        http.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
        return true;
    }

    /// <summary>
    /// Whether the JSON reader can decode the body's charset: none, or one <see cref="Encoding.GetEncoding(string)"/>
    /// returns as written, which is how the reader picks its encoding.
    /// </summary>
    /// <remarks>
    /// The reader throws for any other charset, unknown, disabled (UTF-7) or quoted alike, so a body in one is
    /// refused before the read rather than caught around it, where an exception of the caller's could not be told
    /// from one of ours. Only the redeem route reads its body, so only it asks.
    /// </remarks>
    private static bool JsonReaderCanDecode(HttpRequest request)
    {
        var charset = request.GetTypedHeaders().ContentType?.Charset ?? default;
        if (!charset.HasValue)
        {
            return true;
        }

        try
        {
            Encoding.GetEncoding(charset.ToString());
            return true;
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static string ResultName(SameDeviceRedemption redemption) => redemption switch
    {
        SameDeviceRedemption.Redeemed => "redeemed",
        SameDeviceRedemption.BindingMismatch => "session_mismatch",
        SameDeviceRedemption.NotHeld => "not_held",
        _ => throw new InvalidOperationException($"Unhandled same-device redemption outcome {redemption}."),
    };

    /// <summary>The body <c>POST {prefix}/{sessionId}/redeem</c> takes.</summary>
    private sealed record RedeemRequest(string? ResponseCode);

    /// <summary>What a redemption did: <c>redeemed</c>, <c>session_mismatch</c> or <c>not_held</c>.</summary>
    private sealed record RedeemResult(string Result);

    /// <summary>The link that opens a wallet with a request bound to this browser.</summary>
    private sealed record SameDeviceRequestCreated(string WalletUrl);
}
