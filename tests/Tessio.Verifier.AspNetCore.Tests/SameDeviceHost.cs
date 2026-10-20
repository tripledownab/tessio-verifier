using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// An in-process verifier host driven the way a browser and a wallet drive the same-device flow: what the
/// same-device tests share, so each test reads as the steps of the flow.
/// </summary>
internal sealed class SameDeviceHost : IAsyncDisposable
{
    public const string CookieName = "__Host-tessio-verifier-binding";

    private readonly IHost _host;

    public SameDeviceHost(
        bool completeOnlyOnValidResponse = false,
        Func<IServiceProvider, ISessionStore>? store = null,
        TimeSpan? sessionLifetime = null,
        ILoggerProvider? logs = null,
        Func<IPresentationRequestBuilder, IPresentationRequestBuilder>? builder = null)
    {
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddSingleton<TimeProvider>(Clock);
                    if (logs is not null)
                    {
                        services.AddLogging(builder => builder.AddProvider(logs));
                    }

                    if (builder is not null)
                    {
                        services.AddSingleton(sp => builder(new DemoPresentationRequestBuilder(sp.GetRequiredService<TimeProvider>())));
                    }

                    if (store is not null)
                    {
                        services.AddSingleton<ISessionStore>(store);
                    }

                    services.AddRouting().AddTessioVerifier(options =>
                    {
                        // Mock mode, so the mock issuer's credentials verify. Its wallet answers only sessions
                        // /start enqueues, and these tests never call /start, so every answer here is one they post.
                        options.Mode = VerifierMode.Mock;
                        options.ResponseMode = ResponseMode.DirectPost;
                        options.RequestedClaims = ["age_over_18"];
                        options.CompleteOnlyOnValidResponse = completeOnlyOnValidResponse;
                        options.SessionLifetime = sessionLifetime ?? options.SessionLifetime;
                    });
                })
                .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
            .Start();
        Client = _host.GetTestClient();
    }

    public MovableClock Clock { get; } = new(DateTimeOffset.UtcNow);

    public HttpClient Client { get; }

    public IServiceProvider Services => _host.Services;

    /// <summary>What <c>POST /verify/same-device</c> answered, with the cookie it set and the request it minted.</summary>
    public sealed record Started(HttpResponseMessage Response, string? Cookie, string State, string Nonce);

    /// <summary>The browser asks for a request bound to it, sending <paramref name="cookie"/> if it has one.</summary>
    public async Task<Started> StartSameDeviceAsync(string? cookie = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/verify/same-device")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        AddCookie(request, cookie);
        var response = await Client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var setCookie = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.Single() : null;
        var walletUrl = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("walletUrl").GetString()!;
        var (state, nonce) = StateAndNonce(walletUrl);
        return new Started(response, setCookie?.Split(';')[0].Split('=', 2)[1], state, nonce);
    }

    /// <summary>A session the start page would create: cross-device, bound to no browser.</summary>
    public async Task<VerificationSession> CreateCrossDeviceSessionAsync() =>
        await Services.GetRequiredService<ISessionStore>().CreateAsync(DemoRequestOptionsFactory.Create(
            Services.GetRequiredService<IOptions<VerifierOptions>>().Value, new Uri("http://localhost/verify/callback")));

    /// <summary>The wallet answers a same-device request, posting to the callback path that request names.</summary>
    public Task<HttpResponseMessage> PresentAsync(Started started) =>
        PresentAsync(started.State, started.Nonce, "/verify/callback/same-device");

    /// <summary>
    /// The wallet posts a presentation for <paramref name="state"/> made with <paramref name="nonce"/> to
    /// <paramref name="callbackPath"/>, the start page's cross-device callback unless told otherwise.
    /// </summary>
    public Task<HttpResponseMessage> PresentAsync(string state, string nonce, string callbackPath = "/verify/callback")
    {
        var options = Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var presentation = Services.GetRequiredService<MockCredentialIssuer>().IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, nonce, options.ClientId);
        return Client.PostAsync(callbackPath, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
            ["state"] = state,
        }));
    }

    /// <summary>The session and the response code the wallet's redirect sends the browser to.</summary>
    public static async Task<(Uri ReturnPage, string SessionId, string ResponseCode)> RedirectOf(HttpResponseMessage callback)
    {
        callback.EnsureSuccessStatusCode();
        var redirect = new Uri((await callback.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirect_uri").GetString()!);
        var segments = redirect.AbsolutePath.Split('/');
        Assert.Equal("return", segments[^1]);
        var code = HttpUtility.ParseQueryString(redirect.Fragment.TrimStart('#'))["response_code"];
        return (redirect, Uri.UnescapeDataString(segments[^2]), code!);
    }

    /// <summary>The return page redeems <paramref name="code"/>; returns what the redemption did.</summary>
    public async Task<string> RedeemAsync(string sessionId, string code, string? cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/verify/{sessionId}/redeem")
        {
            Content = JsonContent.Create(new { responseCode = code }),
        };
        AddCookie(request, cookie);
        var response = await Client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("result").GetString()!;
    }

    public async Task<VerificationSession> SessionAsync(string sessionId) =>
        (await Services.GetRequiredService<ISessionStore>().GetAsync(sessionId))!;

    public async Task<VerificationSession> SessionByStateAsync(string state) =>
        (await Services.GetRequiredService<InMemorySessionStore>().FindByStateAsync(state))!;

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    private static void AddCookie(HttpRequestMessage request, string? cookie)
    {
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", $"{CookieName}={cookie}");
        }
    }

    /// <summary>The state and nonce inside the demo request object, an unsigned JWT in the wallet URL.</summary>
    private static (string State, string Nonce) StateAndNonce(string walletUrl)
    {
        var requestObject = HttpUtility.ParseQueryString(new Uri(walletUrl).Query)["request"]!;
        using var claims = JsonDocument.Parse(WebEncoders.Base64UrlDecode(requestObject.Split('.')[1]));
        return (claims.RootElement.GetProperty("state").GetString()!, claims.RootElement.GetProperty("nonce").GetString()!);
    }

    /// <summary>A clock a test moves by hand, to pass the redemption window.</summary>
    internal sealed class MovableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
