using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// HTTP-level tests for the wallet callback endpoint: form translation, status mapping, and the
/// full mock flow driven through real HTTP requests against an in-process server.
/// </summary>
public sealed class CallbackEndpointHttpTests : IAsyncDisposable
{
    private readonly IHost _host;
    private readonly HttpClient _client;

    public CallbackEndpointHttpTests()
    {
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services
                    .AddRouting()
                    .AddTessioVerifier(options =>
                    {
                        options.Mode = VerifierMode.Mock;
                        options.RequestedClaims = ["age_over_18"];
                    }))
                .Configure(app => app
                    .UseRouting()
                    .UseEndpoints(endpoints => endpoints.MapTessioVerifier())))
            .Start();
        _client = _host.GetTestClient();
    }

    private async Task<(string SessionId, string State, string Nonce)> CreateSessionAsync()
    {
        var store = _host.Services.GetRequiredService<InMemorySessionStore>();
        var options = _host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("http://localhost/verify/callback")));
        return (session.SessionId, session.Request.State!, session.Request.Nonce);
    }

    private FormUrlEncodedContent MockWalletForm(string state, string nonce)
    {
        var issuer = _host.Services.GetRequiredService<MockCredentialIssuer>();
        var options = _host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, nonce, options.ClientId);

        return new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
            ["state"] = state,
        });
    }

    [Fact]
    public async Task Callback_ValidWalletResponse_Returns200_AndCompletesSession()
    {
        var (sessionId, state, nonce) = await CreateSessionAsync();

        var response = await _client.PostAsync("/verify/callback", MockWalletForm(state, nonce));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var session = await _host.Services.GetRequiredService<InMemorySessionStore>().GetAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Completed, session!.Status);
        Assert.True(session.Result!.IsValid);
    }

    [Fact]
    public async Task Callback_UnknownState_Returns400()
    {
        var (_, _, nonce) = await CreateSessionAsync();

        var response = await _client.PostAsync("/verify/callback", MockWalletForm("wrong-state", nonce));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Callback_SecondResponse_Returns409()
    {
        var (_, state, nonce) = await CreateSessionAsync();
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/verify/callback", MockWalletForm(state, nonce))).StatusCode);

        var replay = await _client.PostAsync("/verify/callback", MockWalletForm(state, nonce));

        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    [Fact]
    public async Task Callback_NonFormContentType_Returns400()
    {
        var response = await _client.PostAsync("/verify/callback",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Callback_GarbageForm_Returns400()
    {
        var response = await _client.PostAsync("/verify/callback",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["unrelated"] = "x" }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
