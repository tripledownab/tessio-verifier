using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>Request-object hosting, encryption-key advertisement, and both response-mode E2E paths.</summary>
public class LiveWalletSliceTests
{
    // ---- Response modes end to end ------------------------------------------------------------

    private static async Task<VerificationSession> RunMockSessionAsync(ResponseMode mode)
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.ResponseMode = mode;
            options.RequestedClaims = ["age_over_18"];
        });
        await using var provider = services.BuildServiceProvider();
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        try
        {
            var store = provider.GetRequiredService<InMemorySessionStore>();
            var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
            var encryptionJwk = provider.GetRequiredService<ResponseEncryptionKeyProvider>().PublicJwk;
            var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
                options, new Uri("https://verifier.example/verify/callback"), encryptionJwk));

            await provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            return await store.WaitForTerminalAsync(session.SessionId, timeout.Token);
        }
        finally
        {
            foreach (var hosted in provider.GetServices<IHostedService>())
            {
                await hosted.StopAsync(CancellationToken.None);
            }
        }
    }

    [Fact]
    public async Task MockMode_EncryptedDirectPostJwt_VerifiesEndToEnd()
    {
        var terminal = await RunMockSessionAsync(ResponseMode.DirectPostJwt);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        Assert.True(terminal.Result!.IsValid,
            string.Join("; ", terminal.Result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.Equal(true, terminal.Result.DisclosedClaims["age_over_18"]);
    }

    [Fact]
    public async Task MockMode_PlainDirectPost_VerifiesEndToEnd()
    {
        var terminal = await RunMockSessionAsync(ResponseMode.DirectPost);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        Assert.True(terminal.Result!.IsValid);
    }

    // ---- Encryption key advertisement ---------------------------------------------------------

    [Fact]
    public void ClientMetadata_CarriesEncryptionJwks_ForDirectPostJwt()
    {
        using var provider = new ResponseEncryptionKeyProvider();
        var options = new VerifierOptions(); // DirectPostJwt default

        var requestOptions = DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback"), provider.PublicJwk);

        Assert.NotNull(requestOptions.ClientMetadataJson);
        Assert.Contains("\"use\":\"enc\"", requestOptions.ClientMetadataJson, StringComparison.Ordinal);
        Assert.Contains("ECDH-ES+A256KW", requestOptions.ClientMetadataJson, StringComparison.Ordinal);
        Assert.Contains("encrypted_response_enc_values_supported", requestOptions.ClientMetadataJson, StringComparison.Ordinal);
    }

    // ---- Request-object hosting ---------------------------------------------------------------

    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void RequestObjectStore_ServesUntilExpiry_ThenEvicts()
    {
        var clock = new TestClock();
        var store = new RequestObjectStore(clock);

        store.Put("req-1", "eyJ.jar.sig", clock.Now.AddMinutes(5));
        Assert.Equal("eyJ.jar.sig", store.Get("req-1"));

        clock.Now += TimeSpan.FromMinutes(6);
        Assert.Null(store.Get("req-1"));
    }

    [Fact]
    public async Task ByReferenceRequest_IsServed_AtRequestUri()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    // A live-style builder registered before AddTessioVerifier supersedes the demo one.
                    services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
                        new PresentationRequestBuilderOptions
                        {
                            SigningCredentials = new SigningCredentials(
                                new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                            RequestUriBase = new Uri("http://localhost/verify/request"),
                        }));
                    services.AddRouting();
                    services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
                })
                .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
            .Start();
        var client = host.GetTestClient();

        var startHtml = await client.GetStringAsync("/verify/start");
        Assert.Contains("request_uri=", startHtml, StringComparison.Ordinal);

        // Fetch the JAR the way a wallet would.
        var requestUri = ExtractRequestUri(startHtml);
        var response = await client.GetAsync(requestUri);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/oauth-authz-req+jwt", response.Content.Headers.ContentType!.MediaType);
        var jar = await response.Content.ReadAsStringAsync();
        Assert.Equal(3, jar.Split('.').Length); // signed JWT

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/verify/request/no-such-id")).StatusCode);
    }

    // ---- Live mode ----------------------------------------------------------------------------

    [Fact]
    public async Task LiveMode_SessionWaitsForWallet_ThenCallbackCompletes()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
                        new PresentationRequestBuilderOptions
                        {
                            SigningCredentials = new SigningCredentials(
                                new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                        }));
                    // Live mode rejects the dev default trust list; pin the simulated wallet's issuer.
                    services.AddSingleton<Tessio.Verifier.Trust.ITrustListResolver>(sp =>
                        new Tessio.Verifier.Trust.StaticTrustListResolver(
                            [MockCredentialIssuer.Issuer],
                            source: "live-test",
                            trustAnchors: [sp.GetRequiredService<MockCredentialIssuer>().Certificate]));
                    services.AddRouting();
                    services.AddTessioVerifier(options =>
                    {
                        options.Mode = VerifierMode.Live;
                        options.ResponseMode = ResponseMode.DirectPost;
                    });
                })
                .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
            .Start();
        var client = host.GetTestClient();

        var startHtml = await client.GetStringAsync("/verify/start");
        var sessionId = ExtractSessionId(startHtml);

        // No built-in actor completes Live sessions; the session waits for a wallet.
        var store = host.Services.GetRequiredService<InMemorySessionStore>();
        var pending = await store.GetAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Pending, pending!.Status);

        // A wallet responds through the callback endpoint (simulated with the mock issuer's credential).
        var issuer = host.Services.GetRequiredService<MockCredentialIssuer>();
        var options = host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, pending.Request.Nonce, options.ClientId);

        var response = await client.PostAsync("/verify/callback", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
                ["state"] = pending.Request.State!,
            }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var terminal = await store.GetAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Completed, terminal!.Status);
        Assert.True(terminal.Result!.IsValid,
            string.Join("; ", terminal.Result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    private static string ExtractSessionId(string startHtml)
    {
        var marker = "Session <code>";
        var start = startHtml.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        var end = startHtml.IndexOf("</code>", start, StringComparison.Ordinal);
        return startHtml[start..end];
    }

    private static string ExtractRequestUri(string startHtml)
    {
        // The authorization URI on the page carries request_uri=<url-encoded>; decode the local path.
        var marker = "request_uri=";
        var start = startHtml.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        var end = startHtml.IndexOfAny(['&', '"', '<'], start);
        var encoded = startHtml[start..end];
        var url = Uri.UnescapeDataString(Uri.UnescapeDataString(encoded));
        return new Uri(url).PathAndQuery;
    }
}
