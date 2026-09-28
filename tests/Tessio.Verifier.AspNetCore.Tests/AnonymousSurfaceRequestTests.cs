using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Whether an anonymous reader of a session can reach its authorization request. Everything about the
/// session surfaces handing out, or not handing out, what a wallet callback is correlated on belongs here.
/// </summary>
/// <remarks>
/// <para>
/// A callback is matched to its session by <c>state</c>, so <c>state</c> belongs only with the user about
/// to hand the request to a wallet, and with that wallet. The status resource and its SSE stream ask for
/// nothing but a session id, and the start endpoint hands one to anybody, so neither may lead to it.
/// </para>
/// <para>
/// <b>The search decodes and follows, because a plain text search cannot fail.</b> Under by-value
/// delivery <c>state</c> sits base64url-encoded inside the request JWT, so it never appears as text in
/// the body even when the body carries it. Under by-reference delivery it sits behind a
/// <c>request_uri</c> that anyone can fetch. The reader here does both, as an attacker would.
/// </para>
/// </remarks>
public sealed class AnonymousSurfaceRequestTests
{
    private static readonly Regex Jwt = new(@"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static readonly Regex RequestUri = new(@"request_uri=([^&""\s]+)",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static IHost StartHost(bool byReference, ECDsa signingKey) => new HostBuilder()
        .ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(services =>
            {
                if (byReference)
                {
                    services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
                        new PresentationRequestBuilderOptions
                        {
                            SigningCredentials = new SigningCredentials(
                                new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                            RequestUriBase = new Uri("http://localhost/verify/request"),
                        }));
                }

                services.AddRouting();
                services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
            })
            .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
        .Start();

    /// <summary>
    /// Everything an anonymous reader can get from the session surfaces, with every JWT found in it
    /// decoded and every request_uri found in it fetched and decoded.
    /// </summary>
    private static async Task<string> WhatAnAnonymousReaderCanReach(HttpClient client, string sessionId)
    {
        var reached = new StringBuilder();
        reached.AppendLine(await client.GetStringAsync($"/verify/{sessionId}"));
        reached.AppendLine(await client.GetStringAsync($"/verify/{sessionId}/stream"));

        var text = reached.ToString();
        foreach (Match link in RequestUri.Matches(text))
        {
            var target = new Uri(Uri.UnescapeDataString(link.Groups[1].Value));
            var served = await client.GetAsync(target.PathAndQuery);
            reached.AppendLine(await served.Content.ReadAsStringAsync());
        }

        foreach (Match token in Jwt.Matches(reached.ToString()))
        {
            var payload = token.Value.Split('.')[1];
            try
            {
                reached.AppendLine(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(payload)));
            }
            catch (FormatException)
            {
                // Not every dotted run of base64url characters is a JWT. One that does not decode
                // carries nothing to find.
            }
        }

        return reached.ToString();
    }

    private static async Task<(string SessionId, string State)> StartSession(IHost host, HttpClient client)
    {
        var page = await client.GetStringAsync("/verify/start");
        var sessionId = Regex.Match(page, @"/verify/([A-Za-z0-9_-]{16,})", RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;
        var session = await host.Services.GetRequiredService<InMemorySessionStore>().GetAsync(sessionId);
        return (sessionId, session!.Request.State!);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SessionSurfaces_LeadAnAnonymousReaderNowhereNearTheState(bool byReference)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = StartHost(byReference, signingKey);
        var client = host.GetTestClient();
        var (sessionId, state) = await StartSession(host, client);

        var reached = await WhatAnAnonymousReaderCanReach(client, sessionId);

        Assert.DoesNotContain(state, reached, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheStartPage_StillCarriesTheRequest_ForTheRelyingPartysOwnPage()
    {
        // The control for the test above: the request, and so the state, is still reachable from the
        // page the relying party serves its own user, which is where a wallet has to get it. The search
        // above would find it here, so its silence about the session surfaces means something.
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = StartHost(byReference: false, signingKey);
        var client = host.GetTestClient();
        var page = await client.GetStringAsync("/verify/start");
        var sessionId = Regex.Match(page, @"/verify/([A-Za-z0-9_-]{16,})", RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;
        var state = (await host.Services.GetRequiredService<InMemorySessionStore>().GetAsync(sessionId))!
            .Request.State!;

        var decoded = new StringBuilder(page);
        foreach (Match token in Jwt.Matches(WebUtility.HtmlDecode(page)))
        {
            try
            {
                decoded.AppendLine(Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(token.Value.Split('.')[1])));
            }
            catch (FormatException)
            {
                // As above: a dotted run that does not decode is not a JWT and carries nothing.
            }
        }

        Assert.Contains(state, decoded.ToString(), StringComparison.Ordinal);

        // tools/conformance-harness/run-plan.py reads the authorization URI from exactly this element, now
        // that the status resource no longer carries it. A template change that drops it would otherwise
        // surface only as a broken conformance run.
        Assert.Matches(new Regex(@"<p class=""req""><code>[^<]+</code></p>", RegexOptions.None, TimeSpan.FromSeconds(1)), page);
    }

    [Fact]
    public async Task TheRoutesThatDoCarryTheState_AreNotStored_ByAnyCache()
    {
        // The start page and the request object are the two places the state legitimately appears. A
        // cache that served either to a second visitor would hand two people one session, and either
        // could then answer for the other, which is the attack without even needing a session id.
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = StartHost(byReference: true, signingKey);
        var client = host.GetTestClient();

        var start = await client.GetAsync("/verify/start");
        Assert.True(start.Headers.CacheControl?.NoStore, "/verify/start must send Cache-Control: no-store");

        // The page shows request_uri percent-encoded twice, inside an HTML-encoded authorization URI,
        // and the value ends at '&', '"' or '<'. The same reading LiveWalletSliceTests uses.
        var html = await start.Content.ReadAsStringAsync();
        var from = html.IndexOf("request_uri=", StringComparison.Ordinal);
        Assert.True(from >= 0, "a by-reference start page shows a request_uri");
        from += "request_uri=".Length;
        var encoded = html[from..html.IndexOfAny(['&', '"', '<'], from)];
        var requestObject = await client.GetAsync(
            new Uri(Uri.UnescapeDataString(Uri.UnescapeDataString(encoded))).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, requestObject.StatusCode);
        Assert.True(requestObject.Headers.CacheControl?.NoStore, "/verify/request/{id} must send Cache-Control: no-store");
    }

    [Theory]
    [InlineData("")]
    [InlineData("/stream")]
    public async Task SessionSurfaces_AreNotStored_ByAnyCache(string surface)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = StartHost(byReference: false, signingKey);
        var client = host.GetTestClient();
        var (sessionId, _) = await StartSession(host, client);

        var response = await client.GetAsync($"/verify/{sessionId}{surface}");

        // Both carry a verdict and disclosed claims, reachable by whoever holds the id. A shared or
        // browser cache holding either would outlive the session and answer a later reader.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore, $"/verify/{{id}}{surface} must send Cache-Control: no-store");
    }
}
