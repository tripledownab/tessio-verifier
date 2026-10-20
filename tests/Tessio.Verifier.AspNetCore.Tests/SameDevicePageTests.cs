using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The browser's side of the same-device flow: the return page, what the hosted pages put in their
/// scripts, and what a host whose session store cannot hold a presentation is served instead.
/// </summary>
public sealed class SameDevicePageTests
{
    [Fact]
    public async Task TheReturnPage_IsServedForAKnownSessionOnly_AndNeverCached()
    {
        await using var host = new SameDeviceHost();
        var session = await host.CreateCrossDeviceSessionAsync();

        var page = await host.Client.GetAsync($"/verify/{session.SessionId}/return");
        var unknown = await host.Client.GetAsync("/verify/no-such-session/return");

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal("no-store", page.Headers.CacheControl?.ToString());
        Assert.Contains($"\"redeemUrl\":\"/verify/{session.SessionId}/redeem\"", await page.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ASessionIdCannotCloseTheScriptItIsPlacedIn(bool startPage)
    {
        // A host's store mints its own ids, and nothing promises they are base64url.
        const string hostile = "x</script><script>alert(1)</script>";

        var page = Render(startPage, hostile);

        Assert.DoesNotContain("<script>alert(1)", page, StringComparison.Ordinal);
        Assert.Equal(2, CountOf(page, "</script>"));
    }

    [Fact]
    public void ARoutePrefixCannotCloseTheScriptItIsPlacedIn()
    {
        // The prefix is the host's, so this is the serializer's escaping standing alone: session ids are
        // escaped as path segments before they reach the configuration block.
        var page = HostedPages.Return("s", "/x</script><script>alert(1)</script>", offerRedemption: true);

        Assert.DoesNotContain("<script>alert(1)", page, StringComparison.Ordinal);
        Assert.Equal(2, CountOf(page, "</script>"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ASessionIdNamingAPlaceholder_StaysText(bool startPage)
    {
        var page = Render(startPage, "a__BODY__b");

        // One page, one body: the id was not read again as the placeholder it spells.
        Assert.Equal(1, CountOf(page, "<h1>"));
        Assert.Contains("a__BODY__b", page, StringComparison.Ordinal);
    }

    [Fact]
    public void ASessionIdIsEscapedAsOnePathSegmentInEveryUrl()
    {
        var page = Render(startPage: false, "a/b?c");

        Assert.Contains("\"streamUrl\":\"/verify/a%2Fb%3Fc/stream\"", page, StringComparison.Ordinal);
        Assert.Contains("\"redeemUrl\":\"/verify/a%2Fb%3Fc/redeem\"", page, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePageScripts_NeverWriteMarkupFromAValue()
    {
        // An issuer identifier on a failing result is whatever the presenter put there. The scripts
        // build every element with textContent, so this rule is what keeps it text.
        string[] scripts = [HostedPageAssets.SharedScript, HostedPageAssets.StartScript, HostedPageAssets.ReturnScript];

        Assert.All(scripts, script =>
        {
            Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("outerHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("insertAdjacentHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("document.write", script, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void TheStartPage_OffersSameDeviceOnlyWhenAsked()
    {
        var offered = HostedPages.Start("s", "/verify", VerifierMode.Live, "openid4vp://authorize?x=1", offerSameDevice: true);
        var withheld = HostedPages.Start("s", "/verify", VerifierMode.Live, "openid4vp://authorize?x=1", offerSameDevice: false);

        Assert.Contains("id=\"same-device\"", offered, StringComparison.Ordinal);
        Assert.Contains("\"sameDeviceUrl\":\"/verify/same-device\"", offered, StringComparison.Ordinal);
        Assert.DoesNotContain("id=\"same-device\"", withheld, StringComparison.Ordinal);
        Assert.Contains("\"sameDeviceUrl\":null", withheld, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(VerifierMode.Live, true, true)]
    [InlineData(VerifierMode.Mock, true, false)]
    [InlineData(VerifierMode.Live, false, false)]
    public async Task TheStartPage_OffersSameDeviceInLiveModeWithAStoreThatCanHold(VerifierMode mode, bool storeCanHold, bool offered)
    {
        // The other modes answer the start page's own session themselves, and nothing would answer a
        // same-device one. Live mode refuses the demo builder and trust list, so stand-ins pass its checks.
        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    if (!storeCanHold)
                    {
                        services.AddSingleton<ISessionStore>(sp => new CrossDeviceOnlyStore(sp.GetRequiredService<InMemorySessionStore>()));
                    }

                    services
                        .AddSingleton<IPresentationRequestBuilder>(sp =>
                            new NotTheDemoBuilder(new DemoPresentationRequestBuilder(TimeProvider.System)))
                        .AddSingleton<Trust.ITrustListResolver>(new Trust.StaticTrustListResolver([]))
                        .AddRouting()
                        .AddTessioVerifier(options => options.Mode = mode);
                })
                .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
            .Start();

        var page = await host.GetTestClient().GetStringAsync("/verify/start");

        Assert.Equal(offered, page.Contains("id=\"same-device\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AStoreThatCannotHold_GetsNoSameDeviceRoutes_AndAWarning()
    {
        var logs = new CapturingLoggerProvider();
        await using var host = new SameDeviceHost(
            store: sp => new CrossDeviceOnlyStore(sp.GetRequiredService<InMemorySessionStore>()), logs: logs);

        var response = await host.Client.PostAsync("/verify/same-device",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        // Only GET /verify/{sessionId} matches the path, so the POST is refused for its method.
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        var warning = Assert.Single(logs.Records, r => r.EventName == "SameDeviceUnavailable");
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains(nameof(CrossDeviceOnlyStore), warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AStoreThatCannotHold_StillSendsTheWalletToAPageThatExists()
    {
        await using var host = new SameDeviceHost(
            store: sp => new CrossDeviceOnlyStore(sp.GetRequiredService<InMemorySessionStore>()));
        var session = await host.CreateCrossDeviceSessionAsync();

        var (returnPage, _, _) = await SameDeviceHost.RedirectOf(
            await host.PresentAsync(session.Request.State!, session.Request.Nonce));
        var page = await host.Client.GetAsync(returnPage.PathAndQuery);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        // Nothing to redeem with: the page only shows the session.
        Assert.Contains("\"redeemUrl\":null", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private static string Render(bool startPage, string sessionId) => startPage
        ? HostedPages.Start(sessionId, "/verify", VerifierMode.Live, "openid4vp://authorize?x=1", offerSameDevice: true)
        : HostedPages.Return(sessionId, "/verify", offerRedemption: true);

    private static int CountOf(string text, string value) =>
        (text.Length - text.Replace(value, "", StringComparison.Ordinal).Length) / value.Length;

    /// <summary>Builds what the demo builder builds, without being it, so Live mode's startup check passes.</summary>
    private sealed class NotTheDemoBuilder(IPresentationRequestBuilder inner) : IPresentationRequestBuilder
    {
        public Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
            inner.BuildAsync(options, ct);
    }
}
