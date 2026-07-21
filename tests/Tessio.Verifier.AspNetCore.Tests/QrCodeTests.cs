using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>The start page renders the authorization request as a scannable QR code.</summary>
public sealed class QrCodeTests
{
    [Fact]
    public async Task StartPage_RendersQrCode_ForTheAuthorizationRequest()
    {
        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
                })
                .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
            .Start();

        var html = await host.GetTestClient().GetStringAsync("/verify/start");

        Assert.Contains("<svg", html, StringComparison.Ordinal);
        Assert.Contains("openid4vp", html, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderQrCode_ShortPayload_ProducesSvg()
    {
        var svg = TessioVerifierEndpointRouteBuilderExtensions.RenderQrCode(
            "openid4vp://authorize?client_id=x&request_uri=https%3A%2F%2Fverifier.example%2Fverify%2Frequest%2Fabc");

        Assert.StartsWith("<svg", svg.TrimStart(), StringComparison.Ordinal);
    }

    [Fact]
    public void RenderQrCode_PayloadBeyondQrCapacity_FallsBackToEmpty()
    {
        // QR version 40 tops out below 3 KB of binary payload; a huge by-value JAR must not break the page.
        var svg = TessioVerifierEndpointRouteBuilderExtensions.RenderQrCode(new string('a', 8000));

        Assert.Equal(string.Empty, svg);
    }
}
