using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// What the routes that build a <c>response_uri</c> or <c>redirect_uri</c> from the request's own scheme and
/// host do with a host that makes no URI (<see cref="RequestOrigin"/>). The host is the caller's to send.
/// </summary>
public sealed class RequestHostTests
{
    // Kestrel accepts both Host headers. The first names a port out of range, which the URI parser refuses. The
    // second is an IDN label HttpRequest.Host cannot decode, which its getter throws for.
    public static TheoryData<string, string, string, string> Routes => new()
    {
        { "localhost:99999", "GET", "/verify/start", "" },
        { "xn--zz", "GET", "/verify/start", "" },
        { "localhost:99999", "POST", "/verify/same-device", "application/json" },
        { "xn--zz", "POST", "/verify/same-device", "application/json" },
        { "localhost:99999", "POST", "/verify/callback", "application/x-www-form-urlencoded" },
        { "xn--zz", "POST", "/verify/callback", "application/x-www-form-urlencoded" },
    };

    [Theory]
    [MemberData(nameof(Routes))]
    public async Task AHostThatMakesNoUri_IsABadRequestThatBindsNoBrowser(string hostHeader, string method, string path, string contentType)
    {
        await using var host = new SameDeviceHost();
        var server = (TestServer)host.Services.GetRequiredService<IServer>();

        var answered = await server.SendAsync(context =>
        {
            context.Request.Method = method;
            context.Request.Path = path;
            context.Request.Host = new HostString(hostHeader);
            if (contentType.Length > 0)
            {
                context.Request.ContentType = contentType;
                context.Request.Body = new MemoryStream(
                    contentType.EndsWith("json", StringComparison.Ordinal) ? "{}"u8.ToArray() : "state=s"u8.ToArray());
            }
        });

        Assert.Equal(StatusCodes.Status400BadRequest, answered.Response.StatusCode);
        Assert.False(answered.Response.Headers.ContainsKey("Set-Cookie"));
        if (path == "/verify/callback")
        {
            // The callback answers an unknown state 400 too, so the error is what shows the host was the reason.
            var body = await new StreamReader(answered.Response.Body).ReadToEndAsync();
            Assert.Contains("invalid_request", body, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("javascript", StatusCodes.Status400BadRequest)]
    [InlineData("ftp", StatusCodes.Status400BadRequest)]
    [InlineData("HTTPS", StatusCodes.Status200OK)]
    public async Task OnlyAnHttpOrHttpsScheme_StartsASession(string scheme, int expected)
    {
        // A forwarding proxy sets the scheme, and the wallet is handed a URI built from it.
        await using var host = new SameDeviceHost();
        var server = (TestServer)host.Services.GetRequiredService<IServer>();

        var answered = await server.SendAsync(context =>
        {
            context.Request.Method = "GET";
            context.Request.Path = "/verify/start";
            context.Request.Scheme = scheme;
        });

        Assert.Equal(expected, answered.Response.StatusCode);
    }

    [Fact]
    public async Task AnOrdinaryHost_StillStartsASession()
    {
        // The control: the same request with a host that makes a URI.
        await using var host = new SameDeviceHost();

        var response = await host.Client.GetAsync("/verify/start");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
