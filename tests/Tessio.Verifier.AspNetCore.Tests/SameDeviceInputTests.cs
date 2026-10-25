using System.Net;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// What the same-device routes accept from a browser: the content types, bodies and cookies they take and
/// refuse, and the cookie they set. The flow itself is in <see cref="SameDeviceFlowTests"/>.
/// </summary>
public sealed class SameDeviceInputTests
{
    [Fact]
    public async Task ARequestFromAnotherSite_IsRefusedBeforeAnySessionOrCookie()
    {
        await using var host = new SameDeviceHost();

        // What a form on another site can send without a CORS preflight.
        var response = await host.Client.PostAsync("/verify/same-device",
            new StringContent("x=1", Encoding.UTF8, "application/x-www-form-urlencoded"));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task TheBindingCookie_IsHostOnlyHttpOnlySecureAndLax()
    {
        await using var host = new SameDeviceHost();

        var started = await host.StartSameDeviceAsync();

        var setCookie = Assert.Single(started.Response.Headers.GetValues("Set-Cookie")).ToLowerInvariant();
        Assert.StartsWith($"{SameDeviceHost.CookieName.ToLowerInvariant()}=", setCookie);
        Assert.Contains("httponly", setCookie);
        Assert.Contains("secure", setCookie);
        Assert.Contains("samesite=lax", setCookie);
        Assert.Contains("path=/", setCookie);
        Assert.DoesNotContain("domain=", setCookie);
        Assert.Contains($"max-age={(int)TimeSpan.FromDays(1).TotalSeconds}", setCookie);
        Assert.Equal("no-store", started.Response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task AnOverlongCookie_IsReplacedRatherThanReused()
    {
        await using var host = new SameDeviceHost();
        var overlong = SameDeviceSecrets.NewSecret() + new string('a', SameDeviceSecrets.MaxSecretLength);

        var started = await host.StartSameDeviceAsync(overlong);

        Assert.NotEqual(overlong, started.Cookie);
        Assert.True(started.Cookie!.Length <= SameDeviceSecrets.MaxSecretLength);
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded", "responseCode=x", HttpStatusCode.UnsupportedMediaType)]
    [InlineData("application/json", "{not json", HttpStatusCode.BadRequest)]
    [InlineData("application/json", "{}", HttpStatusCode.BadRequest)]
    [InlineData("application/json", "{\"responseCode\":\"\"}", HttpStatusCode.BadRequest)]
    public async Task AMalformedRedemption_IsRefusedUnread(string contentType, string body, HttpStatusCode expected)
    {
        await using var host = new SameDeviceHost();
        var session = await host.CreateCrossDeviceSessionAsync();

        var response = await host.Client.PostAsync($"/verify/{session.SessionId}/redeem",
            new StringContent(body, Encoding.UTF8, contentType));

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [InlineData("application/json; charset=bogus")]
    [InlineData("application/json; charset=utf-7")]
    [InlineData("application/json; charset=\"utf-8\"")]
    public async Task ARedemptionInACharsetTheJsonReaderCannotDecode_IsRefusedAsUnsupported(string contentType)
    {
        // ASP.NET Core's JSON reader throws for a charset Encoding.GetEncoding will not return as written: an
        // unknown name, a disabled one, or a quoted value. So the content type is refused before the body is read.
        var response = await RedeemAsync(contentType);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("application/json; charset=UTF-8")]
    [InlineData("application/json; charset=iso-8859-1")]
    public async Task ARedemptionInACharsetTheJsonReaderDecodes_IsRead(string contentType)
    {
        // The control: these reach the reader and the redemption. The code matches nothing held, so it is not
        // redeemed, but it was read.
        var response = await RedeemAsync(contentType);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task StartingASameDeviceRequest_DoesNotJudgeTheCharsetOfABodyItNeverReads()
    {
        await using var host = new SameDeviceHost();
        var content = new ByteArrayContent("{}"u8.ToArray());
        content.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=bogus");

        var response = await host.Client.PostAsync("/verify/same-device", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> RedeemAsync(string contentType)
    {
        await using var host = new SameDeviceHost();
        var session = await host.CreateCrossDeviceSessionAsync();
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes("{\"responseCode\":\"x\"}"));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        return await host.Client.PostAsync($"/verify/{session.SessionId}/redeem", content);
    }

    [Fact]
    public async Task ARedemptionCodeLongerThanAnyMinted_IsRefusedUnread()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        var response = await host.Client.PostAsync($"/verify/{sessionId}/redeem", System.Net.Http.Json.JsonContent.Create(
            new { responseCode = code + new string('a', SameDeviceSecrets.MaxSecretLength) }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task OneBrowser_KeepsOneSecretAcrossTheRequestsItStarts()
    {
        await using var host = new SameDeviceHost();
        var first = await host.StartSameDeviceAsync();
        var second = await host.StartSameDeviceAsync(first.Cookie);

        // Both requests stay redeemable from the one browser: the second did not replace the first's binding.
        Assert.Equal(first.Cookie, second.Cookie);
        var (_, firstId, firstCode) = await SameDeviceHost.RedirectOf(await host.PresentAsync(first));
        Assert.Equal("redeemed", await host.RedeemAsync(firstId, firstCode, first.Cookie));
    }

    [Fact]
    public async Task ABrowserWithNoCookie_IsHandedABindingNoStoreCouldHave()
    {
        // The binding check lives in the store, and a store must not be able to read an absent cookie as a
        // match. So the store is never handed a value it could predict, not even for one code redeemed twice.
        BindingRecordingStore? store = null;
        await using var host = new SameDeviceHost(
            store: sp => store = new BindingRecordingStore(sp.GetRequiredService<InMemorySessionStore>()));
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        await host.RedeemAsync(sessionId, code, cookie: null);
        await host.RedeemAsync(sessionId, code, cookie: null);

        Assert.Equal(2, store!.RedeemedWith.Count);
        Assert.NotEqual(store.RedeemedWith[0], store.RedeemedWith[1]);
    }
}
