using System.Net;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The same-device flow end to end over HTTP: a request bound to the browser that asked for it, a verified
/// presentation held until that browser redeems the response code its redirect carries, and the
/// rejections HAIP 1.0 section 5.1 requires when the wallet does not come back or comes back elsewhere.
/// </summary>
public sealed class SameDeviceFlowTests
{
    [Fact]
    public async Task AVerifiedPresentation_IsHeldUntilItsBrowserRedeemsIt()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();

        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionAsync(sessionId)).Status);

        Assert.Equal("redeemed", await host.RedeemAsync(sessionId, code, started.Cookie));

        var session = await host.SessionAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Completed, session.Status);
        Assert.True(session.Result!.IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARedirectArrivingInAnotherBrowser_IsRejected(bool otherBrowserHasACookie)
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        // A browser with its own binding, from starting a request of its own, or one with none at all.
        var otherCookie = otherBrowserHasACookie ? (await host.StartSameDeviceAsync()).Cookie : null;
        Assert.Equal("session_mismatch", await host.RedeemAsync(sessionId, code, otherCookie));

        var session = await host.SessionAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Completed, session.Status);
        Assert.False(session.Result!.IsValid);
        Assert.Equal(ErrorCodes.SessionMismatch, Assert.Single(session.Result.Errors).Code);
        Assert.Empty(session.Result.DisclosedClaims);

        // The rejection spent the held presentation: the right browser coming later finds nothing.
        Assert.Equal("not_held", await host.RedeemAsync(sessionId, code, started.Cookie));
    }

    [Fact]
    public async Task WithCompleteOnlyOnValidResponse_ARejectedRedirectIsAFailedAttempt()
    {
        await using var host = new SameDeviceHost(completeOnlyOnValidResponse: true);
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        Assert.Equal("session_mismatch", await host.RedeemAsync(sessionId, code, cookie: null));

        var session = await host.SessionAsync(sessionId);
        Assert.Equal(VerificationSessionStatus.Pending, session.Status);
        Assert.Equal(1, session.FailedAttempts);
        Assert.Equal(ErrorCodes.SessionMismatch, Assert.Single(session.LastFailure!.Errors).Code);

        // The session stays open, but not for that presentation: it was rejected, not set aside.
        Assert.Equal("not_held", await host.RedeemAsync(sessionId, code, started.Cookie));
    }

    [Fact]
    public async Task AWalletThatDoesNotComeBack_NeverCompletesTheSession()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        host.Clock.Advance(SameDeviceSecrets.RedemptionWindow);

        Assert.Equal("not_held", await host.RedeemAsync(sessionId, code, started.Cookie));
        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionAsync(sessionId)).Status);

        // The lapsed hold leaves the session open for the wallet to answer again.
        var (_, _, second) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));
        Assert.Equal("redeemed", await host.RedeemAsync(sessionId, second, started.Cookie));
    }

    [Fact]
    public async Task ASessionThatExpiresDuringTheWindow_CannotBeRedeemed()
    {
        // The window outlives the session here, which is the case where only the session's own expiry stands
        // between a late redemption and a valid verdict for a session that has already ended.
        await using var host = new SameDeviceHost(sessionLifetime: SameDeviceSecrets.RedemptionWindow / 2);
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        host.Clock.Advance(SameDeviceSecrets.RedemptionWindow * 3 / 4);

        Assert.Equal("not_held", await host.RedeemAsync(sessionId, code, started.Cookie));
        Assert.Equal(VerificationSessionStatus.Expired, (await host.SessionAsync(sessionId)).Status);
    }

    [Fact]
    public async Task ASecondResponseWhileOneIsHeld_IsRefused()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();
        await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        var second = await host.PresentAsync(started);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task AWrongCode_RedeemsNothing()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, _) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        Assert.Equal("not_held", await host.RedeemAsync(sessionId, SameDeviceSecrets.NewSecret(), started.Cookie));
        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionAsync(sessionId)).Status);
    }

    [Fact]
    public async Task ACrossDeviceSession_CompletesAtOnce_AndItsRedirectCodeRedeemsNothing()
    {
        await using var host = new SameDeviceHost();
        var session = await host.CreateCrossDeviceSessionAsync();

        var (returnPage, sessionId, code) = await SameDeviceHost.RedirectOf(
            await host.PresentAsync(session.Request.State!, session.Request.Nonce));

        Assert.Equal(session.SessionId, sessionId);
        Assert.Equal($"/verify/{session.SessionId}/return", returnPage.AbsolutePath);
        Assert.Equal(VerificationSessionStatus.Completed, (await host.SessionAsync(sessionId)).Status);
        Assert.Equal("not_held", await host.RedeemAsync(sessionId, code, cookie: null));
        Assert.True((await host.SessionAsync(sessionId)).Result!.IsValid);
    }
}
