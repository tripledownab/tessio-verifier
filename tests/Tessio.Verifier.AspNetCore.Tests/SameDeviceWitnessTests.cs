using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// How the callback decides a session is same-device: the store's binding and the request's own
/// <c>response_uri</c> are two witnesses, either one holds the presentation, and losing one fails closed.
/// </summary>
public sealed class SameDeviceWitnessTests
{
    [Fact]
    public async Task AStoreThatLosesTheBinding_RefusesThePresentationInsteadOfCompleting()
    {
        await using var host = new SameDeviceHost(store: sp => new BindingLosingStore(sp.GetRequiredService<InMemorySessionStore>()));
        var started = await host.StartSameDeviceAsync();

        var response = await host.PresentAsync(started);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionByStateAsync(started.State)).Status);
    }

    [Fact]
    public async Task ABoundSessionsResponse_IsHeldWhicheverCallbackPathItArrivesOn()
    {
        await using var host = new SameDeviceHost();
        var started = await host.StartSameDeviceAsync();

        // The plain cross-device callback path, not the one the bound request names.
        var (_, sessionId, _) = await SameDeviceHost.RedirectOf(
            await host.PresentAsync(started.State, started.Nonce, "/verify/callback"));

        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionAsync(sessionId)).Status);
    }

    [Fact]
    public async Task ABindingWithoutTheMark_IsStillHeld()
    {
        // The reverse of a lost binding: a request that does not say same-device, for a session the store
        // bound. Either witness is enough to hold.
        await using var host = new SameDeviceHost();
        var store = host.Services.GetRequiredService<InMemorySessionStore>();
        var options = host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateBoundAsync(
            DemoRequestOptionsFactory.Create(options, new Uri("http://localhost/verify/callback")),
            SameDeviceSecrets.Hash(SameDeviceSecrets.NewSecret()));

        var response = await host.PresentAsync(session.Request.State!, session.Request.Nonce);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(VerificationSessionStatus.Pending, (await host.SessionAsync(session.SessionId)).Status);
    }

    [Fact]
    public async Task ABuilderThatDropsTheResponseUri_CannotMintASameDeviceRequest()
    {
        await using var host = new SameDeviceHost(builder: inner => new FixedResponseUriBuilder(inner));

        await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartSameDeviceAsync());
    }

    [Theory]
    [InlineData("http://localhost/verify/callback/same-device", true)]
    [InlineData("http://localhost/verify/callback/same-device/", true)]
    [InlineData("http://localhost/VERIFY/Callback/Same-Device", true)]
    [InlineData("http://localhost/verify/callback", false)]
    [InlineData("http://localhost/verify/same-device", false)]
    public async Task TheMark_IsReadAsRoutingWouldReadTheResponseUri(string responseUri, bool sameDevice)
    {
        await using var host = new SameDeviceHost();
        var options = host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var request = await new DemoPresentationRequestBuilder(TimeProvider.System)
            .BuildAsync(DemoRequestOptionsFactory.Create(options, new Uri(responseUri)));

        Assert.Equal(sameDevice, SameDeviceRequests.IsSameDevice(request));
    }

    /// <summary>A builder that ignores the response URI it is given, as a careless host builder might.</summary>
    private sealed class FixedResponseUriBuilder(IPresentationRequestBuilder inner) : IPresentationRequestBuilder
    {
        public Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
            inner.BuildAsync(options with { ResponseUri = new Uri("http://localhost/verify/callback") }, ct);
    }
}
