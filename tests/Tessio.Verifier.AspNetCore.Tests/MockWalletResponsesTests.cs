using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The public wallet-response helper, exercised the way an external host does: self-drive the
/// protocol, mint a response for your own session, verify it through the public
/// <see cref="IWalletResponseVerifier"/> seam. Nothing here touches MOCK mode's /start endpoint.
/// </summary>
public sealed class MockWalletResponsesTests : IDisposable
{
    private readonly MockWalletResponses _wallet = new();

    /// <summary>Builds a verifier that trusts (or does not trust) the helper's ephemeral issuer.</summary>
    private ServiceProvider BuildVerifier(bool trustTheHelpersIssuer)
    {
        var services = new ServiceCollection();

        // Registered first so it wins over AddTessioVerifier's TryAddSingleton dev default.
        services.AddSingleton<ITrustListResolver>(_ => trustTheHelpersIssuer
            ? new StaticTrustListResolver(
                [MockWalletResponses.IssuerId], "test", [_wallet.IssuerCertificate])
            : new StaticTrustListResolver([MockWalletResponses.IssuerId], "test"));

        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.RequestedClaims = ["age_over_18"];
        });

        return services.BuildServiceProvider();
    }

    private static async Task<VerificationSession> CreateSessionAsync(ServiceProvider provider)
    {
        var store = provider.GetRequiredService<InMemorySessionStore>();
        var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        return await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));
    }

    [Fact]
    public async Task Response_VerifiesAgainstItsSession_WhenTheIssuerIsTrusted()
    {
        await using var provider = BuildVerifier(trustTheHelpersIssuer: true);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateSdJwtResponse(session);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, response);

        Assert.True(result.IsValid,
            string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task Response_IsRejected_WhenTheIssuerCertificateIsNotAnchored()
    {
        // Guards against a vacuous helper: the presentation must actually be trust-checked, so a
        // consumer that forgets to anchor IssuerCertificate gets a failure, not a false pass.
        await using var provider = BuildVerifier(trustTheHelpersIssuer: false);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateSdJwtResponse(session);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, response);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Response_CarriesTheSessionState_SoTheHostCanCorrelateIt()
    {
        await using var provider = BuildVerifier(trustTheHelpersIssuer: true);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateSdJwtResponse(session);

        Assert.Equal(session.Request.State, Assert.Single(response.Form["state"]));
    }

    public void Dispose() => _wallet.Dispose();
}
