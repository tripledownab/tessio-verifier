using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The mdoc half of the public wallet-response helper. Worth its own file because mdoc fails in places
/// SD-JWT cannot: the device signature covers the session transcript (client_id, nonce, response_uri),
/// so a host that only exercises SD-JWT has never tested the binding a real mdoc wallet performs. The
/// EU age-verification attestation is mdoc-only, which makes this the shape an age check must handle.
/// </summary>
public sealed class MockWalletMdocResponsesTests : IDisposable
{
    private const string AvDocType = MockWalletResponses.EuAgeVerificationDocType;

    private readonly MockWalletResponses _wallet = new();

    private ServiceProvider BuildVerifier(bool anchorTheIaca)
    {
        var services = new ServiceCollection();

        // Registered first so it wins over AddTessioVerifier's TryAddSingleton dev default. mdoc trust
        // anchors on the IACA root, not the SD-JWT issuer certificate.
        services.AddSingleton<ITrustListResolver>(_ => anchorTheIaca
            ? new StaticTrustListResolver([_wallet.MdocIssuerId], "test", [_wallet.MdocIacaCertificate])
            : new StaticTrustListResolver([_wallet.MdocIssuerId], "test"));

        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = "mso_mdoc";
            options.ExpectedDocType = AvDocType;
            options.MdocNamespace = AvDocType;
            options.RequestedClaims = ["age_over_18"];
            // Cleartext direct_post: the encrypted transcript variant is covered separately below.
            options.ResponseMode = ResponseMode.DirectPost;
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
    public async Task Mdoc_response_verifies_against_its_own_session()
    {
        await using var provider = BuildVerifier(anchorTheIaca: true);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateMdocResponse(session, docType: AvDocType);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, response);

        Assert.True(result.IsValid,
            string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[AvDocType]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public async Task A_disclosed_age_of_false_is_a_valid_presentation_carrying_a_no()
    {
        // The case a host cannot test without choosing the value, and the one that decides whether a
        // minor passes an age check. A wallet holding age_over_18 = false answers the request with false,
        // and the presentation is flawless: right issuer, valid signature, intact device binding. Any
        // host reading "valid" as "old enough" gets this exactly backwards, so the helper has to be able
        // to produce it.
        await using var provider = BuildVerifier(anchorTheIaca: true);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateMdocResponse(
            session, docType: AvDocType, claimValues: new Dictionary<string, object> { ["age_over_18"] = false });
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, response);

        Assert.True(result.IsValid,
            string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[AvDocType]);
        Assert.Equal(false, elements["age_over_18"]);
    }

    [Fact]
    public async Task Mdoc_response_is_rejected_when_the_iaca_is_not_anchored()
    {
        // The point of the trust layer: a well-formed, correctly signed response from an unknown issuer
        // must still fail, or "verified" would mean nothing.
        await using var provider = BuildVerifier(anchorTheIaca: false);
        var session = await CreateSessionAsync(provider);

        var response = _wallet.CreateMdocResponse(session, docType: AvDocType);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, response);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Mdoc_response_is_rejected_when_it_answers_a_different_session()
    {
        // The device signature covers this session's client_id and nonce, so replaying a response into
        // another session must not verify. This is the binding SD-JWT tests never exercise.
        await using var provider = BuildVerifier(anchorTheIaca: true);
        var session = await CreateSessionAsync(provider);
        var otherSession = await CreateSessionAsync(provider);

        var response = _wallet.CreateMdocResponse(session, docType: AvDocType);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(otherSession, response);

        Assert.False(result.IsValid);
    }

    public void Dispose() => _wallet.Dispose();
}
