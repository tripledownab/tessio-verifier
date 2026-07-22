using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The v0.2 pipeline test: MOCK mode with <c>mso_mdoc</c> issues a real ISO 18013-5 DeviceResponse
/// (IACA chain, MSO, device-signed session transcript) and pushes it through response parsing,
/// mdoc verification and session completion using the exact service graph AddTessioVerifier registers.
/// </summary>
public sealed class MdocMockModeTests
{
    private static async Task<VerificationSession> RunSessionAsync(ResponseMode responseMode)
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = "mso_mdoc";
            options.ResponseMode = responseMode;
            options.RequestedClaims = ["family_name", "age_over_18"];
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
            var encryptionJwk = responseMode == ResponseMode.DirectPostJwt
                ? provider.GetRequiredService<ResponseEncryptionKeyProvider>().PublicJwk
                : null;
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

    [Theory]
    [InlineData(ResponseMode.DirectPost)]
    [InlineData(ResponseMode.DirectPostJwt)]
    public async Task MockMode_Mdoc_VerifiesEndToEnd(ResponseMode responseMode)
    {
        var terminal = await RunSessionAsync(responseMode);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        var result = terminal.Result!;
        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        Assert.True(result.Issuer.Trusted);
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Contains("Tessio Mock Document Signer", result.Issuer.Identifier, StringComparison.Ordinal);

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims["org.iso.18013.5.1"]);
        Assert.Equal("Mustermann", elements["family_name"]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public void MdocDcqlQuery_UsesDoctypeAndTwoElementPaths()
    {
        var options = new VerifierOptions
        {
            CredentialFormat = "mso_mdoc",
            RequestedClaims = ["age_over_18"],
        };

        var requestOptions = DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback"));

        Assert.Contains("\"format\":\"mso_mdoc\"", requestOptions.DcqlQueryJson, StringComparison.Ordinal);
        Assert.Contains("\"doctype_value\":\"org.iso.18013.5.1.mDL\"", requestOptions.DcqlQueryJson, StringComparison.Ordinal);
        Assert.Contains("\"path\":[\"org.iso.18013.5.1\",\"age_over_18\"]", requestOptions.DcqlQueryJson, StringComparison.Ordinal);
    }
}
