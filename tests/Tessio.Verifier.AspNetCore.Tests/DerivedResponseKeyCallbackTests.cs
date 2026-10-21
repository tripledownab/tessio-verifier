// What belongs here: what a derived response key that cannot be derived again does at the callback
// endpoint itself. The store's own behaviour is DerivedResponseKeyStoreTests'.
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedResponseKeyCallbackTests
{
    [Fact]
    public async Task A_salt_under_another_master_escapes_the_callback_instead_of_reading_as_an_unknown_key()
    {
        var salts = new SaltTable();
        using var otherDeployment = new ResponseEncryptionKeyStore(TimeProvider.System, Options(salts));
        var keys = otherDeployment.CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5));

        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services
                    .AddRouting()
                    .AddSingleton(sp => new ResponseEncryptionKeyStore(sp.GetRequiredService<TimeProvider>(), Options(salts)))
                    .AddTessioVerifier(options => options.Mode = VerifierMode.Mock))
                .Configure(app => app
                    .UseRouting()
                    .UseEndpoints(endpoints => endpoints.MapTessioVerifier())))
            .Start();

        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response"] = DerivedResponseKeyFixtures.EncryptedResponse(keys).Form["response"][0],
        });

        // The test server hands an unhandled exception to the caller; a real server answers 500.
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.GetTestClient().PostAsync("/verify/callback", form));
        Assert.Contains("master", refused.Message, StringComparison.Ordinal);
    }

    // A fresh master each call, so the two stores above disagree.
    private static ResponseKeyDerivationOptions Options(IResponseKeySaltStore salts) => new()
    {
        Master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength),
        Salts = salts,
    };
}
