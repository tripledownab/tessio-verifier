using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Live mode fails fast on demo configuration, dev-mode engines are only hosted in their own mode,
/// and a spoofed x5c issuer is rejected end to end by the anchored dev trust default.
/// </summary>
public sealed class LiveModeGuardTests
{
    private static IHost BuildHost(Action<IServiceCollection> configureServices) => new HostBuilder()
        .ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(configureServices)
            .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
        .Build();

    [Fact]
    public void LiveMode_WithDemoRequestBuilder_FailsFast()
    {
        using var host = BuildHost(services =>
        {
            services.AddRouting();
            services.AddTessioVerifier(options => options.Mode = VerifierMode.Live);
        });

        var ex = Assert.Throws<InvalidOperationException>(host.Start);
        Assert.Contains("SignedPresentationRequestBuilder", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LiveMode_WithDevTrustList_FailsFast()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = BuildHost(services =>
        {
            services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
                new PresentationRequestBuilderOptions
                {
                    SigningCredentials = new SigningCredentials(
                        new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                }));
            services.AddRouting();
            services.AddTessioVerifier(options => options.Mode = VerifierMode.Live);
        });

        var ex = Assert.Throws<InvalidOperationException>(host.Start);
        Assert.Contains("trust list", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(VerifierMode.Demo, typeof(DemoCompletionService))]
    [InlineData(VerifierMode.Mock, typeof(MockWalletService))]
    [InlineData(VerifierMode.Test, typeof(TestFixtureService))]
    public void OnlyTheModesOwnEngine_IsHosted(VerifierMode mode, Type expected)
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = mode);
        using var provider = services.BuildServiceProvider();

        var hosted = provider.GetServices<IHostedService>().ToList();
        Assert.Single(hosted);
        Assert.IsType(expected, hosted[0]);
    }

    [Fact]
    public void LiveMode_HostsNoDevEngines()
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Live);
        using var provider = services.BuildServiceProvider();

        Assert.Empty(provider.GetServices<IHostedService>());
    }

    [Fact]
    public async Task SpoofedX5cIssuer_SameIssuerString_IsRejectedEndToEnd()
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        await using var provider = services.BuildServiceProvider();

        var store = provider.GetRequiredService<InMemorySessionStore>();
        var options = provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var processor = provider.GetRequiredService<WalletCallbackProcessor>();

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // An attacker's own issuer: same iss string and SAN as the trusted mock issuer, but a
        // self-signed certificate the trust anchor has never seen. Nonce and audience are correct,
        // so only the trust anchoring stands between this credential and a valid result.
        using var spoofedIssuer = new MockCredentialIssuer();
        var presentation = spoofedIssuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, session.Request.Nonce, options.ClientId);

        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                ["state"] = new[] { session.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        Assert.Equal(CallbackOutcome.Completed, await processor.ProcessAsync(response, CancellationToken.None));

        var terminal = await store.GetAsync(session.SessionId);
        Assert.False(terminal!.Result!.IsValid);
        Assert.Contains(terminal.Result.Errors, e => e.Code == "issuer_untrusted");
    }
}
