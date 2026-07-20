using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Registration entry point for the Tessio verifier.
/// </summary>
public static class TessioVerifierServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Tessio verifier: the session store, the credential verification pipeline
    /// (<see cref="SdJwtVcVerifier"/> + <see cref="WalletResponseParser"/>), and the DEMO / MOCK
    /// mode engines. Pair with
    /// <see cref="TessioVerifierEndpointRouteBuilderExtensions.MapTessioVerifier"/> to expose the endpoints.
    /// </summary>
    /// <remarks>
    /// All services are registered with <c>TryAdd</c>: register your own
    /// <see cref="ITrustListResolver"/>, <see cref="ISessionStore"/>, or
    /// <see cref="IPresentationRequestBuilder"/> before calling this method to replace a default.
    /// The default trust list contains only the built-in demo and mock issuers.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures <see cref="VerifierOptions"/> (mode, requested claims, …).</param>
    public static IServiceCollection AddTessioVerifier(this IServiceCollection services, Action<VerifierOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<DemoCompletionQueue>();
        services.TryAddSingleton<MockWalletQueue>();
        services.TryAddSingleton<MockCredentialIssuer>();

        // Default (demo) request builder — swap in SignedPresentationRequestBuilder for live wallets.
        services.TryAddSingleton<IPresentationRequestBuilder, DemoPresentationRequestBuilder>();

        // The real verification pipeline: response parsing (OpenID4VP) + credential verification (Core).
        services.TryAddSingleton<WalletResponseParser>();
        services.TryAddSingleton<IPresentationResponseParser>(sp => sp.GetRequiredService<WalletResponseParser>());
        services.TryAddSingleton<ITrustListResolver>(new StaticTrustListResolver(
            [MockCredentialIssuer.Issuer, "https://demo-issuer.tessio.dev"], source: "tessio-dev-defaults"));
        services.TryAddSingleton<ICredentialVerifier>(sp => new SdJwtVcVerifier(
            sp.GetRequiredService<ITrustListResolver>(),
            clock: sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<WalletCallbackProcessor>();

        services.TryAddSingleton<InMemorySessionStore>();
        services.TryAddSingleton<ISessionStore>(sp => sp.GetRequiredService<InMemorySessionStore>());

        services.AddHostedService<DemoCompletionService>();
        services.AddHostedService<MockWalletService>();

        return services;
    }
}
