using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Registration entry point for the Tessio verifier.
/// </summary>
public static class TessioVerifierServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Tessio verifier services: the session store, the DEMO request builder and completion
    /// worker, and the options. Pair with
    /// <see cref="TessioVerifierEndpointRouteBuilderExtensions.MapTessioVerifier"/> to expose the endpoints.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures <see cref="VerifierOptions"/> (mode, requested claims, …).</param>
    public static IServiceCollection AddTessioVerifier(this IServiceCollection services, Action<VerifierOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<DemoCompletionQueue>();

        // Default (demo) request builder — superseded when Tessio.Verifier.OpenId4Vp registers a real one.
        services.TryAddSingleton<IPresentationRequestBuilder, DemoPresentationRequestBuilder>();

        services.TryAddSingleton<InMemorySessionStore>();
        services.TryAddSingleton<ISessionStore>(sp => sp.GetRequiredService<InMemorySessionStore>());

        services.AddHostedService<DemoCompletionService>();

        return services;
    }
}
