using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Sandbox completion for hosts that create sessions themselves (bypassing the built-in <c>/start</c>
/// endpoint) but still want DEMO-style auto-completion. The <c>/start</c> endpoint enqueues into the
/// background demo completer; a self-driving host never reaches that path, so its sessions would otherwise
/// hang. This exposes the completion explicitly.
/// </summary>
/// <remarks>
/// For demos, samples and tests only: the result is synthesized from the configured requested claims, not
/// verified against a real credential. Never use it on a Live deployment. Resolve it from DI after
/// <see cref="TessioVerifierServiceCollectionExtensions.AddTessioVerifier"/>.
/// </remarks>
public sealed class TessioVerifierSandbox
{
    private readonly ISessionStore _store;
    private readonly VerifierOptions _options;

    /// <summary>Creates the sandbox over the registered session store and options.</summary>
    public TessioVerifierSandbox(ISessionStore store, IOptions<VerifierOptions> options)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(options);
        _store = store;
        _options = options.Value;
    }

    /// <summary>
    /// Completes <paramref name="sessionId"/> immediately with a synthesized valid result built from
    /// <see cref="VerifierOptions.RequestedClaims"/>, independent of mode and without the background
    /// completer. Use this from your own creation flow where the built-in <c>/start</c> demo path is not
    /// in play.
    /// </summary>
    public Task CompleteWithDemoResultAsync(string sessionId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        return _store.CompleteAsync(sessionId, DemoVerificationResultFactory.Create(_options), ct);
    }
}
