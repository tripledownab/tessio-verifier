using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The trust resolver AddTessioVerifier registers when the app supplies none: trusts the built-in
/// demo and mock issuers, with the mock issuer's own certificate pinned as the x5c anchor. A
/// distinct type so <see cref="VerifierMode.Live"/> can detect and reject this dev default at startup.
/// </summary>
internal sealed class DevDefaultTrustListResolver : ITrustListResolver
{
    private readonly StaticTrustListResolver _inner;

    public DevDefaultTrustListResolver(MockCredentialIssuer mockIssuer) => _inner = new StaticTrustListResolver(
        [MockCredentialIssuer.Issuer, "https://demo-issuer.tessio.dev"],
        source: "tessio-dev-defaults",
        trustAnchors: [mockIssuer.Certificate]);

    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
        _inner.ResolveAsync(issuer, x5c, ct);
}
