using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Trust resolver backed by a fixed set of trusted issuer identifiers, plus optional trust-anchor
/// certificates for issuers that present an X.509 chain. Suitable for development, tests and small
/// deployments. Load the identifier set from a JSON file or URL with <see cref="TrustListLoader"/>.
/// </summary>
/// <remarks>
/// <para>
/// Credentials whose key was resolved from an <c>x5c</c> header are only trusted when their chain
/// anchors on one of <c>trustAnchors</c> (or the leaf itself is a pinned anchor). Identifier
/// membership alone proves nothing for those credentials: the signing key comes from the presented
/// certificate, and anyone can put a trusted issuer's name in a self-signed certificate. Without
/// configured anchors, x5c credentials are therefore rejected.
/// </para>
/// <para>
/// This is the open-source end of the trust seam. Production EU trust (LOTL, national lists, WRPAC)
/// is a separate concern behind the same <see cref="ITrustListResolver"/> interface.
/// </para>
/// </remarks>
public sealed class StaticTrustListResolver : ITrustListResolver
{
    private readonly HashSet<string> _trustedIssuers;
    private readonly List<X509Certificate2> _trustAnchors;
    private readonly string _source;

    /// <summary>Creates a resolver trusting exactly the given issuer identifiers.</summary>
    /// <param name="trustedIssuers">Issuer identifiers (iss values or certificate subjects).</param>
    /// <param name="source">Optional label reported as <see cref="IssuerTrustStatus.TrustListSource"/>.</param>
    /// <param name="trustAnchors">
    /// Root or pinned certificates that x5c chains must anchor on. Credentials presenting an x5c
    /// chain are rejected when this is empty.
    /// </param>
    public StaticTrustListResolver(
        IEnumerable<string> trustedIssuers,
        string source = "static",
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        _trustedIssuers = new HashSet<string>(trustedIssuers, StringComparer.Ordinal);
        _trustAnchors = trustAnchors?.ToList() ?? [];
        _source = source;
    }

    /// <inheritdoc />
    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(x5c);

        if (!_trustedIssuers.Contains(issuer))
        {
            return NotTrusted($"Issuer '{issuer}' is not on the configured trust list.");
        }

        if (x5c.Length == 0)
        {
            // Key resolved via issuer metadata: the identifier was proven by control of the iss
            // HTTPS origin, so identifier membership is the whole check here.
            return Trusted();
        }

        if (_trustAnchors.Count == 0)
        {
            return NotTrusted(
                $"Issuer '{issuer}' presented an X.509 chain, but this trust list has no trust anchors. " +
                "An identifier-only list cannot vouch for x5c credentials; configure trustAnchors.");
        }

        return ChainAnchorsOnConfiguredRoot(x5c)
            ? Trusted()
            : NotTrusted($"The certificate chain presented by '{issuer}' does not anchor on a configured trust anchor.");
    }

    private bool ChainAnchorsOnConfiguredRoot(ReadOnlyMemory<byte>[] x5c)
    {
        var certificates = x5c.Select(der => new X509Certificate2(der.ToArray())).ToList();
        try
        {
            var leaf = certificates[0];

            // Pinned leaf: the exact end-entity certificate was configured as an anchor.
            if (_trustAnchors.Any(anchor => anchor.RawData.AsSpan().SequenceEqual(leaf.RawData)))
            {
                return true;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            // Certificate revocation is the production trust layer's concern; credential revocation
            // is checked separately via Token Status Lists.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            foreach (var anchor in _trustAnchors)
            {
                chain.ChainPolicy.CustomTrustStore.Add(anchor);
            }

            foreach (var intermediate in certificates.Skip(1))
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            return chain.Build(leaf);
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private Task<IssuerTrustStatus> Trusted() =>
        Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = _source });

    private static Task<IssuerTrustStatus> NotTrusted(string reason) =>
        Task.FromResult(new IssuerTrustStatus { Trusted = false, Reason = reason });
}
