namespace Tessio.Verifier.Trust;

/// <summary>
/// Trust resolver backed by a fixed set of trusted issuer identifiers. Suitable for development,
/// tests and small deployments. Load the set from a JSON file or URL with <see cref="TrustListLoader"/>.
/// </summary>
/// <remarks>
/// This is the open-source end of the trust seam. Production EU trust (LOTL, national lists, WRPAC)
/// is a separate concern behind the same <see cref="ITrustListResolver"/> interface.
/// </remarks>
public sealed class StaticTrustListResolver : ITrustListResolver
{
    private readonly HashSet<string> _trustedIssuers;
    private readonly string _source;

    /// <summary>Creates a resolver trusting exactly the given issuer identifiers.</summary>
    /// <param name="trustedIssuers">Issuer identifiers (iss values or certificate subjects).</param>
    /// <param name="source">Optional label reported as <see cref="IssuerTrustStatus.TrustListSource"/>.</param>
    public StaticTrustListResolver(IEnumerable<string> trustedIssuers, string source = "static")
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        _trustedIssuers = new HashSet<string>(trustedIssuers, StringComparer.Ordinal);
        _source = source;
    }

    /// <inheritdoc />
    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        var trusted = _trustedIssuers.Contains(issuer);
        return Task.FromResult(new IssuerTrustStatus
        {
            Trusted = trusted,
            TrustListSource = trusted ? _source : null,
            Reason = trusted ? null : $"Issuer '{issuer}' is not on the configured trust list.",
        });
    }
}
