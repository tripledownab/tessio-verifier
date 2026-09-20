using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Trust resolver backed by a fixed set of trusted issuer identifiers, plus optional trust-anchor
/// certificates for issuers that present an X.509 chain. Suitable for development, tests and small
/// deployments. Load the identifier set from a JSON file or URL with <see cref="TrustListLoader"/>.
/// </summary>
/// <remarks>
/// <para>
/// The trust mechanism depends on how the key was resolved. A key resolved from issuer metadata is
/// trusted exactly when its issuer identifier is on the configured list, proven by control of the
/// issuer's HTTPS origin. A key resolved from an <c>x5c</c> (or <c>x5chain</c>) header is trusted when
/// its chain anchors on one of <c>trustAnchors</c> (or the leaf itself is a pinned anchor); the
/// identifier is <em>not</em> required to be on the list, because anyone can put any name in a
/// certificate, so the X.509 chain is the proof. This is the only mechanism ISO mdoc has, where the
/// issuer identifier is a Document Signer subject DN that no list enumerates. Binding the certificate
/// to a claimed issuer, where that applies, is the caller's concern: SD-JWT VC ties <c>iss</c> to a
/// certificate SAN before this point, but ONLY where the leaf asserts a name. A leaf that asserts none
/// cannot contradict <c>iss</c>, and the specification makes its subject the issuer, so for that leaf
/// anchoring is the whole of the proof. Without configured anchors, x5c credentials are rejected.
/// </para>
/// <para>
/// Either way the certificate must be inside its own validity window, read at <c>clock</c>. Anchoring
/// is not the whole answer: a pinned certificate whose window has closed is refused, exactly as the
/// chain check refuses an expired one on the path that builds a chain.
/// </para>
/// <para>
/// <b>What a trusted issuer is trusted FOR.</b> This resolver answers one question, "is this signer
/// trusted", and callers ask it about more than credential issuance: a Token Status List token's
/// signer is judged here too. So adding an entry to <c>trustedIssuers</c> or to <c>trustAnchors</c>
/// authorises that party for every purpose the deployment asks about, including signing revocation
/// status for credentials issued by somebody else. That is the cost of a flat list, and it is worth
/// knowing before adding an entry to clear a rejection.
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
    private readonly TimeProvider _clock;

    /// <summary>Creates a resolver trusting exactly the given issuer identifiers.</summary>
    /// <param name="trustedIssuers">Issuer identifiers (iss values or certificate subjects).</param>
    /// <param name="source">Optional label reported as <see cref="IssuerTrustStatus.TrustListSource"/>.</param>
    /// <param name="trustAnchors">
    /// Root or pinned certificates that x5c chains must anchor on. Credentials presenting an x5c
    /// chain are rejected when this is empty, and an anchor is only usable inside its own validity
    /// window.
    /// </param>
    /// <param name="clock">
    /// Time source for every certificate validity decision here, on both the pinned-leaf and the
    /// chain-building path; system clock when null. Pass the same one given to the verifier, or a
    /// presentation verified at a chosen instant is judged against wall-clock time instead, and the
    /// two disagree for exactly the certificates whose window has since closed.
    /// </param>
    public StaticTrustListResolver(
        IEnumerable<string> trustedIssuers,
        string source = "static",
        IEnumerable<X509Certificate2>? trustAnchors = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        _trustedIssuers = new HashSet<string>(trustedIssuers, StringComparer.Ordinal);
        _trustAnchors = trustAnchors?.ToList() ?? [];
        _source = source;
        _clock = clock ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(x5c);

        // The trust mechanism is chosen by how the issuer key was resolved, not by the credential
        // format. A key resolved from issuer metadata (no x5c) is trusted exactly when its identifier
        // is on the list: control of the iss HTTPS origin is what proved that identifier.
        if (x5c.Length == 0)
        {
            return _trustedIssuers.Contains(issuer)
                ? Trusted()
                : NotTrusted($"Issuer '{issuer}' is not on the configured trust list.");
        }

        // A key resolved from an x5c chain is trusted by anchoring, not by identifier membership: the
        // identifier is only as good as the certificate carrying it, and anyone can put any name in a
        // certificate. This is the only mechanism ISO mdoc has, where the identifier is a Document
        // Signer subject DN that no list enumerates. The caller binds the certificate to a claimed
        // issuer where that applies (SD-JWT VC ties iss to a certificate SAN before this point).
        if (_trustAnchors.Count == 0)
        {
            return NotTrusted(
                $"Issuer '{issuer}' presented an X.509 chain, but this trust list has no trust anchors. " +
                "An identifier-only list cannot vouch for x5c credentials; configure trustAnchors.");
        }

        var (anchored, because) = ChainAnchorsOnConfiguredRoot(x5c);
        return anchored
            ? Trusted()
            : NotTrusted(
                $"The certificate chain presented by '{issuer}' does not anchor on a configured trust anchor. "
                + $"Chain status: {because}");
    }

    /// <summary>
    /// Whether the chain anchors, and when it does not, what the platform said. "Does not anchor" on
    /// its own sends the reader hunting for a wrong certificate when the real cause is often a
    /// validity window, a missing basic-constraints flag or an unsupported critical extension.
    /// </summary>
    private (bool Anchored, string? Because) ChainAnchorsOnConfiguredRoot(ReadOnlyMemory<byte>[] x5c)
    {
        var certificates = x5c.Select(der => LoadCertificate(der.ToArray())).ToList();
        try
        {
            var leaf = certificates[0];

            // Pinned leaf: the exact end-entity certificate was configured as an anchor. Its own bytes
            // are the proof, so there is no chain to build and no signature to verify.
            //
            // ITS VALIDITY WINDOW IS STILL READ. Pinning says "this exact certificate", not "this
            // certificate forever", and the window is what bounds how long a key stays trusted after
            // anyone stops looking after it. Without this, a document signer pinned two years ago goes
            // on verifying credentials, and there is no way to withdraw it except by editing the anchor
            // list, which is the one thing expiry exists to avoid depending on.
            //
            // Read here rather than by sending this case through the X509Chain below, because a pinned
            // leaf is frequently not self-signed, and platforms do not agree on how to treat a
            // non-self-signed certificate placed in a trust store. The answer must not depend on the
            // operating system underneath.
            if (_trustAnchors.Any(anchor => anchor.RawData.AsSpan().SequenceEqual(leaf.RawData)))
            {
                return IsWithinItsValidityWindow(leaf)
                    ? (true, null)
                    : (false,
                        $"The pinned certificate '{leaf.Subject}' is outside its own validity window "
                        + $"({leaf.NotBefore.ToUniversalTime():u} to {leaf.NotAfter.ToUniversalTime():u}).");
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            // THE SAME INSTANT THE PINNED BRANCH ABOVE USES. X509Chain reads the system clock unless
            // it is told otherwise, so leaving this unset would judge one question at two different
            // times: a caller replaying a stored presentation would get their chosen instant when the
            // operator pinned a leaf, and wall-clock time when the operator pinned a root. Which
            // branch runs is a configuration detail, and it must not decide what "expired" means.
            chain.ChainPolicy.VerificationTime = _clock.GetUtcNow().UtcDateTime;
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

            if (chain.Build(leaf))
            {
                return (true, null);
            }

            var status = string.Join("; ", chain.ChainStatus
                .Select(s => $"{s.Status}: {s.StatusInformation.Trim()}")
                .DefaultIfEmpty("no status reported by the platform"));

            // Name the issuer the chain is looking for and the anchors we hold. A PartialChain with
            // neither of those printed sends the reader guessing; with both, a mismatch is obvious on
            // sight and a genuine "right names, still fails" points at the certificates instead.
            var anchorSubjects = string.Join(" | ", _trustAnchors.Select(a => a.Subject));

            // Key identifiers, not just names. When the names match and the chain still fails, the
            // cause is almost always a certificate authority that was regenerated under the same
            // distinguished name with a new key: the leaf points at the old key, the anchor holds the
            // new one, and comparing subjects alone makes that look like it should have worked.
            var wantedKey = leaf.Extensions
                .OfType<X509AuthorityKeyIdentifierExtension>()
                .FirstOrDefault()?.KeyIdentifier;
            var haveKeys = string.Join(" | ", _trustAnchors
                .Select(a => a.Extensions.OfType<X509SubjectKeyIdentifierExtension>()
                    .FirstOrDefault()?.SubjectKeyIdentifier ?? "none"));

            // Opt-in dump of the offending leaf, for when the names and key ids all match and the
            // chain still will not build. Certificates are public, but this is noisy, so it is behind
            // an environment variable rather than on by default.
            var dump = Environment.GetEnvironmentVariable("TESSIO_TRUST_DUMP_LEAF") == "1"
                ? $" Leaf (base64 DER): {Convert.ToBase64String(leaf.RawData)}"
                : string.Empty;

            return (false,
                $"{status} The chain's leaf names its issuer as '{leaf.Issuer}'. "
                + $"Configured anchor subjects: {anchorSubjects}. "
                + $"Leaf's authority key id: {(wantedKey is null ? "none" : Convert.ToHexString(wantedKey.Value.Span))}. "
                + $"Anchor subject key ids: {haveKeys}.{dump}");
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// Whether the certificate may be relied on at the verification time, by the window it states.
    /// </summary>
    /// <remarks>
    /// Both sides are compared in UTC, and that conversion is the whole point of the method.
    /// <see cref="X509Certificate2.NotBefore"/> and <see cref="X509Certificate2.NotAfter"/> are
    /// reported in LOCAL time. A <see cref="DateTime"/> comparison ignores
    /// <see cref="DateTime.Kind"/> and compares ticks, so comparing them raw against a UTC clock is
    /// wrong by the machine's offset: east of Greenwich it keeps accepting a certificate for hours
    /// after it expired. The error is invisible on a server set to UTC, which is most of them, and
    /// appears only on someone's laptop.
    /// </remarks>
    private bool IsWithinItsValidityWindow(X509Certificate2 certificate)
    {
        var nowUtc = _clock.GetUtcNow().UtcDateTime;
        return nowUtc >= certificate.NotBefore.ToUniversalTime()
            && nowUtc <= certificate.NotAfter.ToUniversalTime();
    }

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif

    private Task<IssuerTrustStatus> Trusted() =>
        Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = _source });

    private static Task<IssuerTrustStatus> NotTrusted(string reason) =>
        Task.FromResult(new IssuerTrustStatus { Trusted = false, Reason = reason });
}
