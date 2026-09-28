namespace Tessio.Verifier.Trust;

/// <summary>
/// Outcome of trust-list resolution for a credential issuer.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs may be added as init-only
/// properties, which is how <see cref="TrustAnchorSubject"/> and <see cref="TrustAnchorThumbprint"/>
/// arrived. No existing member changes.
/// </remarks>
public sealed record IssuerTrustStatus
{
    /// <summary>True when the issuer chains to a trusted root.</summary>
    public required bool Trusted { get; init; }

    /// <summary>Identifier of the trust list that produced the verdict (URI, file path, or implementation-defined).</summary>
    public string? TrustListSource { get; init; }

    /// <summary>Human-readable reason when <see cref="Trusted"/> is false; null when trusted.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Subject of the trust anchor the chain actually anchored on, when it anchored on one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null on the identifier route: a key resolved from issuer metadata is trusted because its
    /// identifier is on the list, so no certificate vouched for it and there is no anchor to name.
    /// Null on a refusal where nothing matched, which is most of them. NOT null on the one refusal that
    /// knows which anchor it matched and then rejected, a pinned certificate outside its own validity
    /// window: "we trusted this exact certificate and its window had closed" is a different fact from
    /// "nothing matched", and this field is what tells them apart.
    /// </para>
    /// <para>
    /// A SUBJECT IS NOT AN IDENTITY. Distinguished names are not unique, a certificate authority may be
    /// reissued under the same name with a new key, and a same-name impostor is exactly the case a
    /// name-based check accepts. This field is for a human reading a record;
    /// <see cref="TrustAnchorThumbprint"/> is the identity. It is also the platform's RENDERING of the
    /// name rather than its DER, so two operating systems may format the same anchor differently.
    /// </para>
    /// <para>Init-only and optional, so every existing construction still compiles unchanged.</para>
    /// </remarks>
    public string? TrustAnchorSubject { get; init; }

    /// <summary>
    /// SHA-256 over the trust anchor's DER bytes, uppercase hex, when the chain anchored on one.
    /// </summary>
    /// <remarks>
    /// SHA-256 over the raw certificate rather than the platform's <c>Thumbprint</c> property, which is
    /// SHA-1. This field exists to answer "which anchor, exactly" for a record that may be read years
    /// after the presentation, so the comparison it supports has to be one worth making.
    /// </remarks>
    public string? TrustAnchorThumbprint { get; init; }
}
