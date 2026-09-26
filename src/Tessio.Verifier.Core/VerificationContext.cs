namespace Tessio.Verifier.Core;

/// <summary>
/// Per-verification context the verifier needs to validate freshness, audience, and credential type.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs are added as init-only
/// properties without breaking existing callers. <see cref="ExpectedVctValues"/> was added that way
/// rather than by widening <see cref="ExpectedVct"/>, which the freeze does not allow.
/// </remarks>
public sealed record VerificationContext
{
    /// <summary>The nonce the verifier issued for this presentation; must match the KB-JWT nonce.</summary>
    public required string Nonce { get; init; }

    /// <summary>The verifier's identifier; must match the KB-JWT audience.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// Optional expected credential type (SD-JWT VC <c>vct</c> claim). One accepted type, for a request
    /// that asks for exactly one. See <see cref="ExpectedVctValues"/> for the general case.
    /// </summary>
    public string? ExpectedVct { get; init; }

    /// <summary>
    /// Optional accepted credential types, for a request whose DCQL entry offers several.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 §B.3.5 defines <c>vct_values</c> as "A non-empty array of strings that
    /// specifies allowed values for the type of the requested Verifiable Credential", and §8.6 requires
    /// the Verifier to "validate that the returned Credential(s) meet all criteria defined in the
    /// query". The query states a SET, so the verifier accepts any member of it.
    /// </para>
    /// <para>
    /// Membership is exact. §B.3.5 also permits the Wallet to return a Credential that INHERITS from a
    /// listed type, which this verifier refuses, because following that inheritance needs SD-JWT VC
    /// Type Metadata and nothing here retrieves it. That is narrower than the specification allows and
    /// it fails closed. List each accepted type explicitly.
    /// </para>
    /// <para>
    /// This property and <see cref="ExpectedVct"/> are read together: the verification accepts a
    /// credential whose type is <see cref="ExpectedVct"/> or any entry here. When both are null or
    /// empty, the type check is skipped.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? ExpectedVctValues { get; init; }
}
