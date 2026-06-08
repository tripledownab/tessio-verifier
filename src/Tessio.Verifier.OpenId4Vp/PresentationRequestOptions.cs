namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Inputs the verifier provides to <see cref="IPresentationRequestBuilder"/> when building a presentation request.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs may be added as init-only properties
/// in later contract versions without breaking existing callers.
/// </remarks>
public sealed record PresentationRequestOptions
{
    /// <summary>
    /// Verifier identifier (OpenID4VP <c>client_id</c>). Per OpenID4VP 1.0, the value MAY carry a
    /// client-identifier-scheme prefix (e.g., <c>x509_san_dns:verifier.example.com</c>).
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Per-request nonce for replay protection. Must be cryptographically random and one-time.
    /// Echoed back by the wallet in the KB-JWT and verified by <see cref="Tessio.Verifier.Core.ICredentialVerifier"/>.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The DCQL query as a JSON string (the body of the OpenID4VP <c>dcql_query</c> parameter).
    /// </summary>
    // SPEC: OpenID4VP 1.0 uses DCQL, not Presentation Exchange.
    public required string DcqlQueryJson { get; init; }

    /// <summary>
    /// Wallet-callback URI (<c>response_uri</c>) where the wallet POSTs its response.
    /// </summary>
    public required Uri ResponseUri { get; init; }

    /// <summary>
    /// Response delivery mode. Defaults to <see cref="ResponseMode.DirectPostJwt"/> (HAIP default).
    /// </summary>
    public ResponseMode ResponseMode { get; init; } = ResponseMode.DirectPostJwt;

    /// <summary>
    /// Optional opaque correlation value echoed back in the response (OpenID4VP <c>state</c>).
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// Optional override for how long the built request remains valid. When unset, the builder applies its
    /// configured default. Influences the JAR <c>exp</c> claim and (in by-reference mode) the lifetime of
    /// the <c>request_uri</c> entry.
    /// </summary>
    public TimeSpan? RequestLifetime { get; init; }

    /// <summary>
    /// Optional verifier metadata (OpenID4VP <c>client_metadata</c>) as a JSON string. HAIP-aligned wallets
    /// use this to render the verifier's display name, logo, and purpose-of-request on the consent screen.
    /// </summary>
    public string? ClientMetadataJson { get; init; }

    /// <summary>
    /// Optional transaction-data binding (OpenID4VP <c>transaction_data</c>) as a JSON string. Used by HAIP
    /// for transaction-integrity scenarios (e.g., binding a presentation to a payment confirmation).
    /// </summary>
    public string? TransactionDataJson { get; init; }
}
