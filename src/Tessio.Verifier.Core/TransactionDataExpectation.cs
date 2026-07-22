namespace Tessio.Verifier.Core;

/// <summary>
/// The transaction data this presentation must acknowledge: the exact base64url strings sent in the
/// request's <c>transaction_data</c> parameter. The wallet hashes each string (as received, without
/// decoding) into the KB-JWT's <c>transaction_data_hashes</c>, binding the holder's signature to the
/// transaction the credential authorizes (e.g. a payment).
/// </summary>
// SPEC: OpenID4VP 1.0 Annex B.3.3.1 — transaction data profile for SD-JWT VC.
public sealed record TransactionDataExpectation
{
    /// <summary>The base64url-encoded transaction_data strings, exactly as sent in the request.</summary>
    public required IReadOnlyList<string> TransactionData { get; init; }

    /// <summary>
    /// The request's <c>transaction_data_hashes_alg</c> values, when it constrained the hash
    /// algorithm. Null when the request carried none; the default is then <c>sha-256</c>.
    /// </summary>
    public IReadOnlyList<string>? AllowedHashAlgorithms { get; init; }
}
