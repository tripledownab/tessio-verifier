namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds a signed OpenID4VP 1.0 presentation request (DCQL + JAR per RFC 9101).
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). The signing operation is asynchronous because real-world
/// implementations sign the JAR with keys held in an HSM, Azure Key Vault, AWS KMS, or another
/// remote/asynchronous key store. Synchronous in-memory signers can simply return
/// <c>Task.FromResult</c>.
/// </remarks>
public interface IPresentationRequestBuilder
{
    /// <summary>Builds and signs a presentation request from the supplied options.</summary>
    /// <param name="options">Per-request inputs (DCQL, nonce, response_uri, etc.).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<PresentationRequest> BuildAsync(
        PresentationRequestOptions options,
        CancellationToken ct = default);
}
