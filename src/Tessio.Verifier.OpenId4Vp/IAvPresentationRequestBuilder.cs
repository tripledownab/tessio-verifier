namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds an EU Age Verification authorization request: DCQL in plain query parameters, no JAR.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="IPresentationRequestBuilder"/> because that interface is a frozen contract
/// (contracts-v0) returning <see cref="PresentationRequest"/>, which cannot represent a request that has
/// no request object. See <see cref="AvPresentationRequest"/>.
/// </para>
/// <para>
/// Synchronous in substance, but returns a <see cref="Task{TResult}"/> to match
/// <see cref="IPresentationRequestBuilder"/>. A caller should be able to swap one seam for the other
/// without restructuring, and a profile that later needs a remote key must not force a signature change
/// on every consumer.
/// </para>
/// </remarks>
public interface IAvPresentationRequestBuilder
{
    /// <summary>Builds an unsigned, plain-parameter presentation request from the supplied options.</summary>
    /// <param name="options">
    /// Per-request inputs. <see cref="PresentationRequestOptions.ResponseMode"/> must be
    /// <see cref="ResponseMode.DirectPost"/>, and <see cref="PresentationRequestOptions.ClientMetadataJson"/>
    /// should be null: this profile encrypts nothing and identifies the verifier by its response URI.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    Task<AvPresentationRequest> BuildAsync(
        PresentationRequestOptions options,
        CancellationToken ct = default);
}
