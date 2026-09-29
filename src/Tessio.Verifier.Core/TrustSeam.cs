using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// How a verifier asks the trust seam. Everything about turning a seam that cannot answer into a
/// verification result belongs here, so every verifier does it the same way.
/// </summary>
/// <remarks>
/// A verifier returns a result for any input and never throws. A resolver may do network I/O, as a
/// resolver backed by a published trust list does, and when that fails the resolver throws. Left to
/// escape, the failure would break that promise for whatever credential happened to be presented,
/// forged ones included. So it becomes a refusal carrying its cause, and the credential fails closed.
/// </remarks>
internal static class TrustSeam
{
    /// <summary>
    /// The resolver's verdict, or a refusal with <see cref="ErrorCodes.IssuerTrustUnresolvable"/> when it
    /// could not give one. A cancellation the caller asked for still propagates: that is not a failure.
    /// </summary>
    public static async Task<(IssuerTrustStatus Status, VerificationError? Failure)> ResolveAsync(
        ITrustListResolver resolver, string issuer, ReadOnlyMemory<byte>[] chain, CancellationToken ct)
    {
        try
        {
            return (await resolver.ResolveAsync(issuer, chain, ct).ConfigureAwait(false), null);
        }
        catch (Exception e) when (IsTrustSourceFailure(e, ct))
        {
            var failure = new VerificationError
            {
                Code = ErrorCodes.IssuerTrustUnresolvable,
                Message = $"The trust seam could not decide whether '{issuer}' is trusted: {e.Message}",
            };
            return (new IssuerTrustStatus { Trusted = false, Reason = failure.Message }, failure);
        }
    }

    /// <summary>
    /// Whether an exception from a resolver means it could not decide: a failed request, an I/O error, a
    /// timeout including one the resolver imposed on itself, or a resolver that is not in a state to
    /// answer, such as a trust list not yet loaded.
    /// </summary>
    /// <remarks>
    /// <see cref="InvalidOperationException"/> is included on purpose, and that includes the one
    /// <c>StaticTrustListResolver</c> throws when the platform breaks its chain-building contract. The
    /// result is a refusal that says trust could not be decided, with the resolver's own message, which
    /// is true. What must never happen is a verdict that looks decided, and this is not one. Uncaught,
    /// the same exception would reach the SD-JWT VC verifier's own net and be reported as a malformed
    /// credential, and would escape the mdoc verifier. A caller's own cancellation still propagates.
    /// </remarks>
    public static bool IsTrustSourceFailure(Exception e, CancellationToken ct) =>
        e is HttpRequestException or IOException or TimeoutException or InvalidOperationException
        || (e is OperationCanceledException && !ct.IsCancellationRequested);
}
