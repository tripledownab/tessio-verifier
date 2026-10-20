using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

// The same-device half of InMemorySessionStore: bound sessions, held presentations and their redemption.
public sealed partial class InMemorySessionStore
{
    /// <inheritdoc />
    public Task<VerificationSession> CreateBoundAsync(
        PresentationRequestOptions options, byte[] browserBinding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(browserBinding);
        return CreateCoreAsync(options, browserBinding, ct);
    }

    /// <inheritdoc />
    public Task<SameDeviceHold> HoldAsync(
        string sessionId, VerificationResult result, byte[] responseCodeHash, DateTimeOffset redeemBy,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(responseCodeHash);
        ArgumentNullException.ThrowIfNull(sessionId);
        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            // Gone between the callback finding it and holding it: ended, as far as a wallet is concerned.
            return Task.FromResult(SameDeviceHold.NotPending);
        }

        // An unbound session is answered before its expiry is evaluated, so that asking about a cross-device
        // session leaves it exactly as the callback found it.
        if (!entry.IsBound)
        {
            return Task.FromResult(SameDeviceHold.NotBound);
        }

        EvaluateExpiry(entry);
        return Task.FromResult(entry.Hold(result, responseCodeHash, redeemBy, _clock.GetUtcNow()));
    }

    /// <inheritdoc />
    public Task<SameDeviceRedemption> RedeemAsync(
        string sessionId, byte[] responseCodeHash, byte[] browserBinding, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(responseCodeHash);
        ArgumentNullException.ThrowIfNull(browserBinding);
        if (!_sessions.TryGetValue(sessionId, out var entry))
        {
            // An unknown id is a redemption with nothing to redeem: the id comes from the browser.
            return Task.FromResult(SameDeviceRedemption.NotHeld);
        }

        EvaluateExpiry(entry);
        return Task.FromResult(entry.Redeem(responseCodeHash, browserBinding, _clock.GetUtcNow()));
    }
}
