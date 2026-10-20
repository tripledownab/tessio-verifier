using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

// The same-device half of the wallet callback: holding a verified presentation, and redeeming it once its
// browser comes back.
internal sealed partial class WalletCallbackProcessor
{
    /// <summary>
    /// Redeems a held same-device presentation with the response code from the wallet's redirect and the
    /// secret from the browser's binding cookie. A code redeemed from another browser rejects the
    /// presentation with <see cref="ErrorCodes.SessionMismatch"/>. A browser that sent no cookie is another
    /// browser as far as the binding is concerned.
    /// </summary>
    public async Task<SameDeviceRedemption> RedeemAsync(
        string sessionId, string responseCode, string? browserSecret, CancellationToken ct)
    {
        var sameDevice = _sameDevice ?? throw new InvalidOperationException(
            $"The registered {nameof(ISessionStore)} does not implement {nameof(ISameDeviceSessionStore)}, so " +
            "there is nothing to redeem. MapTessioVerifier maps the redemption route only for a store that does.");

        // A browser with no cookie is given a secret nothing was ever bound to, rather than nothing at all, so a
        // store cannot read an absent binding as a match: the comparison it makes must fail.
        var redemption = await sameDevice.RedeemAsync(sessionId, SameDeviceSecrets.Hash(responseCode),
            SameDeviceSecrets.Hash(browserSecret ?? SameDeviceSecrets.NewSecret()), ct).ConfigureAwait(false);
        switch (redemption)
        {
            case SameDeviceRedemption.Redeemed:
                Log.SameDeviceRedeemed(_logger, sessionId);
                break;
            case SameDeviceRedemption.BindingMismatch:
                await RefuseAsync(sessionId, SessionMismatch, ct).ConfigureAwait(false);
                Log.SameDeviceBindingMismatch(_logger, sessionId);
                break;
            case SameDeviceRedemption.NotHeld:
                break;
            default:
                throw new InvalidOperationException($"Unhandled same-device redemption outcome {redemption}.");
        }

        return redemption;
    }

    /// <summary>The result a presentation redeemed from the wrong browser is refused with.</summary>
    private static readonly VerificationResult SessionMismatch = VerificationResult.Invalid(new VerificationError
    {
        Code = ErrorCodes.SessionMismatch,
        Message = "The redirect back from the wallet arrived in a different browser from the one that started the request.",
    });

    /// <summary>
    /// Holds a verified presentation for a same-device session until its browser redeems it, and returns how
    /// to answer the wallet. Returns null for a cross-device session, which the caller completes.
    /// </summary>
    /// <remarks>
    /// A session is same-device when either of its two marks says so: the store's binding, or the request's
    /// own <c>response_uri</c> (<see cref="SameDeviceRequests"/>). Neither alone lets it complete unbound. With
    /// the binding the presentation is held. With only the mark it is refused, because the binding it would be
    /// checked against is lost.
    /// </remarks>
    private async Task<CallbackResult?> HoldAsync(VerificationSession session, VerificationResult outcome, CancellationToken ct)
    {
        var sessionId = session.SessionId;
        var marked = SameDeviceRequests.IsSameDevice(session.Request);
        if (_sameDevice is null)
        {
            if (!marked)
            {
                return null;
            }

            // This library mints a same-device request only through a store that can hold, so meeting one here
            // means the registered store changed since: it cannot hold the binding either.
            Log.SameDeviceBindingLost(_logger, sessionId);
            return new CallbackResult(CallbackOutcome.SessionNotVerifiable, sessionId);
        }

        var code = SameDeviceSecrets.NewSecret();
        var hold = await _sameDevice.HoldAsync(sessionId, outcome, SameDeviceSecrets.Hash(code),
            _clock.GetUtcNow() + SameDeviceSecrets.RedemptionWindow, ct).ConfigureAwait(false);
        switch (hold)
        {
            case SameDeviceHold.Held:
                Log.PresentationHeld(_logger, sessionId);
                return new CallbackResult(CallbackOutcome.Held, sessionId, code);
            case SameDeviceHold.NotPending:
                Log.CallbackWhileHeld(_logger, sessionId);
                return new CallbackResult(CallbackOutcome.SessionNotPending, sessionId);
            case SameDeviceHold.NotBound when marked:
                Log.SameDeviceBindingLost(_logger, sessionId);
                return new CallbackResult(CallbackOutcome.SessionNotVerifiable, sessionId);
            case SameDeviceHold.NotBound:
                return null;
            default:
                throw new InvalidOperationException($"Unhandled same-device hold outcome {hold}.");
        }
    }
}
