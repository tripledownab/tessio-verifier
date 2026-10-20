using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// An <see cref="ISessionStore"/> that can run the same-device flow: a session bound to the browser that
/// started it, whose verified presentation is held until that browser comes back with the response code
/// the wallet's redirect carried. Everything about binding, holding and redeeming belongs here.
/// </summary>
/// <remarks>
/// <para>
/// SPEC: HAIP 1.0 section 5.1, "Verifiers and Wallets MUST support the "same-device" flow", and for it
/// "Verifiers MUST reject presentations if Wallets do not follow the redirect back or the redirect back
/// arrives in a different user session to the one the request was initiated in". OpenID4VP 1.0 section
/// 14.2: the Response URI "MUST include a fresh secret (Response Code) into the redirect URI returned to
/// the Wallet and the Verifier's Response URI MUST require the frontend to pass the respective Response Code
/// when fetching the Authorization Response". The library gates completing the session on the code and the
/// binding together, rather than gating the fetch of its result.
/// </para>
/// <para>
/// A separate interface because <see cref="ISessionStore"/> is frozen, so a store written against
/// contracts-v0 keeps compiling. <c>MapTessioVerifier</c> maps the same-device routes only when the
/// registered store implements this, and logs a warning when it does not. The built-in
/// <see cref="InMemorySessionStore"/> implements it.
/// </para>
/// <para>
/// The values passed in are SHA-256 hashes, never the secrets themselves, so a store's contents do not let
/// anyone redeem a presentation. Compare them with
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals"/>.
/// </para>
/// </remarks>
public interface ISameDeviceSessionStore : IStateCorrelatingSessionStore
{
    /// <summary>
    /// Creates a session, as <see cref="ISessionStore.CreateAsync"/> does, bound to the browser whose
    /// binding hash is <paramref name="browserBinding"/>.
    /// </summary>
    Task<VerificationSession> CreateBoundAsync(
        PresentationRequestOptions options,
        byte[] browserBinding,
        CancellationToken ct = default);

    /// <summary>
    /// Holds a verified <paramref name="result"/> for a bound session until <paramref name="redeemBy"/>,
    /// leaving the session <see cref="VerificationSessionStatus.Pending"/>. The callback asks this for every
    /// verified presentation, cross-device ones included, because the binding is one of the two marks of a
    /// same-device session.
    /// </summary>
    /// <returns>
    /// <see cref="SameDeviceHold.NotBound"/> for a session the store holds no binding for, whatever its state,
    /// so that asking about a cross-device session changes nothing; <see cref="SameDeviceHold.NotPending"/> when
    /// the session is unknown, or is bound and has ended or already holds an unexpired presentation.
    /// </returns>
    /// <remarks>
    /// Only a verified presentation is held. A failing one that arrives while another is held is refused
    /// under the usual rule, so without <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> it ends
    /// the session and the held presentation with it. Only the holder of the request's <c>state</c> can
    /// send one, and a session ended early is a refusal, never a wrong verdict.
    /// </remarks>
    Task<SameDeviceHold> HoldAsync(
        string sessionId,
        VerificationResult result,
        byte[] responseCodeHash,
        DateTimeOffset redeemBy,
        CancellationToken ct = default);

    /// <summary>
    /// Redeems the held presentation whose response code hashes to <paramref name="responseCodeHash"/>.
    /// When <paramref name="browserBinding"/> matches the session's binding, completes the session with the
    /// held result in the same step. When it does not, discards the held result and leaves the session pending
    /// for the caller to reject. A browser that sent no cookie is passed a hash nothing was ever bound to.
    /// </summary>
    Task<SameDeviceRedemption> RedeemAsync(
        string sessionId,
        byte[] responseCodeHash,
        byte[] browserBinding,
        CancellationToken ct = default);
}

/// <summary>What <see cref="ISameDeviceSessionStore.HoldAsync"/> did.</summary>
public enum SameDeviceHold
{
    /// <summary>The result is held until it is redeemed or its window passes.</summary>
    Held = 0,

    /// <summary>
    /// The store holds no binding for the session. The callback completes it as a cross-device session, unless
    /// its request was minted for the same-device flow: then the store lost the binding, and the callback
    /// refuses the presentation rather than complete the session unbound.
    /// </summary>
    NotBound = 1,

    /// <summary>The session has ended, or already holds a presentation.</summary>
    NotPending = 2,
}

/// <summary>What <see cref="ISameDeviceSessionStore.RedeemAsync"/> did.</summary>
public enum SameDeviceRedemption
{
    /// <summary>The code and the browser matched, and the session is completed with the held result.</summary>
    Redeemed = 0,

    /// <summary>The code matched and the browser did not. The held result is discarded.</summary>
    BindingMismatch = 1,

    /// <summary>
    /// Nothing to redeem: no held presentation, a code that does not match, a window that has passed, or a
    /// session that has ended.
    /// </summary>
    NotHeld = 2,
}
