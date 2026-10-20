using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>Outcome of processing a wallet callback, mapped to HTTP by the endpoint layer.</summary>
internal enum CallbackOutcome
{
    Completed = 0,
    ResponseInvalid = 1,
    UnknownSession = 2,
    SessionNotPending = 3,
    SessionNotVerifiable = 4,
    PresentationRejected = 5,

    /// <summary>A verified same-device presentation, held until its browser redeems the response code.</summary>
    Held = 6,
}

/// <summary>
/// The outcome plus the session it belonged to, when one was correlated, and the response code a held
/// presentation is redeemed with.
/// </summary>
/// <remarks>
/// The session id is carried out because HAIP 1.0 5.1 requires the response to the wallet's POST to
/// contain a <c>redirect_uri</c>, and its destination is this session's own return page.
/// </remarks>
internal readonly record struct CallbackResult(CallbackOutcome Outcome, string? SessionId, string? ResponseCode = null);

/// <summary>
/// Processes a wallet authorization response end to end: parse (<see cref="WalletResponseParser"/>),
/// correlate the session via <c>state</c>, verify every presented credential
/// (<see cref="WalletResponseVerifier"/>) against the session's own request, and complete the session
/// with the outcome. With <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> on, a failing outcome
/// is recorded as a failed attempt instead, and the session stays pending.
/// </summary>
internal sealed partial class WalletCallbackProcessor
{
    private readonly WalletResponseParser _parser;
    private readonly WalletResponseVerifier _responseVerifier;
    private readonly IStateCorrelatingSessionStore _store;
    private readonly IAttemptRecordingSessionStore? _attempts;
    private readonly ISameDeviceSessionStore? _sameDevice;
    private readonly TimeProvider _clock;
    private readonly ILogger<WalletCallbackProcessor> _logger;

    public WalletCallbackProcessor(
        WalletResponseParser parser,
        WalletResponseVerifier responseVerifier,
        ISessionStore store,
        IOptions<VerifierOptions> options,
        TimeProvider clock,
        ILogger<WalletCallbackProcessor> logger)
    {
        _parser = parser;
        _responseVerifier = responseVerifier;
        _clock = clock;
        _logger = logger;
        // Null for a store that cannot hold a presentation. MapTessioVerifier maps no same-device route for
        // one, so every session it holds is cross-device and completes here as before.
        _sameDevice = store as ISameDeviceSessionStore;
        // Wallet responses carry only `state` as a correlation handle, so the callback path cannot
        // work against a store that has no state index.
        _store = store as IStateCorrelatingSessionStore ?? throw new InvalidOperationException(
            $"The registered {nameof(ISessionStore)} ({store.GetType().Name}) does not implement " +
            $"{nameof(IStateCorrelatingSessionStore)}, which the wallet callback endpoint requires " +
            "to correlate responses by OpenID4VP 'state'. Implement that interface on your store.");
        // With the option on, a store that cannot record a failure would leave the callback two choices,
        // both wrong: complete the session the option says to keep open, or drop the failure unseen.
        _attempts = !options.Value.CompleteOnlyOnValidResponse
            ? null
            : store as IAttemptRecordingSessionStore ?? throw new InvalidOperationException(
                $"{nameof(VerifierOptions)}.{nameof(VerifierOptions.CompleteOnlyOnValidResponse)} is on, but the " +
                $"registered {nameof(ISessionStore)} ({store.GetType().Name}) does not implement " +
                $"{nameof(IAttemptRecordingSessionStore)}, which records a failed response without completing " +
                "the session. Implement that interface on your store, or turn the option off.");
    }

    public async Task<CallbackResult> ProcessAsync(WalletResponseData response, CancellationToken ct)
    {
        ParsedWalletResponse parsed;
        try
        {
            parsed = await _parser.ParseDetailedAsync(response, ct).ConfigureAwait(false);
        }
        catch (WalletResponseException e)
        {
            Log.CallbackParseFailed(_logger, e);
            return new CallbackResult(CallbackOutcome.ResponseInvalid, null);
        }

        // SPEC: OpenID4VP 1.0 — state echoes the request and is this verifier's session correlation
        // handle; a response without a known state is rejected (replay / stray callback protection).
        if (parsed.State is null)
        {
            Log.CallbackMissingState(_logger);
            return new CallbackResult(CallbackOutcome.ResponseInvalid, null);
        }

        var session = await _store.FindByStateAsync(parsed.State, ct).ConfigureAwait(false);
        if (session is null)
        {
            Log.CallbackUnknownState(_logger, parsed.State);
            return new CallbackResult(CallbackOutcome.UnknownSession, null);
        }

        if (session.Status != VerificationSessionStatus.Pending)
        {
            Log.CallbackNotPending(_logger, session.SessionId, session.Status);
            return new CallbackResult(CallbackOutcome.SessionNotPending, session.SessionId); // Sessions complete exactly once (replay protection).
        }

        // A RESPONSE IN THE WRONG MODE DOES NOT ANSWER THE REQUEST, so it is refused BEFORE completion, the
        // way a missing state is, and the session stays open for the wallet's own answer. A request that
        // asked for direct_post.jwt is answered encrypted, and the parser has already refused a response
        // token that is not a JWE, so a plaintext form here is not the wallet's answer.
        if (parsed.Encrypted != RequestParameters.AsksForEncryptedResponse(session.Request))
        {
            Log.CallbackWrongResponseMode(_logger, session.SessionId,
                parsed.Encrypted ? "encrypted" : "in plaintext",
                RequestParameters.TryGetResponseMode(session.Request) ?? "no response_mode");
            return new CallbackResult(CallbackOutcome.ResponseInvalid, session.SessionId);
        }

        // A host store can hand back a session whose request no longer says what was asked for, in either
        // encoding. Verifying that one accepts a credential of any type, because no expected type skips
        // the type comparison in SdJwtVcVerifier and a null ExpectedDocType skips it in MdocVerifier. The
        // built-in store never loses the request; a host store that persisted less than the whole request
        // can, and AddTessioVerifier invites hosts to register one.
        if (!WalletResponseVerifier.CanVerify(session.Request))
        {
            Log.CallbackSessionNotVerifiable(_logger, session.SessionId);
            return new CallbackResult(CallbackOutcome.SessionNotVerifiable, session.SessionId);
        }

        // Verify every presented credential; the verifier derives audience, nonce, vct, docType and the
        // response-encryption thumbprint from the session's own request.
        var outcome = await _responseVerifier.VerifyParsedAsync(session, parsed, ct).ConfigureAwait(false);

        if (!outcome.IsValid)
        {
            var errorCodes = string.Join(",", outcome.Errors.Select(e => e.Code));
            if (await RefuseAsync(session.SessionId, outcome, ct).ConfigureAwait(false))
            {
                Log.VerificationFailedSessionKept(_logger, session.SessionId, outcome.Issuer.Identifier, errorCodes);
                return new CallbackResult(CallbackOutcome.PresentationRejected, session.SessionId);
            }

            Log.VerificationFailed(_logger, session.SessionId, outcome.Issuer.Identifier, errorCodes);
            return new CallbackResult(CallbackOutcome.Completed, session.SessionId);
        }

        // A VERIFIED SAME-DEVICE PRESENTATION DOES NOT COMPLETE THE SESSION. It is held until the browser that
        // started the request comes back with the response code the redirect carries, which is what HAIP 1.0
        // section 5.1 requires: reject the presentation if the wallet does not follow the redirect back, or if
        // the redirect arrives in another user session. Only a valid one is held, because a failing one is
        // refused already. A session is same-device when EITHER its request says so or the store holds a binding
        // for it, so losing one of the two still never completes it unbound (SameDeviceRequests).
        if (await HoldAsync(session, outcome, ct).ConfigureAwait(false) is { } held)
        {
            return held;
        }

        await _store.CompleteAsync(session.SessionId, outcome, ct).ConfigureAwait(false);
        Log.VerificationSucceeded(_logger, session.SessionId, outcome.Issuer.Identifier, outcome.Issuer.KeyResolutionMethod);
        return new CallbackResult(CallbackOutcome.Completed, session.SessionId);
    }

    /// <summary>
    /// The one rule for a refused presentation: with <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/>
    /// on, it is recorded as a failed attempt and the session stays pending; otherwise it completes the
    /// session. Returns whether the session was kept open.
    /// </summary>
    private async Task<bool> RefuseAsync(string sessionId, VerificationResult failure, CancellationToken ct)
    {
        if (_attempts is null)
        {
            await _store.CompleteAsync(sessionId, failure, ct).ConfigureAwait(false);
            return false;
        }

        await _attempts.RecordFailedAttemptAsync(sessionId, failure, ct).ConfigureAwait(false);
        return true;
    }
}
