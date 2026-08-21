using Microsoft.Extensions.Logging;
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
}

/// <summary>
/// The outcome plus the session it belonged to, when one was correlated.
/// </summary>
/// <remarks>
/// The session id is carried out because HAIP 1.0 5.1 requires the response to the wallet's POST to
/// contain a <c>redirect_uri</c>, and the only sensible destination is this session's own result.
/// </remarks>
internal readonly record struct CallbackResult(CallbackOutcome Outcome, string? SessionId);

/// <summary>
/// Processes a wallet authorization response end to end: parse (<see cref="WalletResponseParser"/>),
/// correlate the session via <c>state</c>, verify every presented credential
/// (<see cref="WalletResponseVerifier"/>) against the session's own request, and complete the session
/// with the outcome.
/// </summary>
internal sealed class WalletCallbackProcessor
{
    private readonly WalletResponseParser _parser;
    private readonly WalletResponseVerifier _responseVerifier;
    private readonly IStateCorrelatingSessionStore _store;
    private readonly ILogger<WalletCallbackProcessor> _logger;

    public WalletCallbackProcessor(
        WalletResponseParser parser,
        WalletResponseVerifier responseVerifier,
        ISessionStore store,
        ILogger<WalletCallbackProcessor> logger)
    {
        _parser = parser;
        _responseVerifier = responseVerifier;
        _logger = logger;
        // Wallet responses carry only `state` as a correlation handle, so the callback path cannot
        // work against a store that has no state index.
        _store = store as IStateCorrelatingSessionStore ?? throw new InvalidOperationException(
            $"The registered {nameof(ISessionStore)} ({store.GetType().Name}) does not implement " +
            $"{nameof(IStateCorrelatingSessionStore)}, which the wallet callback endpoint requires " +
            "to correlate responses by OpenID4VP 'state'. Implement that interface on your store.");
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

        // A host store can hand back a session whose request no longer says what was asked for, in either
        // encoding. Verifying that one accepts a credential of any type, because a null ExpectedVct skips
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

        await _store.CompleteAsync(session.SessionId, outcome, ct).ConfigureAwait(false);

        if (outcome.IsValid)
        {
            Log.VerificationSucceeded(_logger, session.SessionId, outcome.Issuer.Identifier, outcome.Issuer.KeyResolutionMethod);
        }
        else
        {
            Log.VerificationFailed(_logger, session.SessionId, outcome.Issuer.Identifier,
                string.Join(",", outcome.Errors.Select(e => e.Code)));
        }

        return new CallbackResult(CallbackOutcome.Completed, session.SessionId);
    }
}
