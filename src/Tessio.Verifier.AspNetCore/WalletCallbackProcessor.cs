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
}

/// <summary>
/// Processes a wallet authorization response end to end: parse (<see cref="WalletResponseParser"/>),
/// correlate the session via <c>state</c>, verify every presented credential
/// (<see cref="ICredentialVerifier"/>), and complete the session with the outcome.
/// </summary>
internal sealed class WalletCallbackProcessor
{
    private readonly WalletResponseParser _parser;
    private readonly ICredentialVerifier _verifier;
    private readonly IStateCorrelatingSessionStore _store;
    private readonly VerifierOptions _options;
    private readonly ILogger<WalletCallbackProcessor> _logger;

    public WalletCallbackProcessor(
        WalletResponseParser parser,
        ICredentialVerifier verifier,
        ISessionStore store,
        IOptions<VerifierOptions> options,
        ILogger<WalletCallbackProcessor> logger)
    {
        _parser = parser;
        _verifier = verifier;
        _logger = logger;
        // Wallet responses carry only `state` as a correlation handle, so the callback path cannot
        // work against a store that has no state index.
        _store = store as IStateCorrelatingSessionStore ?? throw new InvalidOperationException(
            $"The registered {nameof(ISessionStore)} ({store.GetType().Name}) does not implement " +
            $"{nameof(IStateCorrelatingSessionStore)}, which the wallet callback endpoint requires " +
            "to correlate responses by OpenID4VP 'state'. Implement that interface on your store.");
        _options = options.Value;
    }

    public async Task<CallbackOutcome> ProcessAsync(WalletResponseData response, CancellationToken ct)
    {
        ParsedWalletResponse parsed;
        try
        {
            parsed = await _parser.ParseDetailedAsync(response, ct).ConfigureAwait(false);
        }
        catch (WalletResponseException e)
        {
            Log.CallbackParseFailed(_logger, e);
            return CallbackOutcome.ResponseInvalid;
        }

        // SPEC: OpenID4VP 1.0 — state echoes the request and is this verifier's session correlation
        // handle; a response without a known state is rejected (replay / stray callback protection).
        if (parsed.State is null)
        {
            Log.CallbackMissingState(_logger);
            return CallbackOutcome.ResponseInvalid;
        }

        var session = await _store.FindByStateAsync(parsed.State, ct).ConfigureAwait(false);
        if (session is null)
        {
            Log.CallbackUnknownState(_logger, parsed.State);
            return CallbackOutcome.UnknownSession;
        }

        if (session.Status != VerificationSessionStatus.Pending)
        {
            Log.CallbackNotPending(_logger, session.SessionId, session.Status);
            return CallbackOutcome.SessionNotPending; // Sessions complete exactly once (replay protection).
        }

        var context = new VerificationContext
        {
            Nonce = session.Request.Nonce,
            Audience = _options.ClientId,
            ExpectedVct = _options.ExpectedVct ?? DemoRequestOptionsFactory.DefaultVct,
        };

        // Verify every presented credential; the session completes with the first failure, or with
        // the first credential's result when all pass (v0.1 flows request a single credential).
        VerificationResult? outcome = null;
        foreach (var credential in parsed.Credentials)
        {
            var result = await _verifier.VerifyAsync(credential, context, ct).ConfigureAwait(false);
            outcome ??= result;
            if (!result.IsValid)
            {
                outcome = result;
                break;
            }
        }

        await _store.CompleteAsync(session.SessionId, outcome!, ct).ConfigureAwait(false);

        if (outcome!.IsValid)
        {
            Log.VerificationSucceeded(_logger, session.SessionId, outcome.Issuer.Identifier, outcome.Issuer.KeyResolutionMethod);
        }
        else
        {
            Log.VerificationFailed(_logger, session.SessionId, outcome.Issuer.Identifier,
                string.Join(",", outcome.Errors.Select(e => e.Code)));
        }

        return CallbackOutcome.Completed;
    }
}
