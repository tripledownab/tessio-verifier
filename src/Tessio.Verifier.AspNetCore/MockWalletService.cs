using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>Queue of session ids awaiting a MOCK wallet response.</summary>
internal sealed class MockWalletQueue
{
    private readonly Channel<string> _channel =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });

    public ValueTask EnqueueAsync(string sessionId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(sessionId, ct);

    public IAsyncEnumerable<string> DequeueAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

/// <summary>
/// MOCK-mode wallet: for each started session it issues a real signed SD-JWT VC presentation
/// (bound to the session's nonce) and posts it through the same callback pipeline a live wallet
/// would hit, so verification runs the full protocol path.
/// </summary>
internal sealed class MockWalletService : BackgroundService
{
    private readonly MockWalletQueue _queue;
    private readonly InMemorySessionStore _store;
    private readonly WalletCallbackProcessor _processor;
    private readonly MockCredentialIssuer _issuer;
    private readonly VerifierOptions _options;

    public MockWalletService(
        MockWalletQueue queue,
        InMemorySessionStore store,
        WalletCallbackProcessor processor,
        MockCredentialIssuer issuer,
        IOptions<VerifierOptions> options)
    {
        _queue = queue;
        _store = store;
        _processor = processor;
        _issuer = issuer;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var sessionId in _queue.DequeueAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                var session = await _store.GetAsync(sessionId, stoppingToken).ConfigureAwait(false);
                if (session is null || session.Status != VerificationSessionStatus.Pending)
                {
                    continue;
                }

                var claims = _options.RequestedClaims is { Count: > 0 }
                    ? _options.RequestedClaims
                    : ["age_over_18"];

                var presentation = _issuer.IssuePresentation(
                    claims,
                    _options.ExpectedVct ?? DemoRequestOptionsFactory.DefaultVct,
                    session.Request.Nonce,
                    _options.ClientId);

                // Mirror what a wallet POSTs for direct_post (OpenID4VP 1.0 §8.2).
                var response = new WalletResponseData
                {
                    ContentType = "application/x-www-form-urlencoded",
                    Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    {
                        ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                        ["state"] = new[] { session.Request.State ?? string.Empty },
                    },
                    Body = ReadOnlyMemory<byte>.Empty,
                };

                await _processor.ProcessAsync(response, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
