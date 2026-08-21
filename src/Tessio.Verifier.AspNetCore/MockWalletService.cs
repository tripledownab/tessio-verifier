using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
    private readonly ISessionStore _store;
    private readonly WalletCallbackProcessor _processor;
    private readonly MockCredentialIssuer _issuer;
    private readonly MockMdocIssuer _mdocIssuer;
    private readonly VerifierOptions _options;
    private readonly ILogger<MockWalletService> _logger;

    public MockWalletService(
        MockWalletQueue queue,
        ISessionStore store,
        WalletCallbackProcessor processor,
        MockCredentialIssuer issuer,
        MockMdocIssuer mdocIssuer,
        IOptions<VerifierOptions> options,
        ILogger<MockWalletService> logger)
    {
        _queue = queue;
        _store = store;
        _processor = processor;
        _issuer = issuer;
        _mdocIssuer = mdocIssuer;
        _options = options.Value;
        _logger = logger;
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

                var presentation = _options.CredentialFormat == "mso_mdoc"
                    ? _mdocIssuer.IssueDeviceResponse(
                        claims,
                        _options.ExpectedDocType,
                        _options.MdocNamespace,
                        session.Request.ClientId,
                        session.Request.Nonce,
                        _options.ResponseMode == ResponseMode.DirectPostJwt
                            ? RequestParameters.TryGetEncryptionKeyThumbprint(session.Request)
                            : null,
                        RequestParameters.TryGetResponseUri(session.Request) ?? string.Empty)
                    : _issuer.IssuePresentation(
                        claims,
                        _options.ExpectedVct ?? DemoRequestOptionsFactory.DefaultVct,
                        session.Request.Nonce,
                        _options.ClientId,
                        RequestParameters.TryGetTransactionData(session.Request));

                // Mirror what a wallet POSTs: cleartext form for direct_post (OpenID4VP 1.0 §8.2),
                // or an ECDH-ES-encrypted response JWT for direct_post.jwt (§8.3, the HAIP default).
                var form = _options.ResponseMode == ResponseMode.DirectPostJwt
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    {
                        ["response"] = new[]
                        {
                            EncryptResponse(
                                presentation,
                                session.Request.State ?? string.Empty,
                                RequestParameters.TryGetEncryptionJwkJson(session.Request)
                                    ?? throw new InvalidOperationException(
                                        "direct_post.jwt session advertised no encryption key in client_metadata.")),
                        },
                    }
                    : new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    {
                        ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                        ["state"] = new[] { session.Request.State ?? string.Empty },
                    };

                var response = new WalletResponseData
                {
                    ContentType = "application/x-www-form-urlencoded",
                    Form = form,
                    Body = ReadOnlyMemory<byte>.Empty,
                };

                await _processor.ProcessAsync(response, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // Loud, and scoped to this session. Letting the exception escape kills the background
                // loop, after which every later session waits silently for a wallet that no longer
                // exists and times out with no explanation anywhere.
                Log.MockWalletFailed(_logger, e, sessionId);
            }
        }
    }

    /// <summary>Encrypts the response the way a HAIP wallet does. See <see cref="EcdhEsJweEncryptor"/>.</summary>
    private static string EncryptResponse(string presentation, string state, string verifierJwkJson) =>
        EcdhEsJweEncryptor.Encrypt(
            JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["vp_token"] = new Dictionary<string, string[]> { ["credential"] = [presentation] },
                ["state"] = state,
            }),
            verifierJwkJson);
}
