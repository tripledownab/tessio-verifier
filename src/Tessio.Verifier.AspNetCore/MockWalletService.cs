using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
    private readonly ResponseEncryptionKeyProvider _encryptionKeys;
    private readonly VerifierOptions _options;

    public MockWalletService(
        MockWalletQueue queue,
        ISessionStore store,
        WalletCallbackProcessor processor,
        MockCredentialIssuer issuer,
        MockMdocIssuer mdocIssuer,
        ResponseEncryptionKeyProvider encryptionKeys,
        IOptions<VerifierOptions> options)
    {
        _queue = queue;
        _store = store;
        _processor = processor;
        _issuer = issuer;
        _mdocIssuer = mdocIssuer;
        _encryptionKeys = encryptionKeys;
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

                var presentation = _options.CredentialFormat == "mso_mdoc"
                    ? _mdocIssuer.IssueDeviceResponse(
                        claims,
                        _options.ExpectedDocType,
                        _options.MdocNamespace,
                        session.Request.ClientId,
                        session.Request.Nonce,
                        _options.ResponseMode == ResponseMode.DirectPostJwt
                            ? _encryptionKeys.ThumbprintBytes
                            : null,
                        RequestObjectPayload.TryGetResponseUri(session.Request.SignedRequestObject) ?? string.Empty)
                    : _issuer.IssuePresentation(
                        claims,
                        _options.ExpectedVct ?? DemoRequestOptionsFactory.DefaultVct,
                        session.Request.Nonce,
                        _options.ClientId,
                        RequestObjectPayload.TryGetTransactionData(session.Request.SignedRequestObject));

                // Mirror what a wallet POSTs: cleartext form for direct_post (OpenID4VP 1.0 §8.2),
                // or an ECDH-ES-encrypted response JWT for direct_post.jwt (§8.3, the HAIP default).
                var form = _options.ResponseMode == ResponseMode.DirectPostJwt
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    {
                        ["response"] = new[] { EncryptResponse(presentation, session.Request.State ?? string.Empty) },
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
        }
    }

    /// <summary>
    /// Encrypts the authorization response the way a HAIP wallet does: ephemeral EC key,
    /// ECDH-ES+A256KW against the verifier's advertised public key, epk in the JWE header.
    /// </summary>
    private string EncryptResponse(string presentation, string state)
    {
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ep = ephemeral.ExportParameters(false);
        var verifierJwk = new JsonWebKey(_encryptionKeys.PublicJwk.ToJsonString());

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            EncryptingCredentials = new EncryptingCredentials(
                new ECDsaSecurityKey(ephemeral), SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes128CbcHmacSha256)
            {
                KeyExchangePublicKey = verifierJwk,
            },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                // SPEC: RFC 7518 §4.6 — epk (the sender's ephemeral public key) is required for the
                // receiver's key agreement; IdentityModel does not write it itself.
                ["epk"] = new Dictionary<string, string>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(ep.Q.X!),
                    ["y"] = Base64UrlEncoder.Encode(ep.Q.Y!),
                },
            },
            Claims = new Dictionary<string, object>
            {
                ["vp_token"] = new Dictionary<string, string[]> { ["credential"] = [presentation] },
                ["state"] = state,
            },
        });
    }
}
