using System.Net;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore;

/// <summary>Queue of session ids awaiting TEST-mode fixture replay.</summary>
internal sealed class TestFixtureQueue
{
    private readonly Channel<string> _channel =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });

    public ValueTask EnqueueAsync(string sessionId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(sessionId, ct);

    public IAsyncEnumerable<string> DequeueAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

/// <summary>
/// TEST mode: replays the pinned RFC 9901 conformance vector through the real
/// <see cref="SdJwtVcVerifier"/> and completes the session with the actual verification result.
/// Runs fully offline — the fixture's issuer metadata is served from memory. Unlike MOCK (which
/// exercises the whole protocol with freshly generated credentials), TEST proves the verifier
/// against immutable, specification-published bytes.
/// </summary>
internal sealed class TestFixtureService : BackgroundService
{
    private readonly TestFixtureQueue _queue;
    private readonly ISessionStore _store;
    private readonly SdJwtVcVerifier _verifier;

    public TestFixtureService(TestFixtureQueue queue, ISessionStore store)
    {
        _queue = queue;
        _store = store;

        // A dedicated verifier instance: fixture metadata served offline, fixture issuer trusted.
        _verifier = new SdJwtVcVerifier(
            new StaticTrustListResolver([ConformanceFixture.Issuer], source: "rfc9901-fixture"),
            httpClient: new HttpClient(new FixtureMetadataHandler()));
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

                // The fixture's KB-JWT is bound to the RFC's published nonce and audience, so the
                // verification context uses those — the point here is the pinned credential bytes.
                var result = await _verifier.VerifyAsync(
                    new PresentedCredential { Format = "dc+sd-jwt", RawValue = ConformanceFixture.Presentation },
                    new VerificationContext
                    {
                        Nonce = ConformanceFixture.Nonce,
                        Audience = ConformanceFixture.Audience,
                        ExpectedVct = ConformanceFixture.Vct,
                    },
                    stoppingToken).ConfigureAwait(false);

                await _store.CompleteAsync(sessionId, result, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>Serves the fixture's issuer metadata from memory; everything else is a 404.</summary>
    private sealed class FixtureMetadataHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = string.Equals(request.RequestUri?.ToString(), ConformanceFixture.IssuerMetadataUrl, StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(ConformanceFixture.IssuerMetadataJson, Encoding.UTF8, "application/json"),
                }
                : new HttpResponseMessage(HttpStatusCode.NotFound);
            return Task.FromResult(response);
        }
    }
}
