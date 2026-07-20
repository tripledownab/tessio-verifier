using System.Net;
using System.Text;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>Trust resolver returning a fixed verdict and capturing what it was asked.</summary>
internal sealed class FakeTrustListResolver : ITrustListResolver
{
    private readonly bool _trusted;

    public FakeTrustListResolver(bool trusted = true) => _trusted = trusted;

    public string? SeenIssuer { get; private set; }

    public int SeenChainLength { get; private set; }

    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        SeenIssuer = issuer;
        SeenChainLength = x5c.Length;
        return Task.FromResult(new IssuerTrustStatus
        {
            Trusted = _trusted,
            TrustListSource = _trusted ? "fake://trust-list" : null,
            Reason = _trusted ? null : "issuer not on the test trust list",
        });
    }
}

/// <summary>Serves canned JSON responses by absolute URL; anything else is a 404.</summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Dictionary<string, string> _responses = new(StringComparer.Ordinal);

    public FakeHttpHandler Map(string url, string json)
    {
        _responses[url] = json;
        return this;
    }

    public List<string> Requested { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri!.ToString();
        Requested.Add(url);
        return Task.FromResult(_responses.TryGetValue(url, out var json)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") }
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
