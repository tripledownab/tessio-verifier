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

    /// <summary>
    /// Issuers this resolver refuses regardless of the fixed verdict. The verifier asks it about two
    /// different identities now, the credential's issuer and the status list token's signer, so a
    /// single global verdict cannot express "the credential is trusted and its status list is not",
    /// which is the case the status authenticity test has to build.
    /// </summary>
    public HashSet<string> Untrusted { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Anchor provenance to report on a trusted verdict, as the real resolver does for an x5c chain.
    /// Null leaves both anchor fields null, which is the identifier route and this fake's default.
    /// </summary>
    public (string Subject, string Thumbprint)? Anchor { get; set; }

    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        SeenIssuer = issuer;
        SeenChainLength = x5c.Length;
        var trusted = _trusted && !Untrusted.Contains(issuer);
        return Task.FromResult(new IssuerTrustStatus
        {
            Trusted = trusted,
            // NAMED ON BOTH VERDICTS, matching the real resolver. This read
            // `trusted ? "fake://trust-list" : null`, under which a refusal recorded nothing about which
            // list refused it. A double that behaves unlike the thing it stands in for is how a wiring
            // test passes while production is wrong, so the two are kept in step deliberately.
            TrustListSource = "fake://trust-list",
            TrustAnchorSubject = trusted ? Anchor?.Subject : null,
            TrustAnchorThumbprint = trusted ? Anchor?.Thumbprint : null,
            Reason = trusted ? null : "issuer not on the test trust list",
        });
    }
}

/// <summary>A trust seam whose trust source is down: every question throws, as a failed fetch would.</summary>
internal sealed class FailingTrustListResolver(Func<Exception>? failure = null) : ITrustListResolver
{
    private readonly Func<Exception> _failure = failure ?? (() => new HttpRequestException("trust source unreachable"));

    public int Calls { get; private set; }

    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        Calls++;
        throw _failure();
    }
}

/// <summary>Serves canned JSON responses by absolute URL; anything else is a 404.</summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Dictionary<string, string> _responses = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _binary = new(StringComparer.Ordinal);

    public FakeHttpHandler Map(string url, string json)
    {
        _responses[url] = json;
        return this;
    }

    /// <summary>Serves raw bytes, such as a DER certificate, at <paramref name="url"/>.</summary>
    public FakeHttpHandler MapBytes(string url, byte[] body)
    {
        _binary[url] = body;
        return this;
    }

    public List<string> Requested { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri!.ToString();
        Requested.Add(url);
        if (_binary.TryGetValue(url, out var body))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }

        return Task.FromResult(_responses.TryGetValue(url, out var json)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") }
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
