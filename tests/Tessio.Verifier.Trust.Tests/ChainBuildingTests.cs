using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tessio.Verifier.Trust.Tests;

/// <summary>
/// What a chain is built from: the presented certificates and the configured anchors, and nothing the
/// certificates point at.
/// </summary>
/// <remarks>
/// What belongs here: the inputs to chain building, as opposed to its verdicts, which
/// <c>X5cAnchoringTests</c> owns. A certificate can carry an Authority Information Access URL for its
/// issuer's certificate, and the platform follows it unless the policy says not to.
/// </remarks>
public sealed class ChainBuildingTests : IDisposable
{
    private const string Issuer = "https://issuer.example";

    /// <summary>
    /// Long enough for a platform chain engine to have made its request if it was going to, since the
    /// build itself is synchronous and the listener counts on its own thread.
    /// </summary>
    private static readonly TimeSpan SettleTime = TimeSpan.FromMilliseconds(500);

    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private int _requests;

    public ChainBuildingTests()
    {
        _listener.Start();
        _ = Task.Run(ServeAsync);
    }

    private string IssuerCertificateUrl => $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/issuer.cer";

    /// <summary>Counts every connection and answers 404, so a follower gets nothing it can use.</summary>
    private async Task ServeAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            Interlocked.Increment(ref _requests);
            using (client)
            {
                var reply = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                await client.GetStream().WriteAsync(reply);
            }
        }
    }

    private static CertificateRequest RequestFor(string subject, ECDsa key, bool isCa)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        return request;
    }

    private (X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf) Pki()
    {
        var root = RequestFor("CN=Test Root", _rootKey, isCa: true)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        // CreateSelfSigned returns the root with its private key attached, so it can sign directly.
        var intermediate = RequestFor("CN=Test Intermediate", _intermediateKey, isCa: true)
            .Create(root,DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(6), Guid.NewGuid().ToByteArray());

        // The leaf names where its issuer's certificate can be fetched: the listener.
        var leafRequest = RequestFor("CN=Test Leaf", _leafKey, isCa: false);
        leafRequest.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(ocspUris: null, caIssuersUris: [IssuerCertificateUrl]));
        using var intermediateWithKey = intermediate.CopyWithPrivateKey(_intermediateKey);
        var leaf = leafRequest.Create(
            intermediateWithKey, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(3), Guid.NewGuid().ToByteArray());

        return (root, intermediate, leaf);
    }

    private static ReadOnlyMemory<byte>[] Chain(params X509Certificate2[] certificates) =>
        certificates.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray();

    /// <summary>
    /// A chain presented without its intermediate is refused, and the URL the leaf names for that
    /// intermediate is never requested.
    /// </summary>
    [Fact]
    public async Task AMissingIntermediate_IsNotFetched_FromTheUrlTheLeafNames()
    {
        var (root, intermediate, leaf) = Pki();
        using (root)
        using (intermediate)
        using (leaf)
        {
            var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [root]);

            var status = await resolver.ResolveAsync(Issuer, Chain(leaf));
            await Task.Delay(SettleTime);

            Assert.False(status.Trusted);
            Assert.Equal(0, Volatile.Read(ref _requests));
        }
    }

    /// <summary>
    /// The control: the same chain, presented whole, anchors without any request. So the refusal above
    /// is the missing intermediate, not a PKI that could never have built.
    /// </summary>
    [Fact]
    public async Task TheSameChain_PresentedWhole_IsTrusted_WithoutAnyRequest()
    {
        var (root, intermediate, leaf) = Pki();
        using (root)
        using (intermediate)
        using (leaf)
        {
            var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [root]);

            var status = await resolver.ResolveAsync(Issuer, Chain(leaf, intermediate));
            await Task.Delay(SettleTime);

            Assert.True(status.Trusted, status.Reason);
            Assert.Equal(0, Volatile.Read(ref _requests));
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _stop.Dispose();
        _rootKey.Dispose();
        _intermediateKey.Dispose();
        _leafKey.Dispose();
    }
}
