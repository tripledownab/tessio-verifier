using System.Net;
using System.Text;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Trust.Tests;

public class TrustListLoaderUrlTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly string _json;

        public FakeHandler(string json) => _json = json;

        public string? RequestedUrl { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestedUrl = request.RequestUri!.ToString();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            });
        }
    }

    [Fact]
    public async Task LoadAsync_FromHttpsUrl_FetchesAndParses()
    {
        var handler = new FakeHandler("""{"trusted_issuers":["https://url.example"]}""");
        using var http = new HttpClient(handler);

        var resolver = await TrustListLoader.LoadAsync("https://trust.example/list.json", http);

        Assert.Equal("https://trust.example/list.json", handler.RequestedUrl);
        Assert.True((await resolver.ResolveAsync("https://url.example", [])).Trusted);
        Assert.False((await resolver.ResolveAsync("https://other.example", [])).Trusted);
    }

    [Fact]
    public async Task LoadAsync_UrlWithoutHttpClient_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => TrustListLoader.LoadAsync("https://trust.example/list.json"));
    }
}
