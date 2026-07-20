using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

public class DemoPresentationRequestBuilderTests
{
    private static PresentationRequestOptions Options(VerifierOptions? verifierOptions = null) =>
        DemoRequestOptionsFactory.Create(
            verifierOptions ?? new VerifierOptions { RequestedClaims = { "age_over_18" } },
            new Uri("https://verifier.example/verify/callback"));

    [Fact]
    public async Task BuildAsync_ProducesByValueRequest_EchoingClientIdAndNonce()
    {
        var builder = new DemoPresentationRequestBuilder(TimeProvider.System);
        var options = Options();

        var request = await builder.BuildAsync(options);

        Assert.IsType<PresentationRequest.ByValue>(request);
        Assert.Equal(options.ClientId, request.ClientId);
        Assert.Equal(options.Nonce, request.Nonce);
        Assert.Equal("openid4vp", request.AuthorizationRequestUri.Scheme);
        Assert.Contains("request=", request.AuthorizationRequestUri.Query, StringComparison.Ordinal);
        Assert.True(request.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task BuildAsync_RequestObject_IsUnsignedThreePartJwt()
    {
        var builder = new DemoPresentationRequestBuilder(TimeProvider.System);

        var request = await builder.BuildAsync(Options());

        var parts = request.SignedRequestObject.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.Equal(string.Empty, parts[2]); // alg=none → empty signature segment
    }

    [Fact]
    public async Task BuildAsync_DcqlQuery_UsesDcSdJwtFormat()
    {
        var builder = new DemoPresentationRequestBuilder(TimeProvider.System);
        var options = Options();

        await builder.BuildAsync(options);

        // SPEC: SD-JWT VC format identifier is "dc+sd-jwt", not the legacy "vc+sd-jwt".
        Assert.Contains("dc+sd-jwt", options.DcqlQueryJson, StringComparison.Ordinal);
        Assert.DoesNotContain("vc+sd-jwt", options.DcqlQueryJson, StringComparison.Ordinal);
    }
}
