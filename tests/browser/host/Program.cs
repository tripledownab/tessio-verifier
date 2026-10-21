// The host the browser test drives: MapTessioVerifier in Live mode, so the start page offers the
// same-device button, plus POST /test/present, which answers a request the way a wallet would. It posts to
// whatever response_uri the request names, so bind it to localhost only, as CI does.
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Tessio.Verifier.AspNetCore;
using Tessio.Verifier.AspNetCore.Tests;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IPresentationRequestBuilder>(sp =>
    new NotTheDemoBuilder(new DemoPresentationRequestBuilder(sp.GetRequiredService<TimeProvider>())));
builder.Services.AddSingleton<ITrustListResolver>(sp => new NotTheDevResolver(new DevDefaultTrustListResolver(
    sp.GetRequiredService<MockCredentialIssuer>(), sp.GetRequiredService<MockMdocIssuer>())));
builder.Services.AddHttpClient();
builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;
    // A plaintext response, so the wallet stand-in below needs no encryption.
    options.ResponseMode = ResponseMode.DirectPost;
    options.RequestedClaims = ["age_over_18"];
});

var app = builder.Build();
app.MapTessioVerifier();

// Answers the request in walletUrl, as a wallet would, and returns what the verifier answered the wallet.
// A valid answer is made with the request's own nonce; an invalid one with another, so it fails verification.
app.MapPost("/test/present", async (PresentRequest present, MockCredentialIssuer issuer,
    IOptions<VerifierOptions> options, IHttpClientFactory http) =>
{
    var requestObject = HttpUtility.ParseQueryString(new Uri(present.WalletUrl).Query)["request"]
        ?? throw new InvalidOperationException("The wallet URL carries no request object.");
    using var claims = JsonDocument.Parse(WebEncoders.Base64UrlDecode(requestObject.Split('.')[1]));
    var request = claims.RootElement;
    var nonce = present.Valid ? request.GetProperty("nonce").GetString()! : "a-nonce-nobody-issued";

    var presentation = issuer.IssuePresentation(
        ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, nonce, options.Value.ClientId);
    var response = await http.CreateClient().PostAsync(request.GetProperty("response_uri").GetString(),
        new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
            ["state"] = request.GetProperty("state").GetString()!,
        }));
    return Results.Content(await response.Content.ReadAsStringAsync(), "application/json", statusCode: (int)response.StatusCode);
});

app.Run();

internal sealed record PresentRequest(string WalletUrl, bool Valid);

/// <summary>Answers as the dev trust list does, without being it, which Live mode refuses by type.</summary>
internal sealed class NotTheDevResolver(ITrustListResolver inner) : ITrustListResolver
{
    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
        inner.ResolveAsync(issuer, x5c, ct);
}
