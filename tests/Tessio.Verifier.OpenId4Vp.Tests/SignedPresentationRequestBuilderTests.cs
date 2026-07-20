using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

public sealed class SignedPresentationRequestBuilderTests : IDisposable
{
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private SignedPresentationRequestBuilder Builder(Uri? requestUriBase = null) => new(
        new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_ecdsa), SecurityAlgorithms.EcdsaSha256),
            RequestUriBase = requestUriBase,
        });

    private static PresentationRequestOptions Options() => new()
    {
        ClientId = "x509_san_dns:verifier.example",
        Nonce = "nonce-123",
        State = "state-456",
        DcqlQueryJson = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["age_over_18"]}]}]}""",
        ResponseUri = new Uri("https://verifier.example/verify/callback"),
        ResponseMode = ResponseMode.DirectPostJwt,
        RequestLifetime = TimeSpan.FromMinutes(10),
        ClientMetadataJson = """{"client_name":"Test Verifier"}""",
    };

    [Fact]
    public async Task ByValue_SignsVerifiableJar_WithRequiredParameters()
    {
        var request = await Builder().BuildAsync(Options());

        Assert.IsType<PresentationRequest.ByValue>(request);

        // The JAR must verify against the builder's public key and carry the right typ.
        var publicKey = new ECDsaSecurityKey(ECDsa.Create(_ecdsa.ExportParameters(false)));
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(request.SignedRequestObject,
            new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = publicKey,
                ValidTypes = ["oauth-authz-req+jwt"],
            });
        Assert.True(result.IsValid, result.Exception?.Message);

        var token = new JsonWebToken(request.SignedRequestObject);
        Assert.Equal("x509_san_dns:verifier.example", token.GetClaim("client_id").Value);
        Assert.Equal("vp_token", token.GetClaim("response_type").Value);
        Assert.Equal("direct_post.jwt", token.GetClaim("response_mode").Value);
        Assert.Equal("https://verifier.example/verify/callback", token.GetClaim("response_uri").Value);
        Assert.Equal("nonce-123", token.GetClaim("nonce").Value);
        Assert.Equal("state-456", token.GetClaim("state").Value);
        Assert.Contains("https://self-issued.me/v2", token.Audiences);
        Assert.Contains("dc+sd-jwt", token.EncodedPayload.Length > 0
            ? System.Text.Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(token.EncodedPayload))
            : string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ByValue_AuthorizationUri_EmbedsRequestParameter()
    {
        var request = await Builder().BuildAsync(Options());

        // Uri normalizes custom schemes to "openid4vp://authorize/?…"; wallets parse the query either way.
        Assert.Equal("openid4vp", request.AuthorizationRequestUri.Scheme);
        Assert.Contains("client_id=", request.AuthorizationRequestUri.Query, StringComparison.Ordinal);
        Assert.Contains("&request=", request.AuthorizationRequestUri.Query, StringComparison.Ordinal);
        Assert.DoesNotContain("request_uri=", request.AuthorizationRequestUri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ByReference_PointsWalletAtRequestUri()
    {
        var request = await Builder(new Uri("https://verifier.example/verify/request")).BuildAsync(Options());

        var byRef = Assert.IsType<PresentationRequest.ByReference>(request);
        Assert.StartsWith("https://verifier.example/verify/request/", byRef.RequestUri.ToString(), StringComparison.Ordinal);
        Assert.Contains("request_uri=", byRef.AuthorizationRequestUri.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("&request=", byRef.AuthorizationRequestUri.ToString(), StringComparison.Ordinal);
        Assert.NotEmpty(byRef.SignedRequestObject);
    }

    [Fact]
    public async Task RequestLifetime_DrivesExpAndExpiresAt()
    {
        var before = DateTimeOffset.UtcNow;
        var request = await Builder().BuildAsync(Options());

        var token = new JsonWebToken(request.SignedRequestObject);
        var exp = DateTimeOffset.FromUnixTimeSeconds(
            long.Parse(token.GetClaim("exp").Value, System.Globalization.CultureInfo.InvariantCulture));

        Assert.Equal(request.ExpiresAt.ToUnixTimeSeconds(), exp.ToUnixTimeSeconds());
        Assert.InRange(exp, before.AddMinutes(9), before.AddMinutes(11));
    }

    public void Dispose() => _ecdsa.Dispose();
}
