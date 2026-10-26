using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc.Tests;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// OpenID4VP requests for the Digital Credentials API (OpenID4VP 1.0 Appendix A): the protocol identifier, the
/// parameters an unsigned and a signed request may and must carry and the signed request's form.
/// </summary>
public sealed class DcApiPresentationRequestBuilderTests : IDisposable
{
    private const string Dcql = """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","age_over_18"]}]}]}""";

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private DcApiPresentationRequestBuilder SigningBuilder(TimeProvider? clock = null) => new(new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
        SigningCertificateChain = [_certificates.Reader],
        Clock = clock,
    });

    private static DcApiPresentationRequestOptions Unsigned(bool encrypted = true) => new()
    {
        Nonce = "n-0S6_WzA2Mj",
        DcqlQueryJson = Dcql,
        EncryptedResponse = encrypted,
        ExpectedOrigins = ["https://verifier.example"],
        ClientMetadataJson = ClientMetadata.Build(
            "mso_mdoc",
            encrypted ? new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = "eA", ["y"] = "eQ", ["kid"] = "1" } : null),
    };

    private DcApiPresentationRequestOptions SignedOptions() => Unsigned() with
    {
        ClientId = ClientIdentifier.X509Hash(_certificates.Reader),
    };

    private static JsonObject Object(string json) => JsonNode.Parse(json)!.AsObject();

    [Theory]
    [InlineData(true, "dc_api.jwt")]
    [InlineData(false, "dc_api")]
    public void AnUnsignedRequest_CarriesTheParametersInTheClear_AndKeepsItsOriginsAndExpiryOnTheRecord(
        bool encrypted, string responseMode)
    {
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
        var request = new DcApiPresentationRequestBuilder(clock).Build(Unsigned(encrypted));
        var data = Object(request.DataJson);

        Assert.Equal("openid4vp-v1-unsigned", request.Protocol);
        Assert.Equal("vp_token", (string?)data["response_type"]);
        Assert.Equal(responseMode, (string?)data["response_mode"]);
        Assert.Equal("n-0S6_WzA2Mj", (string?)data["nonce"]);
        Assert.Equal("org.iso.18013.5.1.mDL", (string?)data["dcql_query"]!["credentials"]![0]!["meta"]!["doctype_value"]);
        Assert.NotNull(data["client_metadata"]);
        Assert.Equal(["https://verifier.example"], request.ExpectedOrigins);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_800_000_300), request.ExpiresAt);
    }

    [Theory]
    [InlineData("client_id")]
    [InlineData("expected_origins")]
    [InlineData("response_uri")]
    [InlineData("state")]
    [InlineData("aud")]
    [InlineData("request")]
    public void AnUnsignedRequest_OmitsWhatTheTransportForbidsOrDoesNotDefine(string member)
    {
        var data = Object(new DcApiPresentationRequestBuilder().Build(Unsigned()).DataJson);

        Assert.False(data.ContainsKey(member));
    }

    [Fact]
    public void ARequestForAnEncryptedResponse_WithNoKeyToEncryptTo_IsRefused()
    {
        var options = Unsigned(encrypted: true) with { ClientMetadataJson = ClientMetadata.Build("mso_mdoc") };

        var e = Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder().Build(options));
        Assert.Contains("exactly one encryption key", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARequestForAnEncryptedResponse_OfferingTwoKeys_IsRefused()
    {
        // The transcript binds the key the wallet chose, which the verifier cannot tell when there are two.
        var twoKeys = """{"vp_formats_supported":{"mso_mdoc":{}},"jwks":{"keys":[{"kty":"EC","kid":"1"},{"kty":"EC","kid":"2"}]}}""";
        var options = Unsigned(encrypted: true) with { ClientMetadataJson = twoKeys };

        var e = Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder().Build(options));
        Assert.Contains("exactly one encryption key", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"jwks":{"keys":[]}}""")]
    [InlineData("""{"vp_formats_supported":"mso_mdoc"}""")]
    public void ARequestWithoutVpFormatsSupported_IsRefused_EvenInTheClear(string metadataJson)
    {
        var options = Unsigned(encrypted: false) with { ClientMetadataJson = metadataJson };

        var e = Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder().Build(options));
        Assert.Contains("vp_formats_supported", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASignedRequestUsingTheOriginPrefix_IsRefused()
    {
        var e = Assert.Throws<ArgumentException>(() =>
            SigningBuilder().Build(SignedOptions() with { ClientId = "origin:https://verifier.example" }));
        Assert.Contains("origin:", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARequestNamingNoOrigin_IsRefused_SignedOrNot()
    {
        // The verifier refuses a response from any origin a request does not name, so a request naming none could
        // never be answered. An unsigned one would also have nothing binding it to a page.
        Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder().Build(Unsigned() with { ExpectedOrigins = [] }));
        Assert.Throws<ArgumentException>(() => SigningBuilder().Build(SignedOptions() with { ExpectedOrigins = [] }));
    }

    [Fact]
    public void ASignedRequest_IsAJwsInTheRequestMember()
    {
        var request = SigningBuilder().Build(SignedOptions());
        var data = Object(request.DataJson);

        Assert.Equal("openid4vp-v1-signed", request.Protocol);
        Assert.Equal(["request"], data.Select(p => p.Key));
        Assert.Equal(3, ((string)data["request"]!).Split('.').Length);
    }

    [Fact]
    public async Task ASignedRequest_VerifiesAgainstTheCertificateItCarries_AndCarriesTheSignedParameters()
    {
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
        var request = SigningBuilder(clock).Build(SignedOptions());
        var jws = (string)Object(request.DataJson)["request"]!;

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(jws, new TokenValidationParameters
        {
            IssuerSigningKey = new ECDsaSecurityKey(_certificates.Reader.GetECDsaPublicKey()),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidTypes = ["oauth-authz-req+jwt"],
        });
        Assert.True(result.IsValid, result.Exception?.Message);

        var token = (JsonWebToken)result.SecurityToken;
        var payload = Object(Base64UrlEncoder.Decode(token.EncodedPayload));
        Assert.Equal(ClientIdentifier.X509Hash(_certificates.Reader), (string?)payload["client_id"]);
        Assert.Equal(["https://verifier.example"], payload["expected_origins"]!.AsArray().Select(o => (string?)o));
        Assert.Equal("dc_api.jwt", (string?)payload["response_mode"]);
        Assert.Equal("n-0S6_WzA2Mj", (string?)payload["nonce"]);
        Assert.Equal(1_800_000_000, (long)payload["iat"]!);
        Assert.Equal(1_800_000_000 + 300, (long)payload["exp"]!);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_800_000_300), request.ExpiresAt);
        Assert.False(payload.ContainsKey("response_uri"));
        Assert.False(payload.ContainsKey("state"));
        Assert.Equal("https://self-issued.me/v2", (string?)payload["aud"]);

        var x5c = JsonDocument.Parse(Base64UrlEncoder.Decode(jws.Split('.')[0])).RootElement.GetProperty("x5c");
        Assert.Equal(Convert.ToBase64String(_certificates.Reader.RawData), x5c[0].GetString());
    }

    [Fact]
    public void ASelfSignedSigner_IsRefusedUnlessAllowed_AndThenSignsARequestNamingItsHash()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var certificateRequest = new CertificateRequest("CN=sandbox signer", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var options = new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = [certificate],
        };

        Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder(options));

        options.AllowSelfSignedSigningCertificate = true;
        var request = new DcApiPresentationRequestBuilder(options).Build(Unsigned() with
        {
            ClientId = ClientIdentifier.X509Hash(certificate),
        });
        var jws = (string)JsonNode.Parse(request.DataJson)!["request"]!;
        var x5c = JsonDocument.Parse(Base64UrlEncoder.Decode(jws.Split('.')[0])).RootElement.GetProperty("x5c");
        Assert.Equal(Convert.ToBase64String(certificate.RawData), x5c[0].GetString());
    }

    [Fact]
    public void ASignedRequest_FromABuilderWithoutSigningOptions_IsRefused()
    {
        Assert.Throws<InvalidOperationException>(() => new DcApiPresentationRequestBuilder().Build(SignedOptions()));
    }

    [Theory]
    [InlineData("https://verifier.example/")]
    [InlineData("https://Verifier.example")]
    [InlineData("HTTPS://verifier.example")]
    [InlineData("https://verifier.example/path")]
    [InlineData("https://verifier.example?q=1")]
    [InlineData("https://user@verifier.example")]
    [InlineData("https://verifier.example:443")]
    [InlineData("")]
    [InlineData("https://verifier .example")]
    [InlineData("android:apk-key-hash:too-short")]
    public void AnExpectedOriginABrowserWouldNotReport_IsRefused_SignedOrNot(string origin)
    {
        Assert.Throws<ArgumentException>(() => SigningBuilder().Build(SignedOptions() with { ExpectedOrigins = [origin] }));
        Assert.Throws<ArgumentException>(() => new DcApiPresentationRequestBuilder().Build(Unsigned() with { ExpectedOrigins = [origin] }));
    }

    [Theory]
    [InlineData("https://verifier.example")]
    [InlineData("https://verifier.example:8443")]
    [InlineData("http://localhost:5000")]
    [InlineData("android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")]
    public void AnOriginInTheFormAPlatformReports_IsAccepted(string origin)
    {
        var request = SigningBuilder().Build(SignedOptions() with { ExpectedOrigins = [origin] });

        Assert.Equal("openid4vp-v1-signed", request.Protocol);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
