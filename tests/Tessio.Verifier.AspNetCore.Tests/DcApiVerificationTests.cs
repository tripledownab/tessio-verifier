using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Verifying an OpenID4VP response returned through the Digital Credentials API. The response is bound to the
/// page's origin rather than a client_id (OpenID4VP 1.0 Appendix A.4) and, for mdoc, to the transcript of Annex
/// B.2.6.2: so a response that verifies here has been checked against the origin, the nonce and, under
/// dc_api.jwt, the key the request advertised.
/// </summary>
/// <remarks>
/// The mock wallet reads the request through the same readers as the verifier, so a mistake both shared would
/// round-trip green. Each check that matters is therefore also driven from the other side: a response built for a
/// different request, origin, type or binding, which the verifier must refuse.
/// </remarks>
public sealed class DcApiVerificationTests : IDisposable
{
    private const string Origin = "https://verifier.example";
    private const string AvDocType = MockWalletResponses.EuAgeVerificationDocType;

    private static readonly string MdocQuery =
        $$"""{"credentials":[{"id":"credential","format":"mso_mdoc","meta":{"doctype_value":"{{AvDocType}}"},"claims":[{"path":["{{AvDocType}}","age_over_18"]}]}]}""";

    private static readonly string SdJwtQuery =
        $$"""{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{"vct_values":["{{DemoRequestOptionsFactory.DefaultVct}}"]},"claims":[{"path":["age_over_18"]}]}]}""";

    // One base64url transaction data entry, a JSON object naming the credential query it binds.
    private static readonly string TransactionData =
        $"""["{Base64UrlEncoder.Encode("""{"type":"example_payment","credential_ids":["credential"]}""")}"]""";

    private readonly MockWalletResponses _wallet = new();
    private readonly ECDsa _encryptionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider _provider;

    public DcApiVerificationTests()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustListResolver>(_ => new StaticTrustListResolver(
            [MockWalletResponses.IssuerId, _wallet.MdocIssuerId], "test", [_wallet.IssuerCertificate, _wallet.MdocIacaCertificate]));
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        _provider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _encryptionKey.Dispose();
        _wallet.Dispose();
    }

    private WalletResponseVerifier Verifier => (WalletResponseVerifier)_provider.GetRequiredService<IWalletResponseVerifier>();

    private SecurityKey DecryptionKey => new ECDsaSecurityKey(_encryptionKey);

    /// <summary>
    /// The public half as a wallet expects it. The kid is deliberately not the key's thumbprint: a wallet may
    /// ask for a kid of its own, so the transcript must be built from the key, not from the kid.
    /// </summary>
    private JsonObject EncryptionJwk()
    {
        var p = _encryptionKey.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            ["use"] = "enc",
            ["alg"] = "ECDH-ES",
            ["kid"] = "1",
        };
    }

    private DcApiPresentationRequestOptions Options(string query, string format, bool encrypted = true, string nonce = "nonce-1") => new()
    {
        Nonce = nonce,
        DcqlQueryJson = query,
        EncryptedResponse = encrypted,
        ExpectedOrigins = [Origin],
        ClientMetadataJson = ClientMetadata.Build(format, encrypted ? EncryptionJwk() : null),
    };

    private DcApiPresentationRequest Request(string query, string format, bool encrypted = true, string nonce = "nonce-1") =>
        new DcApiPresentationRequestBuilder().Build(Options(query, format, encrypted, nonce));

    private static string Errors(VerificationResult result) =>
        string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AnMdocAnswer_Verifies_AndCarriesTheDisclosedAge(bool encrypted)
    {
        var request = Request(MdocQuery, "mso_mdoc", encrypted);
        var data = _wallet.CreateDcApiMdocResponse(request, Origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.True(result.IsValid, Errors(result));
        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[AvDocType]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AnSdJwtAnswer_Verifies(bool encrypted)
    {
        var request = Request(SdJwtQuery, "dc+sd-jwt", encrypted);
        var data = _wallet.CreateDcApiSdJwtResponse(request, Origin);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.True(result.IsValid, Errors(result));
    }

    [Fact]
    public async Task AnMdocAnswerGivenToAnotherOrigin_FailsTheDeviceSignature()
    {
        var request = Request(MdocQuery, "mso_mdoc");
        var data = _wallet.CreateDcApiMdocResponse(request, "https://elsewhere.example", docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("https://verifier.example")]
    [InlineData("origin:https://verifier.example/")]
    public async Task AnSdJwtAnswerNamingAnythingButOriginColonTheOrigin_IsAnAudienceMismatch(string audience)
    {
        // The first is the bare origin, the second A.4's printed example with its trailing slash. The wallet is
        // given the origin as the browser serializes it with no slash. A.4 requires the origin: prefix.
        var request = Request(SdJwtQuery, "dc+sd-jwt");
        var data = _wallet.CreateDcApiSdJwtResponse(request, Origin, audience: audience);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.AudienceMismatch);
    }

    [Theory]
    [InlineData("https://elsewhere.example")]
    [InlineData("https://Verifier.example")]
    public async Task AnAnswerThroughAnOriginTheRequestDoesNotName_IsRefused_EvenWhenTheWalletBoundItThere(string origin)
    {
        // A relay: the wallet answered on another page and bound the answer to that page's origin, so the
        // presentation itself is sound for that origin. Only the request's own origins can refuse it, and for an
        // unsigned request those live only on the request record. The second differs only in case: origins are
        // compared exactly, as a wallet compares them.
        var request = Request(MdocQuery, "mso_mdoc");
        var data = _wallet.CreateDcApiMdocResponse(request, origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(request, origin, data, DecryptionKey);

        Assert.Equal(ErrorCodes.AudienceMismatch, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AnAnswerToAnotherRequest_Fails()
    {
        var asked = Request(MdocQuery, "mso_mdoc", nonce: "nonce-1");
        var other = Request(MdocQuery, "mso_mdoc", nonce: "nonce-2");
        var data = _wallet.CreateDcApiMdocResponse(other, Origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(asked, Origin, data, DecryptionKey);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task AnMdocOfAnotherDocumentType_IsRefused()
    {
        var request = Request(MdocQuery, "mso_mdoc");
        var data = _wallet.CreateDcApiMdocResponse(request, Origin, docType: "org.iso.18013.5.1.mDL");

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task AnSdJwtOfAnotherType_IsRefused()
    {
        var request = Request(SdJwtQuery, "dc+sd-jwt");
        var data = _wallet.CreateDcApiSdJwtResponse(request, Origin, vct: "https://other.example/vct");

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.VctMismatch);
    }

    [Fact]
    public async Task TransactionData_IsBound_AndAnAnswerThatDoesNotAcknowledgeIt_IsRefused()
    {
        var bound = new DcApiPresentationRequestBuilder().Build(
            Options(SdJwtQuery, "dc+sd-jwt") with { TransactionDataJson = TransactionData });
        var acknowledged = _wallet.CreateDcApiSdJwtResponse(bound, Origin);
        var accepted = await Verifier.VerifyDcApiAsync(bound, Origin, acknowledged, DecryptionKey);
        Assert.True(accepted.IsValid, Errors(accepted));

        // Same nonce, origin and key, no transaction data: the answer a wallet that ignored the binding would give.
        var unbound = Request(SdJwtQuery, "dc+sd-jwt");
        var ignored = _wallet.CreateDcApiSdJwtResponse(unbound, Origin);
        var refused = await Verifier.VerifyDcApiAsync(bound, Origin, ignored, DecryptionKey);
        Assert.Contains(refused.Errors, e => e.Code == ErrorCodes.TransactionDataMissing);
    }

    [Fact]
    public async Task ACleartextAnswerToARequestForEncryption_IsRefused()
    {
        var encrypted = Request(MdocQuery, "mso_mdoc", encrypted: true);
        var cleartext = _wallet.CreateDcApiMdocResponse(Request(MdocQuery, "mso_mdoc", encrypted: false), Origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(encrypted, Origin, cleartext, DecryptionKey);

        Assert.Equal("response_invalid", Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ACleartextWalletError_IsAWalletError_WhicheverModeWasAskedFor(bool encrypted)
    {
        // OpenID4VP 1.0 Appendix A.4: "Protocol error responses are returned as an object within the data property".
        var request = Request(MdocQuery, "mso_mdoc", encrypted);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, """{"error":"access_denied"}""", DecryptionKey);

        Assert.Equal(ErrorCodes.WalletError, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task NoKeyForARequestThatAskedForEncryption_IsTheCallersMistake_AndThrows()
    {
        var request = Request(MdocQuery, "mso_mdoc", encrypted: true);
        var data = _wallet.CreateDcApiMdocResponse(request, Origin, docType: AvDocType);

        var e = await Assert.ThrowsAsync<ArgumentNullException>(() => Verifier.VerifyDcApiAsync(request, Origin, data, null));
        Assert.Equal("responseDecryptionKey", e.ParamName);
    }

    [Fact]
    public async Task AnEncryptedAnswerToACleartextRequest_IsResponseInvalid()
    {
        var cleartext = Request(MdocQuery, "mso_mdoc", encrypted: false);
        var encrypted = _wallet.CreateDcApiMdocResponse(Request(MdocQuery, "mso_mdoc", encrypted: true), Origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(cleartext, Origin, encrypted, null);

        Assert.Equal("response_invalid", Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AMalformedAnswer_IsResponseInvalid_NotAnException()
    {
        var request = Request(MdocQuery, "mso_mdoc");

        var result = await Verifier.VerifyDcApiAsync(request, Origin, "not json", DecryptionKey);

        Assert.Equal("response_invalid", Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AnAnswerNamingAParameterTwice_IsRefused_WhicheverCopyWouldHaveBeenRead()
    {
        // JSON parsing keeps both and a read takes the last, so a valid answer last would verify while the first
        // rode along unread. Refused for the cleartext object and for its encrypted form alike.
        var cleartextRequest = Request(MdocQuery, "mso_mdoc", encrypted: false);
        var valid = _wallet.CreateDcApiMdocResponse(cleartextRequest, Origin, docType: AvDocType);
        var cleartextTwice = """{"vp_token":{"credential":["junk"]},""" + valid.TrimStart('{');
        Assert.Equal("response_invalid", Assert.Single((await Verifier.VerifyDcApiAsync(cleartextRequest, Origin, cleartextTwice, DecryptionKey)).Errors).Code);

        var sealedRequest = Request(MdocQuery, "mso_mdoc", encrypted: true);
        var sealedValid = _wallet.CreateDcApiMdocResponse(sealedRequest, Origin, docType: AvDocType);
        var sealedTwice = """{"response":"junk",""" + sealedValid.TrimStart('{');
        Assert.Equal("response_invalid", Assert.Single((await Verifier.VerifyDcApiAsync(sealedRequest, Origin, sealedTwice, DecryptionKey)).Errors).Code);
    }

    [Fact]
    public async Task AnAnswerAfterTheRequestExpired_IsRefused()
    {
        var request = Request(MdocQuery, "mso_mdoc") with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };
        var data = _wallet.CreateDcApiMdocResponse(request, Origin, docType: AvDocType);

        var result = await Verifier.VerifyDcApiAsync(request, Origin, data, DecryptionKey);

        Assert.Equal(ErrorCodes.RequestExpired, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AStoredRequestThatCanNoLongerBeRead_IsRefused_BeforeTheAnswerIsLookedAt()
    {
        // The answer is sound for the origin and nonce. Without the request's query nothing would check its type.
        var request = Request(MdocQuery, "mso_mdoc");
        var data = _wallet.CreateDcApiMdocResponse(request, Origin, docType: AvDocType);
        var unreadable = request with { Protocol = DcApiPresentationRequestBuilder.SignedProtocol, DataJson = """{"request":"not-a-jws"}""" };

        var result = await Verifier.VerifyDcApiAsync(unreadable, Origin, data, DecryptionKey);

        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
        Assert.False(WalletResponseVerifier.CanVerify(unreadable));
        Assert.True(WalletResponseVerifier.CanVerify(request));
    }

    [Fact]
    public async Task ASignedRequest_IsAnsweredThroughTheOriginsItNames()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var builder = new DcApiPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
        });
        var request = builder.Build(Options(MdocQuery, "mso_mdoc") with
        {
            ClientId = "x509_hash:example",
            ExpectedOrigins = ["https://named.example"],
        });

        var named = _wallet.CreateDcApiMdocResponse(request, "https://named.example", docType: AvDocType);
        var accepted = await Verifier.VerifyDcApiAsync(request, "https://named.example", named, DecryptionKey);
        Assert.True(accepted.IsValid, Errors(accepted));

        var unnamed = _wallet.CreateDcApiMdocResponse(request, Origin, docType: AvDocType);
        var refused = await Verifier.VerifyDcApiAsync(request, Origin, unnamed, DecryptionKey);
        Assert.Equal(ErrorCodes.AudienceMismatch, Assert.Single(refused.Errors).Code);
    }
}
