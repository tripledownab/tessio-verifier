using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Reading a Digital Credentials API request's parameters back out of it: from the data object when unsigned,
/// from the request JWS when signed (OpenID4VP 1.0 Appendix A.3).
/// </summary>
public sealed class DcApiRequestParametersTests : IDisposable
{
    private const string DocType = "org.iso.18013.5.1.mDL";
    private static readonly string Query = Dcql.Mdoc(DocType, "org.iso.18013.5.1", "age_over_18");

    private readonly ECDsa _encryptionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose()
    {
        _encryptionKey.Dispose();
        _signingKey.Dispose();
    }

    private (string X, string Y) Coordinates()
    {
        var p = _encryptionKey.ExportParameters(false);
        return (Base64UrlEncoder.Encode(p.Q.X!), Base64UrlEncoder.Encode(p.Q.Y!));
    }

    private string Metadata()
    {
        var (x, y) = Coordinates();
        return ClientMetadata.Build("mso_mdoc", new JsonObject
        {
            ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y, ["use"] = "enc", ["alg"] = "ECDH-ES", ["kid"] = "1",
        });
    }

    private DcApiPresentationRequest Unsigned() => new DcApiPresentationRequestBuilder().Build(new DcApiPresentationRequestOptions
    {
        Nonce = "nonce-1",
        DcqlQueryJson = Query,
        ClientMetadataJson = Metadata(),
        ExpectedOrigins = ["https://verifier.example"],
    });

    private DcApiPresentationRequest Signed() => new DcApiPresentationRequestBuilder(new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_signingKey), SecurityAlgorithms.EcdsaSha256),
    }).Build(new DcApiPresentationRequestOptions
    {
        Nonce = "nonce-1",
        DcqlQueryJson = Query,
        ClientMetadataJson = Metadata(),
        ClientId = "x509_hash:example",
        ExpectedOrigins = ["https://verifier.example", "https://other.example"],
    });

    [Fact]
    public void TheThumbprint_IsRfc7638OverTheKey_WhateverTheKidSays()
    {
        // SPEC: RFC 7638 §3.2: for an EC key the required members are crv, kty, x and y, in lexicographic order,
        // with no whitespace; the thumbprint is the SHA-256 of that JSON. Computed here by hand, independently of
        // the code under test, which a mock wallet sharing that code could not show.
        var (x, y) = Coordinates();
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}"""));

        Assert.Equal(expected, RequestParameters.TryGetEncryptionKeyThumbprint(Unsigned()));
        Assert.Equal(expected, RequestParameters.TryGetEncryptionKeyThumbprint(Signed()));
    }

    [Fact]
    public void BothForms_YieldTheSameExpectations()
    {
        foreach (var request in new[] { Unsigned(), Signed() })
        {
            Assert.Equal(DocType, RequestParameters.TryGetExpectedDocType(request));
            Assert.Equal("mso_mdoc", RequestParameters.TryGetRequestedFormat(request));
            Assert.Equal("dc_api.jwt", RequestParameters.TryGetResponseMode(request));
            Assert.True(RequestParameters.AreRecoverable(request));
        }
    }

    [Fact]
    public void WhetherEncryptionWasAskedFor_FollowsTheResponseModeTheWalletSees()
    {
        // The mock wallet asks the same predicate, so it is checked here against the literal value each builder
        // option writes, not against the mock's answer.
        var cleartext = new DcApiPresentationRequestBuilder().Build(new DcApiPresentationRequestOptions
        {
            Nonce = "nonce-1",
            DcqlQueryJson = Query,
            EncryptedResponse = false,
            ClientMetadataJson = ClientMetadata.Build("mso_mdoc"),
            ExpectedOrigins = ["https://verifier.example"],
        });

        Assert.Equal("dc_api", (string?)JsonNode.Parse(cleartext.DataJson)!["response_mode"]);
        Assert.False(RequestParameters.AsksForEncryptedResponse(cleartext));
        Assert.True(RequestParameters.AsksForEncryptedResponse(Unsigned()));
        Assert.True(RequestParameters.AsksForEncryptedResponse(Signed()));
    }

    [Fact]
    public void TheRecordsNonce_IsTheNonceTheWalletIsSent()
    {
        // Verification reads the nonce from the record and the wallet signs over the one in the data, so the two must
        // be the same value. Read here from the data directly, for the signed form from the JWS payload.
        var unsigned = Unsigned();
        Assert.Equal(unsigned.Nonce, (string?)JsonNode.Parse(unsigned.DataJson)!["nonce"]);

        var signed = Signed();
        var jws = (string)JsonNode.Parse(signed.DataJson)!["request"]!;
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(jws.Split('.')[1]))!;
        Assert.Equal(signed.Nonce, (string?)payload["nonce"]);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""["dcql_query"]""")]
    [InlineData("""{"request":42}""")]
    [InlineData("""{"request":"not-a-jws"}""")]
    public void AnUnreadableDataObject_IsNotRecoverable_AndYieldsNoExpectations(string dataJson)
    {
        var request = Unsigned() with { DataJson = dataJson };

        Assert.False(RequestParameters.AreRecoverable(request));
        Assert.Null(RequestParameters.TryGetExpectedDocType(request));
        Assert.Null(RequestParameters.TryGetEncryptionKeyThumbprint(request));
    }
}
