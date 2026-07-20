using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

public class WalletResponseParserTests
{
    private const string SampleSdJwt = "eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~WyJzYWx0IiwibmFtZSIsInYiXQ~";

    private static WalletResponseData FormResponse(params (string Key, string Value)[] fields) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = fields.ToDictionary(
            f => f.Key,
            f => (IReadOnlyList<string>)new[] { f.Value },
            StringComparer.Ordinal),
        Body = ReadOnlyMemory<byte>.Empty,
    };

    [Fact]
    public async Task DirectPost_VpTokenObject_ExtractsPresentations()
    {
        var vpToken = JsonSerializer.Serialize(new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] });

        var credentials = await new WalletResponseParser().ParseAsync(FormResponse(("vp_token", vpToken)));

        var credential = Assert.Single(credentials);
        Assert.Equal("dc+sd-jwt", credential.Format);
        Assert.Equal(SampleSdJwt, credential.RawValue);
    }

    [Fact]
    public async Task DirectPost_MultipleQueriesAndPresentations_AllExtracted()
    {
        var vpToken = JsonSerializer.Serialize(new Dictionary<string, string[]>
        {
            ["pid"] = [SampleSdJwt, SampleSdJwt],
            ["mdl"] = [SampleSdJwt],
        });

        var credentials = await new WalletResponseParser().ParseAsync(FormResponse(("vp_token", vpToken)));

        Assert.Equal(3, credentials.Count);
    }

    [Fact]
    public async Task DirectPost_BareCompactSerialization_IsAcceptedLeniently()
    {
        var credentials = await new WalletResponseParser().ParseAsync(FormResponse(("vp_token", SampleSdJwt)));

        Assert.Equal(SampleSdJwt, Assert.Single(credentials).RawValue);
    }

    [Fact]
    public async Task DirectPostJwt_EncryptedResponse_IsDecryptedAndParsed()
    {
        // Verifier's ephemeral response-encryption key (advertised via client_metadata.jwks in real flows).
        var decryptionKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var vpToken = new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] };
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = vpToken,
            ["state"] = "state-456",
        });

        var jwe = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(
            payload,
            new EncryptingCredentials(decryptionKey, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes128CbcHmacSha256));

        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = decryptionKey });
        var credentials = await parser.ParseAsync(FormResponse(("response", jwe)));

        var credential = Assert.Single(credentials);
        Assert.Equal(SampleSdJwt, credential.RawValue);
    }

    [Fact]
    public async Task DirectPostJwt_WrongKey_Throws()
    {
        var encryptionKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var otherKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var jwe = new JsonWebTokenHandler().CreateToken(
            """{"vp_token":{"pid":["x~"]}}""",
            new EncryptingCredentials(encryptionKey, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes128CbcHmacSha256));

        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = otherKey });

        await Assert.ThrowsAsync<WalletResponseException>(
            () => parser.ParseAsync(FormResponse(("response", jwe))));
    }

    [Fact]
    public async Task DirectPostJwt_WithoutConfiguredKey_Throws()
    {
        var e = await Assert.ThrowsAsync<WalletResponseException>(
            () => new WalletResponseParser().ParseAsync(FormResponse(("response", "eyJ.."))));

        Assert.Contains("ResponseDecryptionKey", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongContentType_Throws()
    {
        var response = new WalletResponseData
        {
            ContentType = "application/json",
            Form = new Dictionary<string, IReadOnlyList<string>>(),
            Body = Encoding.UTF8.GetBytes("{}"),
        };

        await Assert.ThrowsAsync<WalletResponseException>(() => new WalletResponseParser().ParseAsync(response));
    }

    [Fact]
    public async Task MissingVpTokenAndResponse_Throws()
    {
        await Assert.ThrowsAsync<WalletResponseException>(
            () => new WalletResponseParser().ParseAsync(FormResponse(("state", "s"))));
    }

    [Fact]
    public async Task EmptyVpTokenObject_Throws()
    {
        await Assert.ThrowsAsync<WalletResponseException>(
            () => new WalletResponseParser().ParseAsync(FormResponse(("vp_token", "{}"))));
    }

    [Fact]
    public async Task DuplicateFormParameter_Throws()
    {
        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { "a~", "b~" },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        await Assert.ThrowsAsync<WalletResponseException>(() => new WalletResponseParser().ParseAsync(response));
    }
}
