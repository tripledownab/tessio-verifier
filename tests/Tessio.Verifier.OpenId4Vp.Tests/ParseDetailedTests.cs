using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>State extraction via ParseDetailedAsync, including from inside an encrypted response.</summary>
public class ParseDetailedTests
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
    public async Task DirectPost_State_IsExtractedFromForm()
    {
        var vpToken = JsonSerializer.Serialize(new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] });

        var parsed = await new WalletResponseParser().ParseDetailedAsync(
            FormResponse(("vp_token", vpToken), ("state", "state-abc")));

        Assert.Equal("state-abc", parsed.State);
        Assert.Single(parsed.Credentials);
    }

    [Fact]
    public async Task DirectPost_WithoutState_YieldsNull()
    {
        var vpToken = JsonSerializer.Serialize(new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] });

        var parsed = await new WalletResponseParser().ParseDetailedAsync(FormResponse(("vp_token", vpToken)));

        Assert.Null(parsed.State);
    }

    [Fact]
    public async Task DirectPostJwt_State_IsExtractedFromInsideTheJwe()
    {
        // The whole reason ParseDetailedAsync exists: for direct_post.jwt the state is encrypted.
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] },
            ["state"] = "state-inside-jwe",
        });
        var jwe = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(
            payload,
            new EncryptingCredentials(key, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes128CbcHmacSha256));

        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key });
        var parsed = await parser.ParseDetailedAsync(FormResponse(("response", jwe)));

        Assert.Equal("state-inside-jwe", parsed.State);
        Assert.Equal(SampleSdJwt, Assert.Single(parsed.Credentials).RawValue);
    }
}
