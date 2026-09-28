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
        Assert.True(parsed.Encrypted);
    }

    [Fact]
    public async Task DirectPost_PlaintextForm_IsReportedAsNotEncrypted()
    {
        var parsed = await new WalletResponseParser().ParseDetailedAsync(
            FormResponse(("vp_token", SampleSdJwt), ("state", "s")));

        Assert.False(parsed.Encrypted);
    }

    [Fact]
    public async Task DirectPostJwt_UnsecuredResponseToken_IsRefused()
    {
        // SPEC: OpenID4VP 1.0 §8.3: "implementations MUST use an unsigned, encrypted JWT". An unsecured
        // token (alg "none") in the response parameter is not one, however well formed it is. The
        // parser must refuse it before the handler, which does not require a signature, can validate it.
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        static string B64(string json) => Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(json));
        var unsecured = B64("""{"alg":"none"}""") + "."
            + B64($$"""{"vp_token":{"pid":["{{SampleSdJwt}}"]},"state":"s"}""") + ".";

        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key });
        var refused = await Assert.ThrowsAsync<WalletResponseException>(
            () => parser.ParseDetailedAsync(FormResponse(("response", unsecured))));

        Assert.Contains("not encrypted", refused.Message, StringComparison.Ordinal);
    }
}
