using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// What belongs here: how the parser answers an encrypted response whose decrypted payload is not the
/// response parameters it should hold. ECDH-ES is anonymous key agreement, so anyone holding the
/// verifier's published encryption key can encrypt any payload to it; each of these must be refused as a
/// malformed response, never escape as some other exception.
/// </summary>
public sealed class DecryptedPayloadTests : IDisposable
{
    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private string EncryptToVerifier(string plaintext)
    {
        var p = _verifierEc.ExportParameters(false);
        return WalletEncryption.EcdhEsTo(new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = Base64UrlEncoder.Encode(p.Q.X!),
            Y = Base64UrlEncoder.Encode(p.Q.Y!),
        }, plaintext);
    }

    private async Task<Exception?> ParseAsync(string plaintext)
    {
        var parser = new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        });
        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["response"] = new[] { EncryptToVerifier(plaintext) },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
        return await Record.ExceptionAsync(() => parser.ParseDetailedAsync(response));
    }

    private static string NestedJwt(string encodedPayload) =>
        $"{Base64UrlEncoder.Encode("{\"alg\":\"none\"}")}.{encodedPayload}.";

    /// <summary>
    /// A decrypted payload that is not the response parameters: not JSON, the wrong JSON or a nested JWT
    /// that does not carry them.
    /// </summary>
    [Theory]
    // A payload that starts like a JSON object and is not one.
    [InlineData("an object that is not JSON", "{ this is not json")]
    [InlineData("a lone opening brace", "{")]
    [InlineData("a truncated object", "{\"vp_token\":")]
    [InlineData("an object nested deeper than the parser allows", "DEEP")]
    // Well formed JSON that is not the response parameters.
    [InlineData("an object with no vp_token", "{}")]
    [InlineData("a vp_token that is a number", "{\"vp_token\":5}")]
    [InlineData("a vp_token that is null", "{\"vp_token\":null}")]
    [InlineData("a vp_token with no presentations", "{\"vp_token\":{\"q\":[]}}")]
    [InlineData("a presentation that is an object", "{\"vp_token\":{\"q\":[{}]}}")]
    // Well formed JSON whose strings cannot be read as text: an escaped lone UTF-16 surrogate.
    [InlineData("a vp_token string with a lone surrogate", "{\"vp_token\":\"\\uD800\",\"state\":\"s\"}")]
    [InlineData("a state with a lone surrogate", "{\"vp_token\":\"abc\",\"state\":\"\\uDC00\"}")]
    [InlineData("a presentation with a lone surrogate", "{\"vp_token\":{\"q\":[\"\\uD800\"]},\"state\":\"s\"}")]
    [InlineData("a member name with a lone surrogate", "{\"vp_token\":{\"q\":[\"a\"]},\"\\uD800\":1}")]
    [InlineData("a query id with a lone surrogate", "{\"vp_token\":{\"\\uDC00\":[\"a\"]},\"state\":\"s\"}")]
    // A nested JWT whose payload is not a JSON object is refused before it reaches the JSON parser,
    // because the JWT parser itself requires one. Kept so that stays true.
    [InlineData("a nested JWT whose payload is an array", "NESTED:[1,2]")]
    [InlineData("a nested JWT whose payload is a string", "NESTED:\"vp_token\"")]
    [InlineData("a nested JWT whose payload is not JSON", "NESTED:not json at all")]
    [InlineData("a nested JWT whose payload is not base64url", "RAWNESTED:A")]
    public async Task AMalformedDecryptedPayload_IsRefusedAsAMalformedResponse(string what, string payload)
    {
        var plaintext = payload switch
        {
            _ when payload.StartsWith("NESTED:", StringComparison.Ordinal) =>
                NestedJwt(Base64UrlEncoder.Encode(payload["NESTED:".Length..])),
            _ when payload.StartsWith("RAWNESTED:", StringComparison.Ordinal) => NestedJwt(payload["RAWNESTED:".Length..]),
            // Past System.Text.Json's default maximum depth, which it reports as a JsonException.
            "DEEP" => string.Concat(Enumerable.Repeat("{\"a\":", 100)) + "1" + new string('}', 100),
            _ => payload,
        };

        var e = await ParseAsync(plaintext);

        Assert.True(e is WalletResponseException, $"{what}: expected WalletResponseException, got {e?.GetType().Name ?? "no exception"}: {e?.Message}");
    }

    /// <summary>
    /// The same refusal on the other route: a response encrypted under a key management algorithm other than
    /// ECDH-ES is decrypted by IdentityModel's handler. Its plaintext is an unsigned JWT, as a sender would
    /// send it, so the envelope is accepted.
    /// </summary>
    [Theory]
    // These reach the parser's own reading of the payload.
    [InlineData("a vp_token that is a number", "{\"vp_token\":5}")]
    [InlineData("a vp_token that is null", "{\"vp_token\":null}")]
    [InlineData("a vp_token number JSON cannot round trip", "{\"vp_token\":1e400,\"state\":\"s\"}")]
    [InlineData("a presentation with a lone surrogate", "{\"vp_token\":{\"q\":[\"\\uD800\"]},\"state\":\"s\"}")]
    // The handler refuses these itself, reading the claims it reads; kept so that stays true.
    [InlineData("a vp_token string with a lone surrogate", "{\"vp_token\":\"\\uD800\",\"state\":\"s\"}")]
    [InlineData("a state with a lone surrogate", "{\"vp_token\":\"abc\",\"state\":\"\\uDC00\"}")]
    [InlineData("a member name with a lone surrogate", "{\"vp_token\":{\"q\":[\"a\"]},\"\\uD800\":1}")]
    public async Task AMalformedPayloadUnderDirectEncryption_IsRefusedAsAMalformedResponse(string what, string payload)
    {
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var jwe = new JsonWebTokenHandler().EncryptToken(
            NestedJwt(Base64UrlEncoder.Encode(payload)),
            new EncryptingCredentials(key, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes128CbcHmacSha256));
        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key });

        var e = await Record.ExceptionAsync(() => parser.ParseDetailedAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [jwe] },
            Body = ReadOnlyMemory<byte>.Empty,
        }));

        Assert.True(e is WalletResponseException, $"{what}: expected WalletResponseException, got {e?.GetType().Name ?? "no exception"}: {e?.Message}");
    }

    /// <summary>The well formed case on that route, so the refusals above are refusals of the payload.</summary>
    [Fact]
    public async Task AWellFormedPayloadUnderDirectEncryption_IsParsed()
    {
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var jwe = new JsonWebTokenHandler().EncryptToken(
            NestedJwt(Base64UrlEncoder.Encode("{\"vp_token\":{\"q\":[\"a~\"]},\"state\":\"s\"}")),
            new EncryptingCredentials(key, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes128CbcHmacSha256));
        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key });

        var parsed = await parser.ParseDetailedAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [jwe] },
            Body = ReadOnlyMemory<byte>.Empty,
        });

        Assert.Equal("s", parsed.State);
        Assert.Equal("a~", Assert.Single(parsed.Credentials).RawValue);
    }

    public void Dispose() => _verifierEc.Dispose();
}
