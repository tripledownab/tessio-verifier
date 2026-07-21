using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The interop-realistic encrypted-response path: a wallet encrypts the direct_post.jwt response to
/// the verifier's EC P-256 public key with ECDH-ES+A256KW and includes its ephemeral key in the epk
/// header; the parser decrypts with the private key. IdentityModel ships no receive side for
/// ECDH-ES, so this exercises our EcdhEsJweDecryptor.
/// </summary>
public sealed class EcdhEsResponseTests : IDisposable
{
    private const string SampleSdJwt = "eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~WyJzYWx0IiwibmFtZSIsInYiXQ~";

    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private JsonWebKey VerifierPublicJwk()
    {
        var p = _verifierEc.ExportParameters(false);
        return new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = Base64UrlEncoder.Encode(p.Q.X!),
            Y = Base64UrlEncoder.Encode(p.Q.Y!),
        };
    }

    /// <summary>Wallet-side encryption: ephemeral key, ECDH-ES+A256KW, epk in the header.</summary>
    internal static string WalletEncryptResponse(JsonWebKey verifierPublicJwk, string payloadJson)
    {
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ep = ephemeral.ExportParameters(false);

        // NOTE: IdentityModel's sender requires the key as ECDsaSecurityKey and does NOT write the
        // epk header itself — the caller must add it (RFC 7518 §4.6 requires it for the receiver).
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            EncryptingCredentials = new EncryptingCredentials(
                new ECDsaSecurityKey(ephemeral), SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes128CbcHmacSha256)
            {
                KeyExchangePublicKey = verifierPublicJwk,
            },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["epk"] = new Dictionary<string, string>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(ep.Q.X!),
                    ["y"] = Base64UrlEncoder.Encode(ep.Q.Y!),
                },
            },
            Claims = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson)!,
        });
    }

    private static WalletResponseData ResponseForm(string jwe) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["response"] = new[] { jwe },
        },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    private static string Payload() => JsonSerializer.Serialize(new Dictionary<string, object>
    {
        ["vp_token"] = new Dictionary<string, string[]> { ["pid"] = [SampleSdJwt] },
        ["state"] = "state-ecdh",
    });

    [Fact]
    public async Task EncryptedResponse_EcdhEs_DecryptsAndParses()
    {
        var jwe = WalletEncryptResponse(VerifierPublicJwk(), Payload());

        var parser = new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        });

        var parsed = await parser.ParseDetailedAsync(ResponseForm(jwe));

        Assert.Equal("state-ecdh", parsed.State);
        Assert.Equal(SampleSdJwt, Assert.Single(parsed.Credentials).RawValue);
    }

    [Fact]
    public async Task EncryptedResponse_WrongPrivateKey_Throws()
    {
        var jwe = WalletEncryptResponse(VerifierPublicJwk(), Payload());
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var parser = new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKey = new ECDsaSecurityKey(otherKey),
        });

        await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDetailedAsync(ResponseForm(jwe)));
    }

    [Fact]
    public async Task EncryptedResponse_MissingEpk_Throws()
    {
        // Encrypt without the epk header: undecryptable by construction.
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwe = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            EncryptingCredentials = new EncryptingCredentials(
                new ECDsaSecurityKey(ephemeral), SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes128CbcHmacSha256)
            {
                KeyExchangePublicKey = VerifierPublicJwk(),
            },
            Claims = new Dictionary<string, object> { ["vp_token"] = "x~" },
        });

        var parser = new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        });

        var e = await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDetailedAsync(ResponseForm(jwe)));
        Assert.Contains("epk", e.Message, StringComparison.Ordinal);
    }

    public void Dispose() => _verifierEc.Dispose();
}
