using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// A <c>direct_post.jwt</c> form is answered by its encrypted <c>response</c> alone. A cleartext answer beside it,
/// a <c>vp_token</c> or an <c>error</c>, is refused with the pair, as the Digital Credentials API path refuses it.
/// </summary>
public sealed class EncryptedResponseBesideCleartextAnswerTests : IDisposable
{
    private const string SampleSdJwt = "eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~WyJzYWx0IiwibmFtZSIsInYiXQ~";

    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _verifierEc.Dispose();

    private string SealedPresentation()
    {
        var p = _verifierEc.ExportParameters(false);
        var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = Base64UrlEncoder.Encode(p.Q.X!), Y = Base64UrlEncoder.Encode(p.Q.Y!) };
        return WalletEncryption.EcdhEsTo(jwk, $$"""{"vp_token":{"pid":["{{SampleSdJwt}}"]},"state":"sealed-state"}""");
    }

    private WalletResponseData Form(params (string Name, string Value)[] beside)
    {
        var form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [SealedPresentation()] };
        foreach (var (name, value) in beside)
        {
            form[name] = [value];
        }

        return new WalletResponseData { ContentType = "application/x-www-form-urlencoded", Form = form, Body = ReadOnlyMemory<byte>.Empty };
    }

    private WalletResponseParser Parser(bool readErrorResponses = false) => new(new WalletResponseParserOptions
    {
        ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        ReadErrorResponses = readErrorResponses,
    });

    [Fact]
    public async Task TheSealedPresentationAlone_IsRead()
    {
        var parsed = await Parser().ParseDetailedAsync(Form());

        Assert.Equal(SampleSdJwt, Assert.Single(parsed.Credentials).RawValue);
        Assert.True(parsed.Encrypted);
    }

    [Theory]
    [InlineData("vp_token", """{"pid":["x"]}""", false)]
    [InlineData("vp_token", """{"pid":["x"]}""", true)]
    [InlineData("error", "access_denied", false)]
    [InlineData("error", "access_denied", true)]
    public async Task ACleartextAnswerBesideIt_IsRefused_WithThePair(string name, string value, bool readErrorResponses)
    {
        var e = await Assert.ThrowsAsync<WalletResponseException>(
            () => Parser(readErrorResponses).ParseDetailedAsync(Form((name, value))));

        Assert.Contains($"beside a cleartext '{name}'", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("vp_token", """{"pid":["x"]}""")]
    [InlineData("error", "access_denied")]
    public async Task ThePair_IsRefused_BeforeAnyKeyIsLookedUp(string name, string value)
    {
        var lookups = 0;
        var parser = new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKeyResolver = _ => { lookups++; return new ECDsaSecurityKey(_verifierEc); },
            ReadErrorResponses = true,
        });

        await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDetailedAsync(Form((name, value))));

        Assert.Equal(0, lookups);
    }

    [Fact]
    public async Task AStateBesideIt_IsIgnored_AndTheSealedStateIsUsed()
    {
        var parsed = await Parser().ParseDetailedAsync(Form(("state", "cleartext-state")));

        Assert.Equal("sealed-state", parsed.State);
        Assert.Single(parsed.Credentials);
    }
}
