using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// What belongs here: how the parser answers a direct_post.jwt response whose JWE header is crafted rather
/// than produced by a wallet. Anyone can post to the callback, so every header field is untrusted: every
/// combination must be refused as a malformed response, never escape as some other exception.
/// </summary>
/// <remarks>
/// A cross product rather than one case per field, because the fields are read in sequence and a value that
/// is harmless in one position can reach a different read when another field changes.
/// </remarks>
public sealed class CraftedJweHeaderTests
{
    private static readonly string[] AlgAndEnc =
    [
        "\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\"",
        "\"alg\":\"ECDH-ES\",\"enc\":\"A128CBC-HS256\"",
        "\"alg\":\"ECDH-ES\",\"enc\":\"unknown\"",
        "\"alg\":\"ECDH-ES\",\"enc\":5",
        "\"alg\":\"ECDH-ES\"",
        "\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A128GCM\"",
        "\"alg\":\"ECDH-ES+A128KW\",\"enc\":\"unknown\"",
        "\"alg\":\"dir\",\"enc\":\"A128GCM\"",
        "\"alg\":\"RSA-OAEP\",\"enc\":\"A128GCM\"",
        "\"alg\":5,\"enc\":\"A128GCM\"",
        "\"alg\":null,\"enc\":\"A128GCM\"",
        "\"enc\":\"A128GCM\"",
    ];

    private static readonly string[] Kids = ["", ",\"kid\":\"k\"", ",\"kid\":5", ",\"kid\":{}", ",\"kid\":null"];

    private static readonly string[] Bodies =
    [
        "AAAA.AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
        ".AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
        "!!.!!.!!.!!",
        "...",
    ];

    private static IEnumerable<string> Epks()
    {
        static string B(byte[] b) => Base64UrlEncoder.Encode(b);
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var onCurve = p256.ExportParameters(false).Q;
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var otherCurve = p384.ExportParameters(false).Q;
        var valid = $"{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{B(onCurve.X!)}\",\"y\":\"{B(onCurve.Y!)}\"}}";

        return
        [
            "",
            ",\"epk\":null",
            ",\"epk\":\"a string\"",
            ",\"epk\":5",
            ",\"epk\":[]",
            ",\"epk\":{}",
            ",\"epk\":{\"kty\":\"EC\"}",
            $",\"epk\":{{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"{B(otherCurve.X!)}\",\"y\":\"{B(otherCurve.Y!)}\"}}",
            ",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}",
            ",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"!!\",\"y\":\"!!\"}",
            ",\"epk\":{\"kty\":\"EC\",\"crv\":5,\"x\":5,\"y\":5}",
            ",\"epk\":{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}",
            ",\"epk\":{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
            ",\"epk\":{\"kty\":\"oct\",\"k\":\"AAAA\"}",
            $",\"epk\":{valid}",
            $",\"epk\":{valid},\"apu\":5,\"apv\":{{}}",
        ];
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EveryCraftedHeader_IsRefusedAsAMalformedResponse(bool keyByKid)
    {
        using var verifier = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(verifier);
        var parser = new WalletResponseParser(keyByKid
            ? new WalletResponseParserOptions { ResponseDecryptionKeyResolver = _ => key }
            : new WalletResponseParserOptions { ResponseDecryptionKey = key });

        var escaped = new List<string>();
        foreach (var header in from algEnc in AlgAndEnc from epk in Epks() from kid in Kids select "{" + algEnc + epk + kid + "}")
        foreach (var body in Bodies)
        {
            var e = await Record.ExceptionAsync(() => parser.ParseDetailedAsync(new WalletResponseData
            {
                ContentType = "application/x-www-form-urlencoded",
                Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["response"] = [$"{Base64UrlEncoder.Encode(header)}.{body}"],
                },
                Body = ReadOnlyMemory<byte>.Empty,
            }));
            if (e is not WalletResponseException)
            {
                escaped.Add($"{header} .{body}: {e?.GetType().Name ?? "no exception"}");
            }
        }

        Assert.True(escaped.Count == 0, string.Join(Environment.NewLine, escaped.Take(10)));
    }
}
