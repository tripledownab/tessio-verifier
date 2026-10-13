// What belongs in this file: encrypting a chosen plaintext to a verifier's response encryption key the
// way a wallet does, for tests that need a response no wallet would send. Linked into the AspNetCore
// tests as well, rather than copied.
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

internal static class WalletEncryption
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> exactly as given to <paramref name="verifierPublicJwk"/> with
    /// ECDH-ES+A256KW and A128CBC-HS256, echoing the key's kid when it has one.
    /// </summary>
    public static string EcdhEsTo(JsonWebKey verifierPublicJwk, string plaintext)
    {
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ep = ephemeral.ExportParameters(false);

        // IdentityModel's sender does not write the epk header itself, and it serialises the header from
        // plain dictionaries, not from a JsonWebKey.
        var header = new Dictionary<string, object>
        {
            ["epk"] = new Dictionary<string, string>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = Base64UrlEncoder.Encode(ep.Q.X!),
                ["y"] = Base64UrlEncoder.Encode(ep.Q.Y!),
            },
        };
        if (!string.IsNullOrEmpty(verifierPublicJwk.Kid))
        {
            header["kid"] = verifierPublicJwk.Kid;
        }

        return new JsonWebTokenHandler().EncryptToken(plaintext, new EncryptingCredentials(
            new ECDsaSecurityKey(ephemeral), SecurityAlgorithms.EcdhEsA256kw, SecurityAlgorithms.Aes128CbcHmacSha256)
        {
            KeyExchangePublicKey = verifierPublicJwk,
        }, header);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> to <paramref name="verifierPublicJwk"/> with ECDH-ES (Direct Key
    /// Agreement) and A128GCM under a header written as raw text, so a test can send what no serializer
    /// would: a duplicate member, say. <paramref name="header"/> is given the ephemeral key's JWK and returns
    /// the header JSON, which is also the AAD, so the response decrypts whatever the header says.
    /// </summary>
    public static string EcdhEsUnderHeader(JsonWebKey verifierPublicJwk, string plaintext, Func<string, string> header)
    {
        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ep = ephemeral.ExportParameters(false);
        var epk = $"{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{Base64UrlEncoder.Encode(ep.Q.X!)}\",\"y\":\"{Base64UrlEncoder.Encode(ep.Q.Y!)}\"}}";
        var encodedHeader = Base64UrlEncoder.Encode(header(epk));

        var agreement = new EcdhKeyExchangeProvider(
            new ECDsaSecurityKey(ephemeral), verifierPublicJwk, SecurityAlgorithms.EcdhEs, SecurityAlgorithms.Aes128Gcm)
        {
            KeyDataLen = 128,
        };
        var cek = ((SymmetricSecurityKey)agreement.GenerateKdf()).Key;

        var iv = RandomNumberGenerator.GetBytes(12);
        var clear = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[clear.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(cek, tag.Length);
        gcm.Encrypt(iv, clear, ciphertext, tag, Encoding.ASCII.GetBytes(encodedHeader));
        return string.Join('.', encodedHeader, string.Empty, Base64UrlEncoder.Encode(iv),
            Base64UrlEncoder.Encode(ciphertext), Base64UrlEncoder.Encode(tag));
    }
}
