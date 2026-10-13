// What belongs in this file: encrypting a chosen plaintext to a verifier's response encryption key the
// way a wallet does, for tests that need a response no wallet would send. Linked into the AspNetCore
// tests as well, rather than copied.
using System.Security.Cryptography;
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
}
