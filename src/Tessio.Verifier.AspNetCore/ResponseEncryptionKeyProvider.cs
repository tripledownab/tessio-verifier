using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Holds the verifier's response-encryption key pair: an ephemeral EC P-256 key generated at startup.
/// The public half is advertised to wallets via <c>client_metadata.jwks</c>; the private half decrypts
/// <c>direct_post.jwt</c> (ECDH-ES) responses. Multi-instance deployments should replace this with a
/// shared, persisted key.
/// </summary>
internal sealed class ResponseEncryptionKeyProvider : IDisposable
{
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public ResponseEncryptionKeyProvider()
    {
        KeyId = Guid.NewGuid().ToString("N");
        DecryptionKey = new ECDsaSecurityKey(_ecdsa) { KeyId = KeyId };

        var p = _ecdsa.ExportParameters(false);
        PublicJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            ["kid"] = KeyId,
            ["use"] = "enc",
            ["alg"] = SecurityAlgorithms.EcdhEsA256kw,
        };
    }

    public string KeyId { get; }

    /// <summary>Private key for decrypting wallet responses.</summary>
    public ECDsaSecurityKey DecryptionKey { get; }

    /// <summary>Public JWK for <c>client_metadata.jwks</c>. Clone before embedding in a JsonObject.</summary>
    public JsonObject PublicJwk { get; }

    public void Dispose() => _ecdsa.Dispose();
}
