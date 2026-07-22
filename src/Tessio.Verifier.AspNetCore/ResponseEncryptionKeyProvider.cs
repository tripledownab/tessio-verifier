using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Holds the verifier's response-encryption key pair. The public half is advertised to wallets via
/// <c>client_metadata.jwks</c>; the private half decrypts <c>direct_post.jwt</c> (ECDH-ES) responses.
/// The default registration generates an ephemeral EC P-256 key at startup, which is fine for a
/// single process. Multi-instance deployments must register an instance built from a shared,
/// persisted key so every instance can decrypt responses encrypted against the advertised JWK.
/// </summary>
public sealed class ResponseEncryptionKeyProvider : IDisposable
{
    private readonly ECDsa _ecdsa;

    /// <summary>Creates a provider with a fresh ephemeral P-256 key (the single-process default).</summary>
    public ResponseEncryptionKeyProvider() : this(ECDsa.Create(ECCurve.NamedCurves.nistP256))
    {
    }

    /// <summary>
    /// Creates a provider from a caller-supplied EC P-256 private key, e.g. one loaded from a key
    /// store so all instances share it. The provider takes ownership and disposes the key.
    /// </summary>
    public ResponseEncryptionKeyProvider(ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.KeySize != 256)
        {
            throw new ArgumentException(
                "The response-encryption key must be EC P-256 (the curve advertised to wallets).",
                nameof(privateKey));
        }

        _ecdsa = privateKey;

        var p = _ecdsa.ExportParameters(false);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);

        // SPEC: RFC 7638 — the kid is the JWK thumbprint, so every instance holding the same key
        // advertises the same identifier.
        KeyId = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(
            $$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""")));

        DecryptionKey = new ECDsaSecurityKey(_ecdsa) { KeyId = KeyId };
        PublicJwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = x,
            ["y"] = y,
            ["kid"] = KeyId,
            ["use"] = "enc",
            ["alg"] = SecurityAlgorithms.EcdhEsA256kw,
        };
    }

    /// <summary>Key identifier (RFC 7638 JWK thumbprint).</summary>
    public string KeyId { get; }

    /// <summary>The raw thumbprint bytes, as bound into the mdoc session transcript.</summary>
    public byte[] ThumbprintBytes => Base64UrlEncoder.DecodeBytes(KeyId);

    /// <summary>Private key for decrypting wallet responses.</summary>
    public ECDsaSecurityKey DecryptionKey { get; }

    /// <summary>Public JWK for <c>client_metadata.jwks</c>. Clone before embedding in a JsonObject.</summary>
    public JsonObject PublicJwk { get; }

    /// <inheritdoc />
    public void Dispose() => _ecdsa.Dispose();
}
