using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Encrypts a JWE with ECDH-ES Direct Key Agreement and A256GCM, the shape a HAIP wallet uses for a
/// <c>direct_post.jwt</c> response.
/// </summary>
/// <remarks>
/// The sender side of <see cref="EcdhEsJweDecryptor"/>, kept next to it and shared by everything that
/// plays the wallet: the Mock-mode background wallet and the test helpers both call this rather than
/// each assembling the JWE. A wallet stand-in that encrypts differently from what we advertise, or
/// differently from what our own decryptor expects, tests nothing that matters, which is the mistake
/// that let a content encryption no real wallet would choose sit green for months.
/// <para>
/// Assembled by hand rather than via <c>JsonWebTokenHandler</c> because that library cannot encrypt
/// with AES-GCM at all (it answers <c>IDX10715</c>), and its AES-GCM is Windows-only regardless. Both
/// <c>alg</c> and <c>enc</c> mirror exactly what <see cref="ClientMetadata"/> advertises under HAIP
/// 1.0 §5.
/// </para>
/// </remarks>
// SPEC: RFC 7516 §3.1 (compact serialization), RFC 7518 §4.6 (ECDH-ES), §5.3 (AES-GCM).
public static class EcdhEsJweEncryptor
{
    /// <summary>
    /// Encrypts <paramref name="plaintextJson"/> to <paramref name="recipientJwkJson"/>, a P-256 public
    /// JWK carrying a <c>kid</c>. Returns the JWE compact serialization.
    /// </summary>
    public static string Encrypt(string plaintextJson, string recipientJwkJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintextJson);
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientJwkJson);

        var recipientJwk = new JsonWebKey(recipientJwkJson);

        using var ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ep = ephemeral.ExportParameters(false);

        // SPEC: RFC 7518 §4.6 — epk (the sender's ephemeral public key) is required for the receiver's
        // key agreement, and the encoded header is the AAD, so it has to be built before encrypting.
        // The kid tells the receiver which of its ephemeral keys we encrypted to, since the session
        // correlation handle (state) is inside the payload it cannot yet read.
        var header = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["alg"] = SecurityAlgorithms.EcdhEs,
            ["enc"] = SecurityAlgorithms.Aes256Gcm,
            ["epk"] = new Dictionary<string, string>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = Base64UrlEncoder.Encode(ep.Q.X!),
                ["y"] = Base64UrlEncoder.Encode(ep.Q.Y!),
            },
            ["kid"] = recipientJwk.Kid,
        });

        // Direct Key Agreement: the derived key IS the content encryption key, so there is no wrapped
        // key and the JWE Encrypted Key segment stays empty.
        var ecdh = new EcdhKeyExchangeProvider(
            new ECDsaSecurityKey(ephemeral), recipientJwk, SecurityAlgorithms.EcdhEs, SecurityAlgorithms.Aes256Gcm)
        {
            KeyDataLen = 256,
        };
        var cek = ((SymmetricSecurityKey)ecdh.GenerateKdf()).Key;

        // SPEC: RFC 7518 §5.3 — AES-GCM uses a 96-bit IV and a 128-bit authentication tag.
        var iv = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(plaintextJson);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        var encodedHeader = Base64UrlEncoder.Encode(header);

        using (var gcm = new AesGcm(cek, tag.Length))
        {
            gcm.Encrypt(iv, plaintext, ciphertext, tag, Encoding.ASCII.GetBytes(encodedHeader));
        }

        return string.Join('.', [
            encodedHeader,
            string.Empty, // Direct Key Agreement: no JWE Encrypted Key (RFC 7518 §4.6).
            Base64UrlEncoder.Encode(iv),
            Base64UrlEncoder.Encode(ciphertext),
            Base64UrlEncoder.Encode(tag),
        ]);
    }
}
