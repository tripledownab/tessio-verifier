using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Decrypts ECDH-ES key-agreement JWEs (the encryption HAIP wallets use for
/// <c>direct_post.jwt</c> responses).
/// </summary>
/// <remarks>
/// Microsoft.IdentityModel 8.x implements ECDH-ES only on the <em>encryption</em> side; its JWE
/// decryption path has no <c>epk</c> handling at all, so <c>ValidateTokenAsync</c> can never decrypt
/// these tokens. This class supplies the missing receive side by composing the library's own public
/// primitives: <see cref="EcdhKeyExchangeProvider"/> for the ECDH key derivation and the library's
/// key-wrap provider for CEK unwrap, mirroring its sender implementation step for step.
/// <para>
/// Content decryption goes through the library for AES-CBC-HMAC but through
/// <see cref="System.Security.Cryptography.AesGcm"/> for AES-GCM, because the library's AES-GCM is
/// Windows-only (it P/Invokes <c>BCrypt.dll</c>). See <see cref="DecryptAesGcm"/>. Both are standard
/// platform primitives; no cipher is implemented here.
/// </para>
/// </remarks>
// SPEC: RFC 7518 §4.6 (ECDH-ES with Concat KDF); JWE compact serialization per RFC 7516 §3.1.
internal static class EcdhEsJweDecryptor
{
    // SPEC: RFC 7518 §4.6 — each ECDH-ES+AxxxKW algorithm wraps the CEK with the matching AES key wrap.
    private static readonly Dictionary<string, string> KeyWrapAlgorithmByAlg = new(StringComparer.Ordinal)
    {
        [SecurityAlgorithms.EcdhEsA128kw] = SecurityAlgorithms.Aes128KW,
        [SecurityAlgorithms.EcdhEsA192kw] = SecurityAlgorithms.Aes192KW,
        [SecurityAlgorithms.EcdhEsA256kw] = SecurityAlgorithms.Aes256KW,
    };

    // SPEC: RFC 7518 §4.6 — "ECDH-ES" is Direct Key Agreement: the derived key IS the content
    // encryption key and the JWE Encrypted Key segment is empty. HAIP 1.0 §5 requires verifiers to
    // advertise exactly this, so supporting only the +AxxxKW variants would mean advertising a key
    // agreement we cannot complete.
    public static bool CanHandle(JsonWebToken jwe) =>
        KeyWrapAlgorithmByAlg.ContainsKey(jwe.Alg) || jwe.Alg == SecurityAlgorithms.EcdhEs;

    /// <summary>Decrypts the JWE and returns the plaintext payload (UTF-8 JSON).</summary>
    public static string Decrypt(JsonWebToken jwe, SecurityKey decryptionKey)
    {
        // PrivateKeyStatus can report Unknown for ECDsa keys even when the private key is present,
        // so only a definite DoesNotExist is rejected here; a truly public-only key fails in the KDF.
        if (decryptionKey is not ECDsaSecurityKey privateKey || privateKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
        {
            throw new WalletResponseException(
                "ECDH-ES response decryption requires the ResponseDecryptionKey to be an ECDsaSecurityKey with a private key.");
        }

        var segments = jwe.EncodedToken.Split('.');
        if (segments.Length != 5)
        {
            throw new WalletResponseException("The encrypted response is not a five-segment JWE compact serialization.");
        }

        if (!jwe.TryGetHeaderValue<JsonElement>(JwtHeaderParameterNames.Epk, out var epkElement))
        {
            throw new WalletResponseException("The ECDH-ES response carries no epk header; the sender's ephemeral key is required.");
        }

        JsonWebKey ephemeralPublicKey;
        try
        {
            ephemeralPublicKey = new JsonWebKey(epkElement.GetRawText());
        }
        catch (ArgumentException)
        {
            throw new WalletResponseException("The ECDH-ES epk header is not a valid JWK.");
        }

        jwe.TryGetHeaderValue<string>(JwtHeaderParameterNames.Apu, out var apu);
        jwe.TryGetHeaderValue<string>(JwtHeaderParameterNames.Apv, out var apv);

        try
        {
            // Mirror of the library's sender path (JwtTokenUtilities.GetSecurityKey): derive the
            // key-wrap key via ECDH + Concat KDF, then unwrap the CEK, then decrypt the content.
            var ecdh = new EcdhKeyExchangeProvider(privateKey, ephemeralPublicKey, jwe.Alg, jwe.Enc);

            // Direct Key Agreement derives the CEK itself and carries no encrypted key; the +AxxxKW
            // variants derive a key-wrapping key and unwrap the CEK from segment 1.
            byte[] cek;
            if (jwe.Alg == SecurityAlgorithms.EcdhEs)
            {
                if (segments[1].Length != 0)
                {
                    throw new WalletResponseException(
                        "An ECDH-ES (Direct Key Agreement) response must carry an empty JWE Encrypted Key segment.");
                }

                ecdh.KeyDataLen = ContentEncryptionKeyBits(jwe.Enc);
                cek = ((SymmetricSecurityKey)ecdh.GenerateKdf(apu, apv)).Key;
            }
            else
            {
                var kdfKey = ecdh.GenerateKdf(apu, apv);
                var keyWrap = privateKey.CryptoProviderFactory.CreateKeyWrapProvider(kdfKey, KeyWrapAlgorithmByAlg[jwe.Alg]);
                try
                {
                    cek = keyWrap.UnwrapKey(Base64UrlEncoder.DecodeBytes(segments[1]));
                }
                finally
                {
                    privateKey.CryptoProviderFactory.ReleaseKeyWrapProvider(keyWrap);
                }
            }

            // SPEC: RFC 7516 §5.2 — the additional authenticated data is the ASCII of the encoded header.
            var aad = Encoding.ASCII.GetBytes(segments[0]);
            var iv = Base64UrlEncoder.DecodeBytes(segments[2]);
            var ciphertext = Base64UrlEncoder.DecodeBytes(segments[3]);
            var tag = Base64UrlEncoder.DecodeBytes(segments[4]);

            var plaintext = AesGcmContentEncryption.Contains(jwe.Enc)
                ? DecryptAesGcm(cek, iv, ciphertext, tag, aad)
                : DecryptWithIdentityModel(privateKey, cek, jwe.Enc, iv, ciphertext, tag, aad);

            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException or FormatException
                                      or NotSupportedException or CryptographicException)
        {
            throw new WalletResponseException("The ECDH-ES response could not be decrypted with the configured key.", e);
        }
    }

    /// <summary>
    /// CEK size in bits for Direct Key Agreement, which is fixed by the content encryption.
    /// </summary>
    // SPEC: RFC 7518 §5.1 — A128GCM takes a 128-bit key, A256GCM 256, and the AES-CBC-HMAC family
    // takes double its name (A128CBC-HS256 is a 256-bit key: 128 for HMAC, 128 for AES).
    private static int ContentEncryptionKeyBits(string enc) => enc switch
    {
        SecurityAlgorithms.Aes128Gcm => 128,
        "A192GCM" => 192,
        SecurityAlgorithms.Aes256Gcm => 256,
        SecurityAlgorithms.Aes128CbcHmacSha256 => 256,
        SecurityAlgorithms.Aes192CbcHmacSha384 => 384,
        SecurityAlgorithms.Aes256CbcHmacSha512 => 512,
        _ => throw new WalletResponseException($"Unsupported content encryption '{enc}' for ECDH-ES direct key agreement."),
    };

    // SPEC: RFC 7518 §5.3 — AES-GCM content encryption, 96-bit IV and 128-bit authentication tag.
    private static readonly HashSet<string> AesGcmContentEncryption =
        new(StringComparer.Ordinal) { SecurityAlgorithms.Aes128Gcm, "A192GCM", SecurityAlgorithms.Aes256Gcm };

    /// <summary>
    /// AES-GCM content decryption, done with the platform primitive rather than Microsoft.IdentityModel.
    /// </summary>
    /// <remarks>
    /// The library's AES-GCM P/Invokes <c>BCrypt.dll</c>, so it exists only on Windows: on Linux and
    /// macOS its static initializer throws <see cref="DllNotFoundException"/>. HAIP 1.0 §5 requires
    /// verifiers to accept A128GCM and A256GCM and our hosts are Linux containers, so relying on the
    /// library would mean advertising support we could not honour.
    /// <see cref="System.Security.Cryptography.AesGcm"/> is cross-platform and does the same job.
    /// </remarks>
    private static byte[] DecryptAesGcm(byte[] cek, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad)
    {
        var plaintext = new byte[ciphertext.Length];
        using var gcm = new System.Security.Cryptography.AesGcm(cek, tag.Length);
        gcm.Decrypt(iv, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    private static byte[] DecryptWithIdentityModel(
        ECDsaSecurityKey privateKey, byte[] cek, string enc, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad)
    {
        var contentKey = new SymmetricSecurityKey(cek);
        var aead = privateKey.CryptoProviderFactory.CreateAuthenticatedEncryptionProvider(contentKey, enc);
        return aead.Decrypt(ciphertext, aad, iv, tag);
    }
}
