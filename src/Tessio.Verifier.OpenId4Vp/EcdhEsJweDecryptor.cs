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
/// primitives — <see cref="EcdhKeyExchangeProvider"/> for the ECDH key derivation, the library's
/// key-wrap provider for CEK unwrap, and its authenticated-encryption provider for the content —
/// mirroring the library's sender implementation step for step. No custom cryptography.
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

    public static bool CanHandle(JsonWebToken jwe) => KeyWrapAlgorithmByAlg.ContainsKey(jwe.Alg);

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
            var kdfKey = ecdh.GenerateKdf(apu, apv);
            var keyWrap = privateKey.CryptoProviderFactory.CreateKeyWrapProvider(kdfKey, KeyWrapAlgorithmByAlg[jwe.Alg]);
            byte[] cek;
            try
            {
                cek = keyWrap.UnwrapKey(Base64UrlEncoder.DecodeBytes(segments[1]));
            }
            finally
            {
                privateKey.CryptoProviderFactory.ReleaseKeyWrapProvider(keyWrap);
            }

            var contentKey = new SymmetricSecurityKey(cek);
            var aead = privateKey.CryptoProviderFactory.CreateAuthenticatedEncryptionProvider(contentKey, jwe.Enc);

            // SPEC: RFC 7516 §5.2 — the additional authenticated data is the ASCII of the encoded header.
            var plaintext = aead.Decrypt(
                Base64UrlEncoder.DecodeBytes(segments[3]),
                Encoding.ASCII.GetBytes(segments[0]),
                Base64UrlEncoder.DecodeBytes(segments[2]),
                Base64UrlEncoder.DecodeBytes(segments[4]));

            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException or FormatException or NotSupportedException)
        {
            throw new WalletResponseException("The ECDH-ES response could not be decrypted with the configured key.", e);
        }
    }
}
