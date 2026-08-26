using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Hybrid Public Key Encryption (RFC 9180), reduced to the one configuration the encrypted mdoc
/// response uses: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, one message per
/// encapsulation. The verifier only ever decrypts in production, so <see cref="Open"/> is the
/// production path; <see cref="Seal"/> exists so tests and fixtures can produce what a wallet
/// produces, checked against RFC 9180's own Appendix A.3 vectors.
/// </summary>
// SPEC: RFC 9180 §4.1 (DHKEM encap/decap), §5.1 (key schedule), §5.2 (nonce = base_nonce XOR seq).
internal static class Hpke
{
    // RFC 9180 §7: kem_id 0x0010 is DHKEM(P-256, HKDF-SHA256), kdf_id 0x0001 is HKDF-SHA256,
    // aead_id 0x0001 is AES-128-GCM. The ids are mixed into every HKDF label, so a wrong id
    // derives wrong keys and fails the AEAD tag check rather than producing a wrong plaintext.
    private static readonly byte[] KemSuiteId = [.. "KEM"u8, 0x00, 0x10];
    private static readonly byte[] HpkeSuiteId = [.. "HPKE"u8, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01];

    // RFC 9180 §5: mode_base = 0x00, used by §5.1 as the first byte of key_schedule_context.
    private const byte ModeBase = 0x00;

    // RFC 9180 §7.1 and §7.3 for this suite: Npk = 65 (uncompressed SEC 1 point),
    // Nsecret = 32, Nk = 16 (AES-128 key), Nn = 12 (GCM nonce), and a full 16-byte GCM tag.
    private const int PublicKeyLength = 65;
    private const int SharedSecretLength = 32;
    private const int KeyLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    /// <summary>
    /// Encrypts one message to <paramref name="recipientPublicKey"/>. The ephemeral key is a
    /// parameter rather than generated here so the RFC 9180 vectors, which fix it, stay testable.
    /// Returns the encapsulated key and the ciphertext with the GCM tag appended.
    /// </summary>
    public static (byte[] Enc, byte[] Ciphertext) Seal(
        ECDiffieHellman ephemeralKey,
        ECDiffieHellman recipientPublicKey,
        byte[] info,
        byte[] aad,
        byte[] plaintext)
    {
        var enc = ExportUncompressedPoint(ephemeralKey);
        var recipientPoint = ExportUncompressedPoint(recipientPublicKey);
        using var recipientPublic = recipientPublicKey.PublicKey;
        var dh = ephemeralKey.DeriveRawSecretAgreement(recipientPublic);
        var (key, nonce) = DeriveKeyAndNonce(dh, enc, recipientPoint, info);

        var ciphertext = new byte[plaintext.Length + TagLength];
        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(
            nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length),
            ciphertext.AsSpan(plaintext.Length), aad);
        return (enc, ciphertext);
    }

    /// <summary>
    /// Decrypts one message sealed to <paramref name="recipientKey"/>. Throws
    /// <see cref="CryptographicException"/> when the encapsulated key is malformed or when the
    /// key material, <paramref name="info"/> or <paramref name="aad"/> do not match the sender's.
    /// </summary>
    public static byte[] Open(
        ECDiffieHellman recipientKey,
        byte[] enc,
        byte[] info,
        byte[] aad,
        byte[] ciphertext)
    {
        if (ciphertext.Length < TagLength)
        {
            throw new CryptographicException($"The ciphertext is shorter than the {TagLength}-byte GCM tag.");
        }

        using var ephemeral = ImportUncompressedPoint(enc);
        using var ephemeralPublic = ephemeral.PublicKey;
        var dh = recipientKey.DeriveRawSecretAgreement(ephemeralPublic);
        var (key, nonce) = DeriveKeyAndNonce(dh, enc, ExportUncompressedPoint(recipientKey), info);

        var plaintext = new byte[ciphertext.Length - TagLength];
        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(
            nonce, ciphertext.AsSpan(0, plaintext.Length),
            ciphertext.AsSpan(plaintext.Length), plaintext, aad);
        return plaintext;
    }

    // SPEC: RFC 9180 §4.1 ExtractAndExpand, then §5.1 KeySchedule in base mode: psk and psk_id
    // are empty, key_schedule_context = mode || psk_id_hash || info_hash. This API encrypts one
    // message per encapsulation, so the only sequence number is zero and §5.2's
    // base_nonce XOR seq leaves base_nonce unchanged; no counter exists here on purpose.
    private static (byte[] Key, byte[] Nonce) DeriveKeyAndNonce(
        byte[] dh, byte[] enc, byte[] recipientPoint, byte[] info)
    {
        var eaePrk = LabeledExtract(KemSuiteId, salt: [], "eae_prk"u8, dh);
        byte[] kemContext = [.. enc, .. recipientPoint];
        var sharedSecret = LabeledExpand(KemSuiteId, eaePrk, "shared_secret"u8, kemContext, SharedSecretLength);

        var pskIdHash = LabeledExtract(HpkeSuiteId, salt: [], "psk_id_hash"u8, []);
        var infoHash = LabeledExtract(HpkeSuiteId, salt: [], "info_hash"u8, info);
        byte[] context = [ModeBase, .. pskIdHash, .. infoHash];

        var secret = LabeledExtract(HpkeSuiteId, salt: sharedSecret, "secret"u8, []);
        var key = LabeledExpand(HpkeSuiteId, secret, "key"u8, context, KeyLength);
        var nonce = LabeledExpand(HpkeSuiteId, secret, "base_nonce"u8, context, NonceLength);
        return (key, nonce);
    }

    // SPEC: RFC 9180 §4: LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm).
    private static byte[] LabeledExtract(
        byte[] suiteId, byte[] salt, ReadOnlySpan<byte> label, byte[] ikm)
    {
        byte[] labeledIkm = [.. "HPKE-v1"u8, .. suiteId, .. label, .. ikm];
        return HKDF.Extract(HashAlgorithmName.SHA256, labeledIkm, salt);
    }

    // SPEC: RFC 9180 §4: LabeledExpand(prk, label, info, L) prefixes I2OSP(L, 2) to the labeled info.
    private static byte[] LabeledExpand(
        byte[] suiteId, byte[] prk, ReadOnlySpan<byte> label, byte[] info, int length)
    {
        byte[] labeledInfo = [(byte)(length >> 8), (byte)length, .. "HPKE-v1"u8, .. suiteId, .. label, .. info];
        return HKDF.Expand(HashAlgorithmName.SHA256, prk, length, labeledInfo);
    }

    // SPEC: RFC 9180 §7.1.1: P-256 public keys travel as the uncompressed SEC 1 point 0x04 || X || Y.
    private static byte[] ExportUncompressedPoint(ECDiffieHellman key)
    {
        var q = key.ExportParameters(includePrivateParameters: false).Q;
        if (q.X is not { Length: 32 } x || q.Y is not { Length: 32 } y)
        {
            throw new CryptographicException("The key does not have the 32-byte coordinates of a P-256 point.");
        }

        return [0x04, .. x, .. y];
    }

    private static ECDiffieHellman ImportUncompressedPoint(byte[] enc)
    {
        if (enc.Length != PublicKeyLength || enc[0] != 0x04)
        {
            throw new CryptographicException(
                $"The encapsulated key is not an uncompressed P-256 point ({PublicKeyLength} bytes starting 0x04).");
        }

        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = enc[1..33], Y = enc[33..] },
        });
    }
}
