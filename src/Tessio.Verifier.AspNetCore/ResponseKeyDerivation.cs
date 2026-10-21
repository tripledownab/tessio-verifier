// What belongs here: turning a master secret and a per-request salt into a response-encryption key, and
// the limits on both inputs. Where the salt is kept is ResponseEncryptionKeyStore's concern.
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Derives a P-256 response-encryption key from a master secret and a salt, so any instance holding the
/// master can recreate the key for a request from its salt alone, and no private key is stored anywhere.
/// </summary>
/// <remarks>
/// HKDF-SHA256 (RFC 5869) expands the master and salt into 48 bytes, which are reduced to a private scalar
/// d in [1, n - 1] by the step NIST SP 800-56A Rev. 3 section 5.6.1.2.1 uses for key-establishment key
/// pairs: d = (c mod (n - 1)) + 1. That section draws c from a random bit generator; here it comes from
/// HKDF, so this follows its reduction and is not its approved key-pair generation. The
/// derivation is fixed by its info string: changing anything here changes every key, so a new derivation
/// takes a new info string rather than editing this one.
/// </remarks>
public static class ResponseKeyDerivation
{
    /// <summary>The shortest master accepted: as long as the private scalar it derives.</summary>
    public const int MinimumMasterLength = 32;

    /// <summary>The shortest salt accepted, enough that two random salts colliding is negligible.</summary>
    public const int MinimumSaltLength = 16;

    // SP 800-56A Rev. 3 section 5.6.1.2.1 asks for len(n) + 64 bits, 320 for P-256, so that the bias of the
    // reduction below is negligible; FIPS 186-5 Table A.2 recommends 352 for the same reduction. 48 bytes
    // is 384 bits.
    private const int OkmLength = 48;

    private const int ScalarLength = 32;

    // The order n of P-256; a test compares it with the platform's own curve parameters. The leading zero
    // keeps BigInteger positive.
    internal static readonly BigInteger Order = BigInteger.Parse(
        "00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static ReadOnlySpan<byte> Info => "tessio-verifier response-encryption-key v1"u8;

    /// <summary>
    /// The P-256 key that <paramref name="master"/> and <paramref name="salt"/> derive. The caller owns and
    /// disposes it.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// The master is shorter than <see cref="MinimumMasterLength"/> bytes or the salt shorter than
    /// <see cref="MinimumSaltLength"/>.
    /// </exception>
    public static ECDsa Derive(ReadOnlySpan<byte> master, ReadOnlySpan<byte> salt)
    {
        if (master.Length < MinimumMasterLength)
        {
            throw new ArgumentException(
                $"The response-key master must be at least {MinimumMasterLength} bytes.", nameof(master));
        }

        if (salt.Length < MinimumSaltLength)
        {
            throw new ArgumentException(
                $"A response-key salt must be at least {MinimumSaltLength} bytes.", nameof(salt));
        }

        Span<byte> okm = stackalloc byte[OkmLength];
        var d = new byte[ScalarLength];
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, master, okm, salt, Info);
            var scalar = (new BigInteger(okm, isUnsigned: true, isBigEndian: true) % (Order - 1)) + 1;
            var length = scalar.GetByteCount(isUnsigned: true);
            scalar.TryWriteBytes(d.AsSpan(ScalarLength - length), out _, isUnsigned: true, isBigEndian: true);

            // Only d: the platform computes the public point, so no curve arithmetic is written here.
            return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = d });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(okm);
            CryptographicOperations.ZeroMemory(d);
        }
    }
}
