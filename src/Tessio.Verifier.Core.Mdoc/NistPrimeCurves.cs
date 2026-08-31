using System.Numerics;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The domain parameters of the NIST prime curves this verifier accepts, and the public-key
/// validation every untrusted point passes before a platform key import sees it. Parameters and
/// the check belong together in one file so neither can change without the other.
/// </summary>
/// <remarks>
/// Every platform rejects an off-curve point, but not with one exception type: Windows CNG reports
/// <see cref="PlatformNotSupportedException"/> wrapping a <see cref="CryptographicException"/>,
/// while Linux and macOS throw <see cref="CryptographicException"/> directly. A caller that catches
/// the documented type would therefore see an unhandled exception on Windows alone. Checking the
/// curve equation here makes an attacker-supplied point produce the same answer on every OS, and
/// leaves a <see cref="PlatformNotSupportedException"/> from the import to mean what it says: the
/// platform does not support the curve.
/// </remarks>
// SPEC: SEC 1 v2.0 §3.2.2.1 (public key validation), over the curves of NIST SP 800-186 §4.2.1.
internal static class NistPrimeCurves
{
    // NIST SP 800-186 §4.2.1, big-endian hex as the standard prints it. Each of these curves has
    // a = p - 3, so the curve equation needs only p and b. Each has cofactor 1, so a point on the
    // curve is already in the prime-order subgroup and no further check applies.
    private static readonly Curve P256 = new(
        "P-256",
        "1.2.840.10045.3.1.7",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

    private static readonly Curve P384 = new(
        "P-384",
        "1.3.132.0.34",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            + "FFFFFFFF0000000000000000FFFFFFFF",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            + "C656398D8A2ED19D2A85C8EDD3EC2AEF");

    private static readonly Curve P521 = new(
        "P-521",
        "1.3.132.0.35",
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            + "FFFF",
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            + "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
            + "3F00");

    private static readonly Curve[] All = [P256, P384, P521];

    /// <summary>
    /// Returns the public-key parameters for <paramref name="x"/> and <paramref name="y"/> on
    /// <paramref name="curve"/>. Throws <see cref="CryptographicException"/> when the coordinates
    /// are the wrong length, are not field elements, or are not a point on the curve.
    /// </summary>
    public static ECParameters PublicKeyParameters(ECCurve curve, byte[] x, byte[] y)
    {
        var c = Find(curve);
        if (x.Length != c.CoordinateLength || y.Length != c.CoordinateLength)
        {
            throw new CryptographicException(
                $"The point does not have the {c.CoordinateLength}-byte coordinates of {c.Name}.");
        }

        var px = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var py = new BigInteger(y, isUnsigned: true, isBigEndian: true);
        if (px >= c.Prime || py >= c.Prime)
        {
            throw new CryptographicException($"The point's coordinates are not field elements of {c.Name}.");
        }

        // y^2 = x^3 - 3x + b (mod p). The uncompressed encoding has no point at infinity to
        // exclude, and b is not zero, so (0, 0) fails this too.
        var left = py * py % c.Prime;
        var right = (px * px % c.Prime * px - (3 * px) + c.B) % c.Prime;
        if (right.Sign < 0)
        {
            right += c.Prime;
        }

        if (left != right)
        {
            throw new CryptographicException($"The point is not on {c.Name}.");
        }

        return new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
    }

    // The OID is the curve's identity. The friendly name is a display form that differs by
    // platform, so it never decides the match; a curve that carries no OID is refused.
    private static Curve Find(ECCurve curve)
    {
        foreach (var c in All)
        {
            if (c.Oid == curve.Oid.Value)
            {
                return c;
            }
        }

        throw new CryptographicException(
            $"Points on curve '{curve.Oid.Value ?? curve.Oid.FriendlyName}' cannot be validated.");
    }

    private sealed record Curve
    {
        public Curve(string name, string oid, string prime, string b)
        {
            Name = name;
            Oid = oid;
            var primeBytes = Convert.FromHexString(prime);
            Prime = new BigInteger(primeBytes, isUnsigned: true, isBigEndian: true);
            B = new BigInteger(Convert.FromHexString(b), isUnsigned: true, isBigEndian: true);
            CoordinateLength = primeBytes.Length;
        }

        public string Name { get; }

        public string Oid { get; }

        public BigInteger Prime { get; }

        public BigInteger B { get; }

        public int CoordinateLength { get; }
    }
}
