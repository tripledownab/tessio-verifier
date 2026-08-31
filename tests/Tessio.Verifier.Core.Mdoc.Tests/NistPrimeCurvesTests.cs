using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// NistPrimeCurves against keys the platform generated. The curve parameters are transcribed
/// constants, so every accepted point here comes from outside this codebase: a wrong p or b would
/// reject a key the platform itself produced.
/// </summary>
public sealed class NistPrimeCurvesTests
{
    public static TheoryData<string> CurveOids =>
        new("1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35");

    private static ECParameters GenerateOn(string oid)
    {
        using var key = ECDsa.Create(ECCurve.CreateFromValue(oid));
        return key.ExportParameters(includePrivateParameters: false);
    }

    [Theory]
    [MemberData(nameof(CurveOids))]
    public void PublicKeyParameters_WithAPlatformGeneratedKey_Accepts(string oid)
    {
        var q = GenerateOn(oid).Q;

        var validated = NistPrimeCurves.PublicKeyParameters(ECCurve.CreateFromValue(oid), q.X!, q.Y!);

        Assert.Equal(q.X, validated.Q.X);
        Assert.Equal(q.Y, validated.Q.Y);
    }

    [Theory]
    [MemberData(nameof(CurveOids))]
    public void PublicKeyParameters_WithAFlippedCoordinateBit_Throws(string oid)
    {
        var q = GenerateOn(oid).Q;
        var y = q.Y!;
        y[^1] ^= 0x01;

        var e = Assert.Throws<CryptographicException>(
            () => NistPrimeCurves.PublicKeyParameters(ECCurve.CreateFromValue(oid), q.X!, y));
        Assert.Contains("is not on", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicKeyParameters_WithAShortCoordinate_Throws()
    {
        var q = GenerateOn("1.2.840.10045.3.1.7").Q;

        var e = Assert.Throws<CryptographicException>(() => NistPrimeCurves.PublicKeyParameters(
            ECCurve.NamedCurves.nistP256, q.X!, q.Y![1..]));
        Assert.Contains("32-byte coordinates", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicKeyParameters_WithACoordinateAtOrAboveThePrime_Throws()
    {
        // All ones is larger than every prime here, so it is not a field element on any of them.
        var q = GenerateOn("1.2.840.10045.3.1.7").Q;
        var x = new byte[32];
        Array.Fill(x, (byte)0xFF);

        var e = Assert.Throws<CryptographicException>(() => NistPrimeCurves.PublicKeyParameters(
            ECCurve.NamedCurves.nistP256, x, q.Y!));
        Assert.Contains("field elements", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicKeyParameters_WithACurveItDoesNotKnow_Throws()
    {
        // Nothing may pass unvalidated: an unknown curve is refused, not waved through.
        var q = GenerateOn("1.2.840.10045.3.1.7").Q;

        Assert.Throws<CryptographicException>(() => NistPrimeCurves.PublicKeyParameters(
            ECCurve.NamedCurves.brainpoolP256r1, q.X!, q.Y!));
    }

    [Theory]
    [MemberData(nameof(CurveOids))]
    public void NamedCurves_CarryTheOidTheTableIsKeyedOn(string oid)
    {
        // The lookup reads ECCurve.Oid.Value and nothing else. A runtime that stopped populating
        // it would make every point unvalidatable, so pin the assumption rather than infer it.
        var named = oid switch
        {
            "1.2.840.10045.3.1.7" => ECCurve.NamedCurves.nistP256,
            "1.3.132.0.34" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };

        Assert.Equal(oid, named.Oid.Value);
    }
}
