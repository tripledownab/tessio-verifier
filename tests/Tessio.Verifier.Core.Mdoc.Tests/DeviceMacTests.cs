using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// MAC-based device authentication against the ISO/IEC 18013-5 Annex D worked example, whose device
/// response authenticates with deviceMac. Nothing here was produced by this codebase: the reader key,
/// the transcript, the EMacKey and the tag are all published, so a misreading shared by a wallet and
/// this verifier cannot pass.
/// </summary>
public sealed class DeviceMacTests
{
    private const string MdlDocType = "org.iso.18013.5.1.mDL";

    // The deviceMac value in the Annex D response: an untagged four-element array, the protected header
    // {1: 5} as a three-byte string, an empty unprotected map, a null payload and a 32-byte tag. Every
    // edit below rewrites this run, which occurs once in the response.
    private const string DeviceMacStart = "8443a10105a0f65820";

    private sealed class AnnexDClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2021, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }

    [Fact]
    public void DeriveEMacKey_ReproducesThePublishedKey()
    {
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);

        var emacKey = source.DeriveEMacKey(DeviceKey(), Iso18013AnnexDVectors.SessionTranscriptBytes);

        Assert.Equal(Iso18013AnnexDVectors.EMacKeyHex, Hex(emacKey));
    }

    [Fact]
    public void DeriveEMacKey_SaltedWithTheBareTranscript_IsADifferentKey()
    {
        // The salt is the tag-24 SessionTranscriptBytes, not the transcript inside it. The pipeline wraps
        // the transcript itself; this pins that the two are not interchangeable.
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);

        var emacKey = source.DeriveEMacKey(DeviceKey(), BareTranscript());

        Assert.NotEqual(Iso18013AnnexDVectors.EMacKeyHex, Hex(emacKey));
    }

    [Fact]
    public void DeriveEMacKey_RefusesADeviceKeyNotOnP256()
    {
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<CryptographicException>(() =>
            source.DeriveEMacKey(p384.ExportParameters(false), Iso18013AnnexDVectors.SessionTranscriptBytes));
    }

    [Fact]
    public void FromPrivateKey_RefusesAKeyNotOnP256()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<ArgumentException>(() => MdocMacKeySource.FromPrivateKey(p384.ExportParameters(true)));
    }

    [Fact]
    public void FromPrivateKey_RefusesAPublicKey()
    {
        var publicOnly = Iso18013AnnexDVectors.ReaderKey;
        publicOnly.D = null;

        Assert.Throws<ArgumentException>(() => MdocMacKeySource.FromPrivateKey(publicOnly));
    }

    [Fact]
    public async Task FullPipeline_WithTheReaderKey_PassesTheDeviceMac()
    {
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);

        var result = await VerifyAsync(Iso18013AnnexDVectors.DeviceResponse, source);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
        Assert.Equal(MdocDeviceAuthentication.Mac, result.DeviceAuthentication);
    }

    [Fact]
    public async Task FullPipeline_OptedInWithoutAReaderKey_RefusesTheDeviceMac()
    {
        var result = await VerifyAsync(Iso18013AnnexDVectors.DeviceResponse, macKeys: null);

        AssertRefused(result, "reader key");
    }

    [Fact]
    public async Task FullPipeline_WithTheOptionOff_RefusesTheDeviceMac_EvenWithTheReaderKey()
    {
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);

        var result = await VerifyAsync(Iso18013AnnexDVectors.DeviceResponse, source, acceptDeviceMac: false);

        AssertRefused(result, "AcceptDeviceMac");
    }

    [Fact]
    public async Task FullPipeline_AnotherReaderKey_FailsTheMac()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var source = MdocMacKeySource.FromPrivateKey(other.ExportParameters(true));

        var result = await VerifyAsync(Iso18013AnnexDVectors.DeviceResponse, source);

        AssertRefused(result, "does not verify");
    }

    [Fact]
    public async Task FullPipeline_ATagWithOneByteFlipped_FailsTheMac()
    {
        // The tag's first byte is e9; e8 differs in one bit.
        var result = await VerifyEditedAsync(DeviceMacStart + "e9", DeviceMacStart + "e8");

        AssertRefused(result, "does not verify");
    }

    [Fact]
    public async Task FullPipeline_AnAlgorithmOtherThanHmac256_IsRefused()
    {
        // alg 6 is HMAC 384/384 (RFC 9053 Table 7), which ISO 18013-5 does not allow here.
        var result = await VerifyEditedAsync(DeviceMacStart, "8443a10106a0f65820");

        AssertRefused(result, "alg");
    }

    [Fact]
    public async Task FullPipeline_AnAttachedPayload_IsRefused()
    {
        // The null payload replaced by an empty byte string: same length, so nothing else moves.
        var result = await VerifyEditedAsync(DeviceMacStart, "8443a10105a0405820");

        AssertRefused(result, "payload");
    }

    [Fact]
    public async Task FullPipeline_ACriticalHeaderThisVerifierDoesNotProcess_IsRefused()
    {
        // Protected header {1: 5, 2: [99]}: alg as before, and crit naming label 99.
        var result = await VerifyEditedAsync(DeviceMacStart, "8447a20105028118" + "63a0f65820");

        AssertRefused(result, "critical");
    }

    // Each row rewrites the start of the deviceMac. Byte strings carry their length and arrays and maps their count,
    // so each row sets the protected header's length prefix (43 to 46) to match. Every one is refused before the MAC
    // is computed, so the unchanged tag does not decide the outcome.
    [Theory]
    [InlineData("d818" + DeviceMacStart, "not a valid COSE_Mac0")] // CBOR tag 24, not COSE_Mac0's 17
    [InlineData("8445a201050280a0f65820", "crit")]                  // crit: an empty array
    [InlineData("8446a20105029fffa0f65820", "crit")]                // crit: an empty indefinite-length array
    [InlineData("8445a201050201a0f65820", "crit")]                  // crit: not an array
    [InlineData("8445a201050105a0f65820", "malformed")]             // protected header repeats alg
    [InlineData("8444a1010500a0f65820", "malformed")]               // a byte after the protected map
    [InlineData("8444a1016135a0f65820", "alg")]                     // alg as the text "5"
    [InlineData("8443a10105a2044004" + "40f65820", "malformed")]    // unprotected header repeats label 4
    [InlineData("8443a10105a10106f65820", "both")]                  // alg in both buckets, 5 and 6
    public async Task FullPipeline_AHeaderRfc9052Refuses_IsRefused(string to, string reason)
    {
        var result = await VerifyEditedAsync(DeviceMacStart, to);

        AssertRefused(result, reason);
    }

    [Fact]
    public async Task FullPipeline_ACritInTheUnprotectedHeader_IsRefused()
    {
        // Unprotected header {2: [1]}: crit naming alg, but in the bucket RFC 9052 section 3.1 forbids.
        var result = await VerifyEditedAsync(DeviceMacStart, "8443a10105a1028101f65820");

        AssertRefused(result, "unprotected");
    }

    [Fact]
    public async Task FullPipeline_AMalformedProtectedHeader_IsRefusedNotThrown()
    {
        // The protected header's first byte made a CBOR break code, which no map can start with.
        var result = await VerifyEditedAsync(DeviceMacStart, "8443ff0105a0f65820");

        AssertRefused(result, "malformed");
    }

    [Fact]
    public async Task FullPipeline_ACoseMac0Tag_IsAccepted()
    {
        // Tag 17 marks a COSE_Mac0 (RFC 9052 section 2). ISO 18013-5 sends it untagged, and the tag adds
        // nothing a verifier needs, so a wallet that adds it is not refused for that, as the platform's
        // COSE_Sign1 decoder does not refuse a tagged deviceSignature. Arrays and maps carry counts, not
        // byte lengths, so the extra byte moves nothing else.
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);

        var result = await VerifyAsync(Edit(DeviceMacStart, "d1" + DeviceMacStart), source);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
    }

    [Fact]
    public async Task FullPipeline_ADisposedSource_IsRefusedNotThrown()
    {
        var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);
        source.Dispose();

        var result = await VerifyAsync(Iso18013AnnexDVectors.DeviceResponse, source);

        AssertRefused(result, "deviceMac");
    }

    private static void AssertRefused(VerificationResult result, string reason)
    {
        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal(MdocErrorCodes.DeviceAuthInvalid, error.Code);
        Assert.Contains(reason, error.Message, StringComparison.Ordinal);
        Assert.Null(result.DeviceAuthentication);
    }

    private static async Task<VerificationResult> VerifyEditedAsync(string from, string to)
    {
        using var source = MdocMacKeySource.FromPrivateKey(Iso18013AnnexDVectors.ReaderKey);
        return await VerifyAsync(Edit(from, to), source);
    }

    // Convert.ToHexStringLower is .NET 9 and later; this suite also runs on .NET 8.
    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] Edit(string from, string to)
    {
        var hex = Hex(Iso18013AnnexDVectors.DeviceResponse);
        var at = hex.IndexOf(from, StringComparison.Ordinal);
        Assert.True(at >= 0 && hex.IndexOf(from, at + 1, StringComparison.Ordinal) < 0, "the edited run must occur once");
        return Convert.FromHexString(string.Concat(hex.AsSpan(0, at), to, hex.AsSpan(at + from.Length)));
    }

    private static async Task<VerificationResult> VerifyAsync(
        byte[] deviceResponse, MdocMacKeySource? macKeys, bool acceptDeviceMac = true)
    {
#if NET9_0_OR_GREATER
        using var dsCert = X509CertificateLoader.LoadCertificate(Iso18013AnnexDVectors.DsCertificate);
#else
        using var dsCert = new X509Certificate2(Iso18013AnnexDVectors.DsCertificate);
#endif
        var clock = new AnnexDClock();
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([dsCert.Subject], source: "iso-annex-d", trustAnchors: [dsCert], clock: clock),
            new MdocVerifierOptions { AcceptDeviceMac = acceptDeviceMac },
            clock);

        return await verifier.VerifyAsync(
            new PresentedCredential
            {
                Format = MdocVerifier.Format,
                RawValue = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(deviceResponse),
            },
            new MdocVerificationContext
            {
                ExpectedDocType = MdlDocType,
                SessionTranscript = BareTranscript(),
                MacKeySource = macKeys,
            });
    }

    private static ECParameters DeviceKey()
    {
        var document = DeviceResponseParser.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(Iso18013AnnexDVectors.DeviceResponse)).Documents[0];
        return CoseKey.ReadEc2PublicKey(DeviceResponseParser.ParseMso(document.IssuerAuth).DeviceKeyEncoded);
    }

    private static byte[] BareTranscript()
    {
        var reader = new CborReader(Iso18013AnnexDVectors.SessionTranscriptBytes, CborConformanceMode.Lax);
        Assert.Equal((CborTag)24, reader.ReadTag());
        return reader.ReadByteString();
    }
}
