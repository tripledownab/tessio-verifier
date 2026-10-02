// What belongs here: hostile CBOR that every mdoc reader must turn into a typed error, one case per
// reader, built from exact bytes so a failure here reproduces on any machine.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <remarks>
/// A CBOR unsigned integer can hold up to 2^64-1, and <c>CborReader.ReadInt64</c> throws
/// <see cref="OverflowException"/> for anything past <see cref="long.MaxValue"/>. That exception was in
/// no reader's catch, so each integer an mdoc carries was a way to escape the typed-error contract.
/// </remarks>
public sealed class CborIntegerRangeTests
{
    private static byte[] Encode(Action<CborWriter> write)
    {
        var w = new CborWriter();
        write(w);
        return w.Encode();
    }

    [Fact]
    public void A_status_past_the_long_range_is_a_structure_error()
    {
        var response = Encode(w =>
        {
            w.WriteStartMap(2);
            w.WriteTextString("version");
            w.WriteTextString("1.0");
            w.WriteTextString("status");
            w.WriteUInt64(ulong.MaxValue);
            w.WriteEndMap();
        });

        var e = Assert.Throws<MdocProcessingException>(
            () => DeviceResponseParser.Parse(Base64UrlEncoder.Encode(response)));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
    }

    /// <summary>
    /// The WIRING case: the verifier a caller uses, not the parser. It promises a result on any input,
    /// and before the fix this input made it throw.
    /// </summary>
    [Fact]
    public async Task The_verifier_returns_a_result_for_a_status_past_the_long_range()
    {
        var response = Encode(w =>
        {
            w.WriteStartMap(2);
            w.WriteTextString("version");
            w.WriteTextString("1.0");
            w.WriteTextString("status");
            w.WriteUInt64(ulong.MaxValue);
            w.WriteEndMap();
        });
        using var builder = new MdocTestBuilder();
        var verifier = new MdocVerifier(new Tessio.Verifier.Trust.StaticTrustListResolver(
            [builder.DsCertificate.Subject], source: "test", trustAnchors: [builder.IacaCertificate]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = MdocVerifier.Format, RawValue = Base64UrlEncoder.Encode(response) },
            new MdocVerificationContext
            {
                ExpectedDocType = MdocTestBuilder.DefaultDocType,
                ClientId = builder.ClientId,
                Nonce = builder.Nonce,
                ResponseUri = builder.ResponseUri,
            });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.StructureInvalid);
    }

    [Fact]
    public void A_digest_id_past_the_long_range_in_the_mso_is_an_mso_error()
    {
        var mso = Encode(w =>
        {
            w.WriteStartMap(1);
            w.WriteTextString("valueDigests");
            w.WriteStartMap(1);
            w.WriteTextString("org.iso.18013.5.1");
            w.WriteStartMap(1);
            w.WriteUInt64(ulong.MaxValue);
            w.WriteByteString([0x00]);
            w.WriteEndMap();
            w.WriteEndMap();
            w.WriteEndMap();
        });
        var payload = Encode(w =>
        {
            w.WriteTag((CborTag)24);
            w.WriteByteString(mso);
        });
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerAuth = CoseSign1Message.SignEmbedded(payload, new CoseSigner(key, HashAlgorithmName.SHA256));

        var e = Assert.Throws<MdocProcessingException>(() => DeviceResponseParser.ParseMso(issuerAuth));
        Assert.Equal(MdocErrorCodes.MsoInvalid, e.Code);
    }

    [Fact]
    public void A_cose_key_label_past_the_long_range_is_a_structure_error()
    {
        var coseKey = Encode(w =>
        {
            w.WriteStartMap(1);
            w.WriteUInt64(ulong.MaxValue);
            w.WriteInt32(2);
            w.WriteEndMap();
        });

        var e = Assert.Throws<MdocProcessingException>(() => CoseKey.ReadEc2PublicKey(coseKey));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
    }

    /// <summary>
    /// Not an integer case: the COSE_Key reader caught nothing at all, so plain truncation escaped too.
    /// The device key path is where that mattered, because its caller does not catch CBOR errors.
    /// </summary>
    [Fact]
    public void A_truncated_cose_key_is_a_structure_error()
    {
        var e = Assert.Throws<MdocProcessingException>(() => CoseKey.ReadEc2PublicKey([0xA4, 0x01]));
        Assert.Equal(MdocErrorCodes.StructureInvalid, e.Code);
    }
}
