using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// COSE_Key EC2 encoding and decoding, in one file so the writer and the reader of the same
/// format cannot drift apart. Read for the MSO's device key; written for the encrypted-response
/// recipient key an ISO/IEC 18013-7 Annex C request advertises.
/// </summary>
// SPEC: RFC 9053 §7: COSE_Key EC2: kty(1)=2, crv(-1) in {1,2,3}, x(-2), y(-3).
internal static class CoseKey
{
    /// <summary>Encodes a P-256 public key as a COSE_Key.</summary>
    // Label order 1, -1, -2, -3: CBOR canonical, and the order the published Annex C examples
    // use. These bytes can end up inside a session transcript digest, so the encoding must be
    // deterministic.
    public static byte[] EncodeP256(ECParameters parameters)
    {
        if (parameters.Q.X is not { Length: 32 } x || parameters.Q.Y is not { Length: 32 } y)
        {
            throw new CryptographicException("The key does not have the 32-byte coordinates of a P-256 point.");
        }

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(4);
        w.WriteInt32(1);
        w.WriteInt32(2); // kty: EC2
        w.WriteInt32(-1);
        w.WriteInt32(1); // crv: P-256
        w.WriteInt32(-2);
        w.WriteByteString(x);
        w.WriteInt32(-3);
        w.WriteByteString(y);
        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>Reads an EC2 COSE_Key into curve and point. Unknown labels are skipped.</summary>
    public static ECParameters ReadEc2PublicKey(byte[] coseKey)
    {
        var reader = new CborReader(coseKey, CborConformanceMode.Lax);
        long? kty = null, crv = null;
        byte[]? x = null, y = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            var label = reader.ReadInt64();
            switch (label)
            {
                case 1:
                    kty = reader.ReadInt64();
                    break;
                case -1:
                    crv = reader.ReadInt64();
                    break;
                case -2:
                    x = reader.ReadByteString();
                    break;
                case -3:
                    y = reader.ReadByteString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (kty != 2 || x is null || y is null)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.StructureInvalid, "The COSE_Key is not an EC2 key with x and y coordinates.");
        }

        var curve = crv switch
        {
            1 => ECCurve.NamedCurves.nistP256,
            2 => ECCurve.NamedCurves.nistP384,
            3 => ECCurve.NamedCurves.nistP521,
            _ => throw new MdocProcessingException(
                MdocErrorCodes.StructureInvalid, $"The COSE_Key uses unsupported curve {crv}."),
        };

        return new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
    }
}
