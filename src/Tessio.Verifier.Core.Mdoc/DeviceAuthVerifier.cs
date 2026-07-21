using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies the holder's device authentication: the <c>deviceSignature</c> COSE_Sign1 whose
/// detached payload is <c>DeviceAuthenticationBytes</c> over the session transcript, verified with
/// the device key pinned in the MSO. This is the mdoc analogue of the KB-JWT: it proves the wallet
/// that responded holds the key the issuer bound the credential to, for exactly this request.
/// </summary>
// SPEC: ISO/IEC 18013-5 §9.1.3.4 —
//   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
//   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
internal static class DeviceAuthVerifier
{
    public static List<VerificationError> Verify(
        ParsedDocument document, MobileSecurityObject mso, byte[] sessionTranscript)
    {
        if (document.DeviceSigned is not { } deviceSigned)
        {
            return [Error("The document carries no deviceSigned structure; device authentication is required.")];
        }

        if (deviceSigned.DeviceSignature is null)
        {
            return [Error(deviceSigned.DeviceMac is null
                ? "The document carries no deviceSignature."
                : "MAC-based device authentication (deviceMac) is not supported; use deviceSignature.")];
        }

        var deviceAuthenticationBytes = BuildDeviceAuthenticationBytes(
            sessionTranscript, document.DocType, deviceSigned.EncodedNameSpacesBytes);

        try
        {
            var message = CoseMessage.DecodeSign1(deviceSigned.DeviceSignature);
            using var deviceKey = ReadDeviceKey(mso.DeviceKeyEncoded);
            if (!message.VerifyDetached(deviceKey, deviceAuthenticationBytes))
            {
                return [Error("The deviceSignature does not verify over this request's session transcript.")];
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or MdocProcessingException)
        {
            return [Error($"Device authentication could not be verified: {e.Message}")];
        }

        return [];
    }

    internal static byte[] BuildDeviceAuthenticationBytes(
        byte[] sessionTranscript, string docType, byte[] encodedDeviceNameSpacesBytes)
    {
        var auth = new CborWriter(CborConformanceMode.Lax);
        auth.WriteStartArray(4);
        auth.WriteTextString("DeviceAuthentication");
        auth.WriteEncodedValue(sessionTranscript);
        auth.WriteTextString(docType);
        auth.WriteEncodedValue(encodedDeviceNameSpacesBytes);
        auth.WriteEndArray();

        var outer = new CborWriter(CborConformanceMode.Lax);
        outer.WriteTag((CborTag)24);
        outer.WriteByteString(auth.Encode());
        return outer.Encode();
    }

    // SPEC: RFC 9053 §7 — COSE_Key EC2: kty(1)=2, crv(-1)∈{1,2,3}, x(-2), y(-3).
    private static ECDsa ReadDeviceKey(byte[] coseKey)
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
                MdocErrorCodes.DeviceAuthInvalid, "The MSO device key is not an EC2 COSE_Key with x and y coordinates.");
        }

        var curve = crv switch
        {
            1 => ECCurve.NamedCurves.nistP256,
            2 => ECCurve.NamedCurves.nistP384,
            3 => ECCurve.NamedCurves.nistP521,
            _ => throw new MdocProcessingException(
                MdocErrorCodes.DeviceAuthInvalid, $"The MSO device key uses unsupported curve {crv}."),
        };

        return ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } });
    }

    private static VerificationError Error(string message) =>
        new() { Code = MdocErrorCodes.DeviceAuthInvalid, Message = message };
}
