// What belongs in this file: checking a deviceMac COSE_Mac0. Its header rules are in DeviceMacVerifier.Headers.cs;
// deriving its key is MdocMacKeySource's job; choosing between this and the signature is DeviceAuthVerifier's.
using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies the holder's MAC-based device authentication: the <c>deviceMac</c> COSE_Mac0 over
/// <c>DeviceAuthenticationBytes</c>, keyed with the EMacKey the reader derives from its own private key and
/// the device key pinned in the MSO.
/// </summary>
// SPEC: ISO/IEC 18013-5 section 9.1.3.5 (second edition working draft of 2025-09-14, clause 12.4.5): "The MAC
// value is contained in the tag element within DeviceAuth in an untagged COSE_Mac0 structure as defined in RFC
// 9052 and identified as DeviceMac. Within the COSE_Mac0 structure, the payload shall have a null value. The
// detached content is DeviceAuthenticationBytes. The ‘external_aad’ field shall be a bytestring of size
// zero. The alg element (RFC 9052) shall be included as an element in the protected header." and
// "“HMAC 256/256” (HMAC with SHA-256) shall be used."
internal static partial class DeviceMacVerifier
{
    // RFC 9053 section 3.1, Table 7: HMAC 256/256 is alg 5.
    private const int Hmac256 = 5;

    // RFC 9052 section 2: the CBOR tag of a COSE_Mac0.
    private const ulong CoseMac0Tag = 17;

    private const int AlgLabel = 1;
    private const int CritLabel = 2;

    public static List<VerificationError> Verify(
        byte[] deviceMac,
        MobileSecurityObject mso,
        byte[] sessionTranscript,
        byte[] deviceAuthenticationBytes,
        MdocMacKeySource? macKeys)
    {
        if (macKeys is null)
        {
            return [Error("The document authenticates with deviceMac, which needs the reader key the request "
                + "published; this verification has none it can use.")];
        }

        byte[]? emacKey = null;
        try
        {
            if (Read(deviceMac) is not { } mac)
            {
                return [Error("The deviceMac is not a valid COSE_Mac0.")];
            }

            if (HeaderProblem(mac) is { } problem)
            {
                return [Error(problem)];
            }

            if (mac.HasPayload)
            {
                return [Error("The deviceMac carries its payload; it must be null, with DeviceAuthentication detached.")];
            }

            emacKey = macKeys.DeriveEMacKey(CoseKey.ReadEc2PublicKey(mso.DeviceKeyEncoded), WrapTranscript(sessionTranscript));
            var expected = HMACSHA256.HashData(emacKey, MacStructure(mac.ProtectedHeader, deviceAuthenticationBytes));
            if (!CryptographicOperations.FixedTimeEquals(expected, mac.Tag))
            {
                return [Error("The deviceMac does not verify over this request's session transcript.")];
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or MdocProcessingException
            or ObjectDisposedException)
        {
            return [Error($"The deviceMac could not be verified: {e.Message}")];
        }
        finally
        {
            if (emacKey is not null)
            {
                CryptographicOperations.ZeroMemory(emacKey);
            }
        }

        return [];
    }

    private sealed record Mac0(byte[] ProtectedHeader, byte[] UnprotectedHeader, bool HasPayload, byte[] Tag);

    /// <summary>The four elements of a COSE_Mac0, or null when the bytes are not one.</summary>
    /// <remarks>
    /// The parser hands over exactly one CBOR item (<c>ReadEncodedValue</c>), so nothing can follow the array.
    /// </remarks>
    // SPEC: RFC 9052 section 6.2: COSE_Mac0 = [Headers (protected bstr, unprotected map), payload : bstr / nil,
    // tag : bstr]. Tag 17 is accepted although ISO 18013-5 sends the structure untagged: it carries nothing a
    // verifier needs, and the platform's COSE_Sign1 decoder accepts a tagged deviceSignature the same way. Any
    // other tag is refused.
    private static Mac0? Read(byte[] bytes)
    {
        try
        {
            var reader = new CborReader(bytes, CborConformanceMode.Lax);
            if (reader.PeekState() == CborReaderState.Tag && (ulong)reader.ReadTag() != CoseMac0Tag)
            {
                return null;
            }

            if (reader.ReadStartArray() != 4)
            {
                return null;
            }

            var protectedHeader = reader.ReadByteString();
            var unprotectedHeader = reader.ReadEncodedValue().ToArray();
            var hasPayload = reader.PeekState() != CborReaderState.Null;
            reader.SkipValue();
            var tag = reader.ReadByteString();
            reader.ReadEndArray();
            return new Mac0(protectedHeader, unprotectedHeader, hasPayload, tag);
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            return null;
        }
    }

    /// <summary><c>SessionTranscriptBytes</c>: the transcript inside a tag-24 byte string, which the salt hashes.</summary>
    // SPEC: ISO/IEC 18013-5 section 9.1.5.1: SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript).
    private static byte[] WrapTranscript(byte[] sessionTranscript)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteTag((CborTag)24);
        w.WriteByteString(sessionTranscript);
        return w.Encode();
    }

    /// <summary>The bytes the tag is computed over.</summary>
    // SPEC: RFC 9052 section 6.3: MAC_structure = [context : "MAC0", protected : empty_or_serialized_map,
    // external_aad : bstr, payload : bstr], with the detached content as the payload and, per ISO 18013-5,
    // an empty external_aad.
    private static byte[] MacStructure(byte[] protectedHeader, byte[] deviceAuthenticationBytes)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(4);
        w.WriteTextString("MAC0");
        w.WriteByteString(protectedHeader);
        w.WriteByteString([]);
        w.WriteByteString(deviceAuthenticationBytes);
        w.WriteEndArray();
        return w.Encode();
    }

    private static VerificationError Error(string message) =>
        new() { Code = MdocErrorCodes.DeviceAuthInvalid, Message = message };
}
