// What belongs in this file: the mock wallet's deviceMac, made the way a wallet makes one, from the device's private
// key and the reader's public key. It shares no code with the verifier's check on purpose, so the two halves meet
// only in the bytes; the published ISO/IEC 18013-5 Annex D example is what proves either one right.
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;

namespace Tessio.Verifier.AspNetCore;

internal sealed partial class MockMdocIssuer
{
    /// <summary>An untagged COSE_Mac0 with HMAC 256/256 over the detached DeviceAuthenticationBytes.</summary>
    // SPEC: ISO/IEC 18013-5 section 9.1.3.5 (second edition working draft of 2025-09-14, clause 12.4.5): the
    // mdoc performs ECKA-DH with "SDeviceKey.Priv and EReaderKey.Pub", derives EMacKey with HKDF-SHA-256 over ZAB, salted with
    // SHA-256(SessionTranscriptBytes) and labelled "EMacKey", then MACs DeviceAuthenticationBytes as detached
    // content with an empty external_aad. RFC 9052 section 6.3 gives the MAC_structure.
    private byte[] DeviceMac(ECParameters readerPublicKey, byte[] sessionTranscript, byte[] deviceAuthenticationBytes)
    {
        using var device = ECDiffieHellman.Create(_deviceKey.ExportParameters(includePrivateParameters: true));
        using var reader = ECDiffieHellman.Create(readerPublicKey);
        var zab = device.DeriveRawSecretAgreement(reader.PublicKey);

        var transcriptBytes = new CborWriter(CborConformanceMode.Lax);
        transcriptBytes.WriteTag((CborTag)24);
        transcriptBytes.WriteByteString(sessionTranscript);
        var emacKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256, zab, 32, SHA256.HashData(transcriptBytes.Encode()), Encoding.UTF8.GetBytes("EMacKey"));

        var protectedHeader = new CborWriter(CborConformanceMode.Lax);
        protectedHeader.WriteStartMap(1);
        protectedHeader.WriteInt32(1);
        protectedHeader.WriteInt32(5); // alg: HMAC 256/256
        protectedHeader.WriteEndMap();
        var encodedProtected = protectedHeader.Encode();

        var macStructure = new CborWriter(CborConformanceMode.Lax);
        macStructure.WriteStartArray(4);
        macStructure.WriteTextString("MAC0");
        macStructure.WriteByteString(encodedProtected);
        macStructure.WriteByteString([]);
        macStructure.WriteByteString(deviceAuthenticationBytes);
        macStructure.WriteEndArray();

        var mac0 = new CborWriter(CborConformanceMode.Lax);
        mac0.WriteStartArray(4);
        mac0.WriteByteString(encodedProtected);
        mac0.WriteStartMap(0);
        mac0.WriteEndMap();
        mac0.WriteNull();
        mac0.WriteByteString(HMACSHA256.HashData(emacKey, macStructure.Encode()));
        mac0.WriteEndArray();
        return mac0.Encode();
    }
}
