using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The ISO/IEC 18013-7 Annex C <c>EncryptionInfo</c> a verifier sends with a Digital Credentials
/// API request: <c>["dcapi", {"nonce": bstr, "recipientPublicKey": COSE_Key}]</c>. The wallet
/// encrypts its response to the key in here, and the session transcript digest covers the encoded
/// bytes, so the encoding is deterministic and callers keep the sent bytes rather than rebuild.
/// </summary>
internal static class EncryptionInfo
{
    // The nonce length the published Annex C examples use.
    public const int NonceLength = 16;

    /// <summary>Encodes an EncryptionInfo for a P-256 recipient key.</summary>
    // Member order nonce, recipientPublicKey: the order of the published examples, which is also
    // CBOR canonical order for these keys.
    public static byte[] Encode(byte[] nonce, ECParameters recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException($"The nonce must be {NonceLength} bytes.", nameof(nonce));
        }

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(2);
        w.WriteTextString("dcapi");
        w.WriteStartMap(2);
        w.WriteTextString("nonce");
        w.WriteByteString(nonce);
        w.WriteTextString("recipientPublicKey");
        w.WriteEncodedValue(CoseKey.EncodeP256(recipientPublicKey));
        w.WriteEndMap();
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>
    /// Returns the encoded bytes of the EncryptionParameters map, exactly as they sit inside
    /// <paramref name="encryptionInfo"/>. The derived session transcript embeds these bytes
    /// verbatim; re-encoding from parsed values could reorder keys and change the digest.
    /// </summary>
    public static byte[] ExtractEncryptionParameters(byte[] encryptionInfo)
    {
        ArgumentNullException.ThrowIfNull(encryptionInfo);
        try
        {
            var reader = new CborReader(encryptionInfo, CborConformanceMode.Lax);
            reader.ReadStartArray();
            var label = reader.ReadTextString();
            if (label != "dcapi")
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.StructureInvalid, $"The EncryptionInfo label is '{label}', expected 'dcapi'.");
            }

            var parameters = reader.ReadEncodedValue().ToArray();
            reader.ReadEndArray();
            return parameters;
        }
        catch (Exception e) when (e is CborContentException or InvalidOperationException)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.StructureInvalid, $"The EncryptionInfo is not the expected CBOR shape: {e.Message}");
        }
    }
}
