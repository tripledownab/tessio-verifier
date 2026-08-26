using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Reads the ISO/IEC 18013-7 Annex C <c>EncryptedResponse</c> a wallet returns over the Digital
/// Credentials API: <c>["dcapi", {"enc": bstr, "cipherText": bstr}]</c>. Reading only, because
/// the verifier never produces one.
/// </summary>
internal static class EncryptedResponse
{
    /// <summary>Returns the encapsulated key and the ciphertext.</summary>
    public static (byte[] Enc, byte[] CipherText) Decode(byte[] encryptedResponse)
    {
        ArgumentNullException.ThrowIfNull(encryptedResponse);
        try
        {
            var reader = new CborReader(encryptedResponse, CborConformanceMode.Lax);
            reader.ReadStartArray();
            var label = reader.ReadTextString();
            if (label != "dcapi")
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.StructureInvalid, $"The EncryptedResponse label is '{label}', expected 'dcapi'.");
            }

            byte[]? enc = null;
            byte[]? cipherText = null;
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "enc":
                        enc = reader.ReadByteString();
                        break;
                    case "cipherText":
                        cipherText = reader.ReadByteString();
                        break;
                    default:
                        // Newer editions add members; enc and cipherText are what decryption needs.
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();
            reader.ReadEndArray();

            if (enc is null || cipherText is null)
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.StructureInvalid, "The EncryptedResponse lacks enc or cipherText.");
            }

            return (enc, cipherText);
        }
        catch (Exception e) when (e is CborContentException or InvalidOperationException)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.StructureInvalid, $"The EncryptedResponse is not the expected CBOR shape: {e.Message}");
        }
    }
}
