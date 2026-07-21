using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Builds the ISO 18013-5 <c>SessionTranscript</c> for OpenID4VP redirect flows. The device
/// signature covers these bytes, binding the presentation to this verifier's request: client_id,
/// nonce, the response encryption key thumbprint and the response_uri.
/// </summary>
// SPEC: OpenID4VP 1.0 Annex B.2.6.1 —
//   SessionTranscript = [null, null, OpenID4VPHandover]
//   OpenID4VPHandover = ["OpenID4VPHandover", sha-256(OpenID4VPHandoverInfo as CBOR)]
//   OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint / null, responseUri]
internal static class SessionTranscriptBuilder
{
    public static byte[] Build(string clientId, string nonce, byte[]? encryptionKeyThumbprint, string responseUri)
    {
        var handoverInfoHash = SHA256.HashData(
            BuildHandoverInfo(clientId, nonce, encryptionKeyThumbprint, responseUri));

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(3);
        w.WriteNull(); // DeviceEngagementBytes MUST be null
        w.WriteNull(); // EReaderKeyBytes MUST be null
        w.WriteStartArray(2);
        w.WriteTextString("OpenID4VPHandover");
        w.WriteByteString(handoverInfoHash);
        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    internal static byte[] BuildHandoverInfo(string clientId, string nonce, byte[]? encryptionKeyThumbprint, string responseUri)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(4);
        w.WriteTextString(clientId);
        w.WriteTextString(nonce);
        if (encryptionKeyThumbprint is null)
        {
            w.WriteNull(); // unencrypted responses carry no key to bind
        }
        else
        {
            w.WriteByteString(encryptionKeyThumbprint);
        }

        w.WriteTextString(responseUri);
        w.WriteEndArray();
        return w.Encode();
    }
}
