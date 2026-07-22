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
public static class SessionTranscriptBuilder
{
    /// <summary>Builds the SessionTranscript for an OpenID4VP redirect-flow presentation.</summary>
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

    /// <summary>
    /// Builds <c>DeviceAuthenticationBytes</c>, the detached payload the device signature covers.
    /// Wallet simulators sign these; the verifier reconstructs them.
    /// </summary>
    // SPEC: ISO/IEC 18013-5 §9.1.3.4 —
    //   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
    //   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
    public static byte[] BuildDeviceAuthenticationBytes(
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
}
