using System.Formats.Cbor;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Builds the ISO 18013-5 <c>SessionTranscript</c> for each transport this library supports. The
/// device signature covers these bytes, binding the presentation to this verifier's request. An
/// OpenID4VP redirect flow binds client_id, nonce, the response encryption key thumbprint and the
/// response_uri; OpenID4VP over the Digital Credentials API binds the origin, nonce and thumbprint;
/// ISO/IEC 18013-7 Annex C over the same API binds the origin and the EncryptionInfo bytes.
/// </summary>
// SPEC: OpenID4VP 1.0 Annex B.2.6.1, redirect flows —
//   SessionTranscript = [null, null, OpenID4VPHandover]
//   OpenID4VPHandover = ["OpenID4VPHandover", sha-256(OpenID4VPHandoverInfo as CBOR)]
//   OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint / null, responseUri]
// The Digital Credentials API variant is Annex B.2.6.2, on BuildForDcApi below.
public static class SessionTranscriptBuilder
{
    /// <summary>Builds the SessionTranscript for an OpenID4VP redirect-flow presentation.</summary>
    public static byte[] Build(string clientId, string nonce, byte[]? encryptionKeyThumbprint, string responseUri) =>
        WrapHandover("OpenID4VPHandover", BuildHandoverInfo(clientId, nonce, encryptionKeyThumbprint, responseUri));

    /// <summary>
    /// Builds the SessionTranscript for a presentation made over the W3C Digital Credentials API.
    /// </summary>
    /// <remarks>
    /// <see cref="MdocVerifier"/> does not call this. A caller verifying a Digital Credentials API
    /// presentation takes the bytes from here and passes them via
    /// <see cref="MdocVerificationContext.SessionTranscript"/>, which the verifier checks the device
    /// signature over.
    /// </remarks>
    /// <param name="origin">
    /// The request's Origin, WITHOUT the <c>origin:</c> prefix. The prefix belongs on the Client
    /// Identifier and not in here, and the two are easy to confuse because the audience of the
    /// presentation is the same value with the prefix on it.
    /// </param>
    /// <param name="nonce">The <c>nonce</c> request parameter.</param>
    /// <param name="encryptionKeyThumbprint">
    /// The RFC 7638 thumbprint of the key the response is encrypted to, under response mode
    /// <c>dc_api.jwt</c>. Null under <c>dc_api</c>, which is cleartext.
    /// </param>
    // SPEC: OpenID4VP 1.0 Annex B.2.6.2, "Invocation via the Digital Credentials API" —
    //   SessionTranscript = [null, null, OpenID4VPDCAPIHandover]
    //   OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", sha-256(OpenID4VPDCAPIHandoverInfo as CBOR)]
    //   OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint]
    //
    // The CDDL types that third element `bstr`, but the prose overrides it: "If the Response Mode is
    // dc_api, the third element MUST be null". Prose wins, so this takes a nullable thumbprint. Reading
    // the CDDL alone would produce a transcript no wallet agrees with, on the cleartext path only,
    // which is the harder half to notice.
    //
    // Differs from the redirect flow above in exactly two ways: this label, and three fields where that
    // has four. There is no response_uri here, because the DC API returns the response through the
    // browser rather than by posting to one.
    public static byte[] BuildForDcApi(string origin, string nonce, byte[]? encryptionKeyThumbprint) =>
        WrapHandover("OpenID4VPDCAPIHandover", BuildDcApiHandoverInfo(origin, nonce, encryptionKeyThumbprint));

    /// <summary>
    /// Builds the SessionTranscript for a presentation over the W3C Digital Credentials API under
    /// ISO/IEC 18013-7 Annex C: the mdoc-native mechanism, distinct from OpenID4VP's DC API
    /// handover on <see cref="BuildForDcApi"/>. The handover digest commits to the exact
    /// EncryptionInfo bytes sent with the request and to the origin the browser reports.
    /// </summary>
    /// <param name="encryptionInfo">The encoded EncryptionInfo, byte for byte as sent.</param>
    /// <param name="origin">The request's Origin, without the <c>origin:</c> prefix.</param>
    /// <param name="encryptionParameters">
    /// Null builds the base form, whose second element is null; the profile's examples print that
    /// form. Non-null builds the form whose second element is these bytes tag-24 wrapped, which the
    /// reference implementations derive the response's HPKE keys over. Pass the parameters exactly
    /// as they sit inside <paramref name="encryptionInfo"/>, never re-encoded, because the second
    /// element carries the bytes and not the values.
    /// </param>
    // SPEC (shape): the profile's published request example prints
    //   SessionTranscript = [null, null, ["dcapi", h'...']]
    // but no text this library can cite states the digest preimage. The construction
    //   sha-256(cbor([base64url(EncryptionInfo), origin]))
    // reproduces the profile's own published digest, which the conformance test pins.
    public static byte[] BuildForIso18013AnnexC(byte[] encryptionInfo, string origin, byte[]? encryptionParameters)
    {
        ArgumentNullException.ThrowIfNull(encryptionInfo);
        RequireBareOrigin(origin);

        var info = new CborWriter(CborConformanceMode.Lax);
        info.WriteStartArray(2);
        info.WriteTextString(Base64UrlEncoder.Encode(encryptionInfo));
        info.WriteTextString(origin);
        info.WriteEndArray();

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(3);
        w.WriteNull(); // DeviceEngagementBytes: none over this transport
        if (encryptionParameters is null)
        {
            w.WriteNull();
        }
        else
        {
            w.WriteTag((CborTag)24);
            w.WriteByteString(encryptionParameters);
        }

        w.WriteStartArray(2);
        w.WriteTextString("dcapi");
        w.WriteByteString(SHA256.HashData(info.Encode()));
        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>
    /// The outer transcript the two OpenID4VP transports share: two nulls and a handover of
    /// <c>[label, sha-256(handoverInfo)]</c>. Only the label and the handover info differ between
    /// them, so this is stated once rather than twice. The Annex C transcript does not come through
    /// here, because its second element is not always null.
    /// </summary>
    private static byte[] WrapHandover(string handoverLabel, byte[] handoverInfo)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(3);
        w.WriteNull(); // DeviceEngagementBytes MUST be null
        w.WriteNull(); // EReaderKeyBytes MUST be null
        w.WriteStartArray(2);
        w.WriteTextString(handoverLabel);
        w.WriteByteString(SHA256.HashData(handoverInfo));
        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>
    /// The <c>origin:</c> prefix belongs to the Client Identifier, never to a transcript. Refuse
    /// rather than strip it: a caller passing the prefixed form has confused the two values, and
    /// silently accepting it would produce a transcript that verifies here and nowhere else.
    /// </summary>
    private static void RequireBareOrigin(string origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (origin.StartsWith("origin:", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The Origin must not carry the 'origin:' Client Identifier Prefix. Pass the bare origin, " +
                "for example https://verifier.example.com.", nameof(origin));
        }
    }

    internal static byte[] BuildDcApiHandoverInfo(string origin, string nonce, byte[]? encryptionKeyThumbprint)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        RequireBareOrigin(origin);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(3);
        w.WriteTextString(origin);
        w.WriteTextString(nonce);
        if (encryptionKeyThumbprint is null)
        {
            w.WriteNull(); // response mode dc_api: cleartext, so there is no key to bind
        }
        else
        {
            w.WriteByteString(encryptionKeyThumbprint);
        }

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
