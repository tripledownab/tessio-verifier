using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Builds the ISO/IEC 18013-5 <c>DeviceRequest</c> that travels over the W3C Digital Credentials
/// API (ISO/IEC 18013-7 Annex C): one docRequest, the itemsRequest tag-24 wrapped so its bytes
/// stay stable under the digest that binds the session. <see cref="Build"/> is unsigned; a signed
/// request comes from <see cref="Iso18013AnnexC.CreateSignedRequest"/>.
/// </summary>
// SPEC (shape): the published Annex C request examples:
//   DeviceRequest = {"version": "1.0", "docRequests": [{"itemsRequest": 24(<< ItemsRequest >>)}]}
//   ItemsRequest  = {"docType": tstr, "nameSpaces": {tstr: {tstr: bool}}}
// The bool on each element is IntentToRetain, not a requested value. A signed docRequest adds
// "readerAuth" beside "itemsRequest", as the ISO/IEC 18013-5 Annex D.4.1.1 example does.
public static class DeviceRequestBuilder
{
    // The version the published Annex C examples carry.
    private const string Version = "1.0";

    // The requestInfo member that carries the registration certificate. CIR (EU) 2026/1731, adapting
    // ETSI TS 119 472-2 V1.2.1 clause 5.3.2: ISO/IEC 18013-5-REQ-05's CDDL gives RequestInfo one
    // member, 'euWrprc', of type bstr, and REQ-07 says "The value of the 'euWrprc' shall be a
    // CBOR-encoded registration certificate". The standard's own CDDL spells it "eUWrprc" while its
    // prose says "euWrprc"; the regulation, the EUDI wallet core library and A-SIT Plus VCK all use
    // "euWrprc". It goes in the ItemsRequest, inside the bytes readerAuth signs: the regulation points
    // at ISO/IEC 18013-5 clause 8.3.2.1.2.1, which this library could not read, while the ETSI text it
    // replaced said ItemsRequest and the wallet libraries above read it there. ETSI cites ISO/IEC
    // 18013-5 without a date, so by its own rule the latest edition applies, and a clause number can
    // move when a new edition replaces the current one.
    private const string RegistrationCertificateKey = "euWrprc";

    /// <summary>Builds an unsigned single-document request for the named elements.</summary>
    /// <param name="docType">The requested document type, e.g. <c>eu.europa.ec.av.1</c>.</param>
    /// <param name="nameSpace">The namespace the elements live in.</param>
    /// <param name="elementIdentifiers">The elements to request. Requesting is the list itself.</param>
    /// <param name="intentToRetain">
    /// ISO/IEC 18013-5's IntentToRetain flag, applied to every requested element: whether the
    /// verifier intends to store the element after verifying it. This is NOT the value being
    /// requested; reading it as one inverts the question the request asks.
    /// </param>
    public static byte[] Build(
        string docType, string nameSpace, IReadOnlyList<string> elementIdentifiers, bool intentToRetain) =>
        EncodeDeviceRequest(EncodeItemsRequest(docType, nameSpace, elementIdentifiers, intentToRetain, null), null);

    /// <summary>
    /// Builds a single-document request signed with <c>readerAuth</c> over
    /// <paramref name="sessionTranscript"/>, so a wallet can show who is asking and refuse the request
    /// when it computes a different transcript, as it does for a request made from another origin.
    /// </summary>
    /// <param name="docType">The requested document type.</param>
    /// <param name="nameSpace">The namespace the elements live in.</param>
    /// <param name="elementIdentifiers">The elements to request.</param>
    /// <param name="intentToRetain">IntentToRetain for every element; see <see cref="Build"/>.</param>
    /// <param name="sessionTranscript">
    /// The encoded SessionTranscript the wallet will compute for this session. Over the Digital
    /// Credentials API that is <see cref="SessionTranscriptBuilder.BuildForIso18013AnnexC"/>.
    /// </param>
    /// <param name="reader">The reader key and certificate path to sign with.</param>
    /// <param name="registrationCertificate">
    /// The registration certificate to carry under <c>euWrprc</c>, or null; see
    /// <see cref="Iso18013AnnexC.CreateSignedRequest"/>.
    /// </param>
    // Internal until a transport other than the Digital Credentials API needs it. The one public way in
    // builds the transcript from the request's own EncryptionInfo, so the two can never disagree.
    internal static byte[] BuildSigned(
        string docType,
        string nameSpace,
        IReadOnlyList<string> elementIdentifiers,
        bool intentToRetain,
        byte[] sessionTranscript,
        MdocReaderKey reader,
        byte[]? registrationCertificate)
    {
        ArgumentNullException.ThrowIfNull(sessionTranscript);
        ArgumentNullException.ThrowIfNull(reader);
        if (registrationCertificate is { Length: 0 })
        {
            throw new ArgumentException(
                "An empty registration certificate is not one. Pass null when there is none.", nameof(registrationCertificate));
        }

        var itemsRequestBytes = EncodeItemsRequest(docType, nameSpace, elementIdentifiers, intentToRetain, registrationCertificate);
        return EncodeDeviceRequest(itemsRequestBytes, ReaderAuthentication.Sign(reader, sessionTranscript, itemsRequestBytes));
    }

    /// <summary>The docRequest's <c>itemsRequest</c>, tag-24 wrapped: the exact bytes readerAuth signs.</summary>
    private static byte[] EncodeItemsRequest(
        string docType,
        string nameSpace,
        IReadOnlyList<string> elementIdentifiers,
        bool intentToRetain,
        byte[]? registrationCertificate)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);
        ArgumentNullException.ThrowIfNull(elementIdentifiers);
        if (elementIdentifiers.Count == 0)
        {
            throw new ArgumentException("At least one element identifier is required.", nameof(elementIdentifiers));
        }

        if (elementIdentifiers.Distinct(StringComparer.Ordinal).Count() != elementIdentifiers.Count)
        {
            throw new ArgumentException("Element identifiers must be distinct.", nameof(elementIdentifiers));
        }

        var items = new CborWriter(CborConformanceMode.Lax);
        items.WriteStartMap(registrationCertificate is null ? 2 : 3);
        items.WriteTextString("docType");
        items.WriteTextString(docType);
        items.WriteTextString("nameSpaces");
        items.WriteStartMap(1);
        items.WriteTextString(nameSpace);
        items.WriteStartMap(elementIdentifiers.Count);
        foreach (var element in elementIdentifiers)
        {
            items.WriteTextString(element);
            items.WriteBoolean(intentToRetain);
        }

        items.WriteEndMap();
        items.WriteEndMap();
        if (registrationCertificate is not null)
        {
            items.WriteTextString("requestInfo");
            items.WriteStartMap(1);
            items.WriteTextString(RegistrationCertificateKey);
            items.WriteByteString(registrationCertificate);
            items.WriteEndMap();
        }

        items.WriteEndMap();

        var wrapped = new CborWriter(CborConformanceMode.Lax);
        wrapped.WriteTag((CborTag)24);
        wrapped.WriteByteString(items.Encode());
        return wrapped.Encode();
    }

    private static byte[] EncodeDeviceRequest(byte[] itemsRequestBytes, byte[]? readerAuth)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(2);
        w.WriteTextString("version");
        w.WriteTextString(Version);
        w.WriteTextString("docRequests");
        w.WriteStartArray(1);
        w.WriteStartMap(readerAuth is null ? 1 : 2);
        w.WriteTextString("itemsRequest");
        w.WriteEncodedValue(itemsRequestBytes);
        if (readerAuth is not null)
        {
            w.WriteTextString("readerAuth");
            w.WriteEncodedValue(readerAuth);
        }

        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteEndMap();
        return w.Encode();
    }
}
