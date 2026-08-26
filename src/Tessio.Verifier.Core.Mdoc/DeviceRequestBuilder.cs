using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Builds the ISO/IEC 18013-5 <c>DeviceRequest</c> that travels over the W3C Digital Credentials
/// API (ISO/IEC 18013-7 Annex C): one docRequest, no readerAuth, the itemsRequest tag-24 wrapped
/// so its bytes stay stable under the digest that binds the session.
/// </summary>
// SPEC (shape): the published Annex C request examples:
//   DeviceRequest = {"version": "1.0", "docRequests": [{"itemsRequest": 24(<< ItemsRequest >>)}]}
//   ItemsRequest  = {"docType": tstr, "nameSpaces": {tstr: {tstr: bool}}}
// The bool on each element is IntentToRetain, not a requested value.
public static class DeviceRequestBuilder
{
    // The version the published Annex C examples carry.
    private const string Version = "1.0";

    /// <summary>Builds a single-document request for the named elements.</summary>
    /// <param name="docType">The requested document type, e.g. <c>eu.europa.ec.av.1</c>.</param>
    /// <param name="nameSpace">The namespace the elements live in.</param>
    /// <param name="elementIdentifiers">The elements to request. Requesting is the list itself.</param>
    /// <param name="intentToRetain">
    /// ISO/IEC 18013-5's IntentToRetain flag, applied to every requested element: whether the
    /// verifier intends to store the element after verifying it. This is NOT the value being
    /// requested; reading it as one inverts the question the request asks.
    /// </param>
    public static byte[] Build(
        string docType, string nameSpace, IReadOnlyList<string> elementIdentifiers, bool intentToRetain)
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
        items.WriteStartMap(2);
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
        items.WriteEndMap();

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(2);
        w.WriteTextString("version");
        w.WriteTextString(Version);
        w.WriteTextString("docRequests");
        w.WriteStartArray(1);
        w.WriteStartMap(1);
        w.WriteTextString("itemsRequest");
        w.WriteTag((CborTag)24);
        w.WriteByteString(items.Encode());
        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteEndMap();
        return w.Encode();
    }
}
