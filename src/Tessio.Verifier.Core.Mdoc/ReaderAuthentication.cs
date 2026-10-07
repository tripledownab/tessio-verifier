// What belongs in this file: the reader's signature over one docRequest (ISO/IEC 18013-5 readerAuth),
// what it is computed over and how it is encoded.
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Signs an mdoc request's docRequest: a COSE_Sign1 with a detached payload over
/// <c>ReaderAuthenticationBytes</c>, the reader certificate path in <c>x5chain</c>. The session
/// transcript inside the signed bytes is what binds the request to one session and, under
/// ISO/IEC 18013-7 Annex C, to the origin that asked.
/// </summary>
// SPEC: ISO/IEC 18013-5 itself was not available to this library. The construction is the one its
// Annex D.4.1.1 request example is signed over, which a conformance test verifies against the
// published signature:
//   ReaderAuthentication      = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
//   ReaderAuthenticationBytes = #6.24(bstr .cbor ReaderAuthentication)
//   ItemsRequestBytes         = #6.24(bstr .cbor ItemsRequest), the docRequest's own item
// x5chain is RFC 9360 header label 33: one bstr for a single certificate, else an array of bstr,
// "starting with the certificate containing the end-entity key". RFC 9360 also says "The end-entity
// certificate MUST be integrity protected by COSE", which an unprotected x5chain alone is not; ETSI
// TS 119 472-2 V1.2.1 ISO/IEC 18013-REQ-03 nevertheless names "The x5chain unprotected header
// parameter", the Annex D example does the same, and that profile governs here.
internal static class ReaderAuthentication
{
    // RFC 9360 section 2, the x5chain header parameter.
    private const int X5ChainLabel = 33;

    /// <summary>
    /// Builds the bytes readerAuth is computed over, for one docRequest.
    /// </summary>
    /// <param name="sessionTranscript">The encoded SessionTranscript, not tag-24 wrapped.</param>
    /// <param name="itemsRequestBytes">The docRequest's encoded <c>itemsRequest</c>, tag 24 included.</param>
    public static byte[] BuildBytes(byte[] sessionTranscript, byte[] itemsRequestBytes)
    {
        var auth = new CborWriter(CborConformanceMode.Lax);
        auth.WriteStartArray(3);
        auth.WriteTextString("ReaderAuthentication");
        auth.WriteEncodedValue(sessionTranscript);
        auth.WriteEncodedValue(itemsRequestBytes);
        auth.WriteEndArray();

        var outer = new CborWriter(CborConformanceMode.Lax);
        outer.WriteTag((CborTag)24);
        outer.WriteByteString(auth.Encode());
        return outer.Encode();
    }

    /// <summary>
    /// Produces the encoded <c>readerAuth</c> COSE_Sign1 for one docRequest. The algorithm goes in
    /// the protected header, the certificate path in the unprotected one, and the payload is nil.
    /// </summary>
    public static byte[] Sign(MdocReaderKey reader, byte[] sessionTranscript, byte[] itemsRequestBytes)
    {
        var chain = new CborWriter(CborConformanceMode.Lax);
        if (reader.CertificatePath.Count == 1)
        {
            chain.WriteByteString(reader.CertificatePath[0].RawData);
        }
        else
        {
            chain.WriteStartArray(reader.CertificatePath.Count);
            foreach (var certificate in reader.CertificatePath)
            {
                chain.WriteByteString(certificate.RawData);
            }

            chain.WriteEndArray();
        }

        var signer = new CoseSigner(reader.Key, reader.HashAlgorithm);
        signer.UnprotectedHeaders.Add(new CoseHeaderLabel(X5ChainLabel), CoseHeaderValue.FromEncodedValue(chain.Encode()));
        return Untagged(CoseSign1Message.SignDetached(BuildBytes(sessionTranscript, itemsRequestBytes), signer));
    }

    /// <summary>
    /// Removes the COSE_Sign1 tag (18) that .NET writes. The Annex D example's readerAuth is the
    /// bare four-element array, and at least one wallet library (multipaz, whose
    /// <c>CoseSign1.fromDataItem</c> requires an array) cannot read the tagged form at all.
    /// </summary>
    // SPEC: RFC 9052 section 4.2: COSE_Sign1 "can be encoded as either tagged or untagged depending on
    // the context it will be used in", and COSE_Sign1_Tagged = #6.18(COSE_Sign1).
    private static byte[] Untagged(byte[] coseSign1)
    {
        var reader = new CborReader(coseSign1, CborConformanceMode.Lax);
        if (reader.PeekState() == CborReaderState.Tag && reader.ReadTag() != (CborTag)18)
        {
            throw new InvalidOperationException("The platform COSE encoder wrote a tag other than COSE_Sign1's.");
        }

        return reader.ReadEncodedValue().ToArray();
    }
}
