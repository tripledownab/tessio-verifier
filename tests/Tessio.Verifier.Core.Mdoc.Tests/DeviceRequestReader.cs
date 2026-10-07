// What belongs in this file: test-side decoding of an encoded DeviceRequest, written independently of
// DeviceRequestBuilder so a test reads what was actually emitted rather than what the builder meant.
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>Reads the parts of a single-document DeviceRequest that tests assert on.</summary>
internal static class DeviceRequestReader
{
    /// <summary>
    /// The one docRequest's <c>itemsRequest</c> as encoded (tag 24 included, the bytes readerAuth
    /// covers) and its <c>readerAuth</c> as encoded, or null when the request is unsigned.
    /// </summary>
    public static (byte[] ItemsRequest, byte[]? ReaderAuth) ReadSingleDocRequest(byte[] deviceRequest)
    {
        var reader = new CborReader(deviceRequest, CborConformanceMode.Lax);
        byte[]? itemsRequest = null;
        byte[]? readerAuth = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.ReadTextString() != "docRequests")
            {
                reader.SkipValue();
                continue;
            }

            Assert.Equal(1, reader.ReadStartArray());
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                switch (reader.ReadTextString())
                {
                    case "itemsRequest":
                        itemsRequest = reader.ReadEncodedValue().ToArray();
                        break;
                    case "readerAuth":
                        readerAuth = reader.ReadEncodedValue().ToArray();
                        break;
                    default:
                        Assert.Fail("A docRequest holds only itemsRequest and readerAuth.");
                        break;
                }
            }

            reader.ReadEndMap();
            reader.ReadEndArray();
        }

        reader.ReadEndMap();
        Assert.Equal(0, reader.BytesRemaining);
        Assert.NotNull(itemsRequest);
        return (itemsRequest, readerAuth);
    }

    /// <summary>
    /// The ItemsRequest's <c>requestInfo</c> map, key to encoded value, or null when it has none.
    /// </summary>
    public static Dictionary<string, byte[]>? ReadRequestInfo(byte[] itemsRequestBytes)
    {
        var outer = new CborReader(itemsRequestBytes, CborConformanceMode.Lax);
        Assert.Equal((CborTag)24, outer.ReadTag());
        var reader = new CborReader(outer.ReadByteString(), CborConformanceMode.Lax);
        Dictionary<string, byte[]>? requestInfo = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.ReadTextString() != "requestInfo")
            {
                reader.SkipValue();
                continue;
            }

            requestInfo = [];
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                requestInfo[reader.ReadTextString()] = reader.ReadEncodedValue().ToArray();
            }

            reader.ReadEndMap();
        }

        return requestInfo;
    }

    /// <summary>A reader positioned on a COSE_Sign1's unprotected x5chain header (label 33).</summary>
    public static CborReader ReadX5Chain(CoseSign1Message message) =>
        new(message.UnprotectedHeaders[new CoseHeaderLabel(33)].EncodedValue, CborConformanceMode.Lax);
}
