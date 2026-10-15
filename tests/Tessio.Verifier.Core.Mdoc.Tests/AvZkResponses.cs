using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Builds a DeviceResponse carrying the Annex A, A.11 zero knowledge presentation, with knobs to break it.
/// Without <see cref="AvZkShape.Proof"/> the proof bytes are a placeholder. Shared with the zero knowledge
/// package's tests. Its writers are lax so that a test can write what a hostile wallet would, such as text that
/// is not valid UTF-8.
/// </summary>
internal static class AvZkResponses
{
    public static byte[] Build(AvZkShape? shape = null)
    {
        shape ??= new AvZkShape();
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(3);
        writer.WriteTextString("version");
        writer.WriteTextString("1.0");
        writer.WriteTextString("zkDocuments");
        writer.WriteStartArray(shape.Presentations);
        for (var p = 0; p < shape.Presentations; p++)
        {
            writer.WriteStartMap(2);
            writer.WriteTextString("proof");
            writer.WriteByteString(shape.Proof ?? [0x01, 0x02, 0x03]);
            writer.WriteTextString("documentData");
            writer.WriteTag(CborTag.EncodedCborDataItem);
            writer.WriteByteString(DocumentData(shape));
            writer.WriteEndMap();
        }

        writer.WriteEndArray();
        writer.WriteTextString("status");
        writer.WriteInt32(0);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] DocumentData(AvZkShape shape)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(shape.Chain is null ? 5 : 6);
        writer.WriteTextString("zkSystemId");
        writer.WriteTextString(shape.ZkSystemId);
        writer.WriteTextString("docType");
        writer.WriteTextString(shape.DocType);
        writer.WriteTextString("timestamp");
        writer.WriteTag(CborTag.DateTimeString);
        writer.WriteTextString(shape.Timestamp);
        writer.WriteTextString("issuerSigned");
        writer.WriteStartMap(shape.SecondNamespace ? 2 : 1);
        WriteItems(writer, AvZkVectors.DocType, shape);
        if (shape.SecondNamespace)
        {
            WriteItems(writer, "org.iso.18013.5.1", shape);
        }

        writer.WriteEndMap();
        writer.WriteTextString("deviceSigned");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        if (shape.Chain is { } chain)
        {
            writer.WriteTextString("msoX5chain");
            writer.WriteByteString(chain);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static void WriteItems(CborWriter writer, string nameSpace, AvZkShape shape)
    {
        writer.WriteTextString(nameSpace);
        writer.WriteStartArray(shape.Items);
        for (var i = 0; i < shape.Items; i++)
        {
            writer.WriteStartMap(2);
            writer.WriteTextString("elementIdentifier");
            writer.WriteTextString(i == 0 || shape.SameIdentifier ? "age_over_18" : $"age_over_{20 + i}");
            writer.WriteTextString("elementValue");
            (shape.Value ?? (w => w.WriteBoolean(true)))(writer);
            writer.WriteEndMap();
        }

        writer.WriteEndArray();
    }
}

/// <summary>What <see cref="AvZkResponses.Build"/> writes; each default is the A.11 example's.</summary>
internal sealed record AvZkShape
{
    public string ZkSystemId { get; init; } = AvZkVectors.ZkSystemId;

    public string DocType { get; init; } = AvZkVectors.DocType;

    public string Timestamp { get; init; } = AvZkVectors.Timestamp;

    public int Items { get; init; } = 1;

    public int Presentations { get; init; } = 1;

    public bool SameIdentifier { get; init; }

    public bool SecondNamespace { get; init; }

    /// <summary>The msoX5chain; null leaves the member out.</summary>
    public byte[]? Chain { get; init; } = AvZkVectors.DocumentSignerCertificate;

    /// <summary>Writes each disclosed item's value; true when null.</summary>
    public Action<CborWriter>? Value { get; init; }

    public byte[]? Proof { get; init; }
}
