namespace Tessio.Verifier.Core.Mdoc;

// SPEC: ISO/IEC 18013-5 §8.3.2.1.2.2 — DeviceResponse structure, carried base64url-encoded in the
// OpenID4VP vp_token per OpenID4VP 1.0 Annex B.2.

/// <summary>A decoded <c>DeviceResponse</c>.</summary>
internal sealed record ParsedDeviceResponse
{
    public required string Version { get; init; }

    public required IReadOnlyList<ParsedDocument> Documents { get; init; }

    /// <summary>DeviceResponse status code; 0 is OK.</summary>
    public required long Status { get; init; }
}

/// <summary>One document inside a DeviceResponse.</summary>
internal sealed record ParsedDocument
{
    public required string DocType { get; init; }

    /// <summary>Disclosed items per namespace.</summary>
    public required IReadOnlyDictionary<string, IReadOnlyList<ParsedIssuerSignedItem>> NameSpaces { get; init; }

    /// <summary>The issuerAuth COSE_Sign1, exactly as transported.</summary>
    public required byte[] IssuerAuth { get; init; }

    public ParsedDeviceSigned? DeviceSigned { get; init; }
}

/// <summary>A disclosed IssuerSignedItem plus its exact transported encoding.</summary>
internal sealed record ParsedIssuerSignedItem
{
    public required long DigestId { get; init; }

    public required string ElementIdentifier { get; init; }

    public required object? ElementValue { get; init; }

    /// <summary>
    /// The item's <c>IssuerSignedItemBytes</c> (#6.24 tagged bytestring) exactly as transported.
    /// MSO digests are computed over these bytes, so they are hashed as received, never re-encoded.
    /// </summary>
    // SPEC: ISO/IEC 18013-5 §9.1.2.4 — digest input is IssuerSignedItemBytes.
    public required byte[] EncodedItemBytes { get; init; }
}

/// <summary>The deviceSigned part of a document (verified in the deviceAuth step).</summary>
internal sealed record ParsedDeviceSigned
{
    /// <summary>DeviceNameSpacesBytes (#6.24 tagged bytestring) exactly as transported.</summary>
    public required byte[] EncodedNameSpacesBytes { get; init; }

    /// <summary>The deviceSignature COSE_Sign1, when signature-based device auth is used.</summary>
    public byte[]? DeviceSignature { get; init; }

    /// <summary>The deviceMac COSE_Mac0, when MAC-based device auth is used.</summary>
    public byte[]? DeviceMac { get; init; }
}

/// <summary>The Mobile Security Object carried as the issuerAuth payload.</summary>
// SPEC: ISO/IEC 18013-5 §9.1.2.4 — MobileSecurityObject.
internal sealed record MobileSecurityObject
{
    public required string Version { get; init; }

    public required string DigestAlgorithm { get; init; }

    /// <summary>Digests per namespace, keyed by digestID.</summary>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<long, byte[]>> ValueDigests { get; init; }

    /// <summary>The holder's device key as encoded COSE_Key (verified in the deviceAuth step).</summary>
    public required byte[] DeviceKeyEncoded { get; init; }

    public required string DocType { get; init; }

    public required DateTimeOffset Signed { get; init; }

    public required DateTimeOffset ValidFrom { get; init; }

    public required DateTimeOffset ValidUntil { get; init; }
}
