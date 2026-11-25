namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The values of <see cref="VerificationResult.DeviceAuthentication"/> for an mdoc: the member of the response's
/// <c>DeviceAuth</c> that verified.
/// </summary>
public static class MdocDeviceAuthentication
{
    /// <summary>The device signed with the key its MSO pins (COSE_Sign1).</summary>
    public const string Signature = "deviceSignature";

    /// <summary>The device made a MAC with a key agreed between its key and the reader's (COSE_Mac0).</summary>
    public const string Mac = "deviceMac";

    /// <summary>
    /// Which member of a document's device authentication is checked, or null when it carried none. The parser
    /// refuses a document carrying both, a member twice or deviceSigned twice, so there is at most one. The one
    /// statement of that rule, for both the check (DeviceAuthVerifier) and the method a passing result reports.
    /// </summary>
    internal static string? Of(ParsedDocument document) => document.DeviceSigned switch
    {
        null => null,
        { DeviceSignature: not null } => Signature,
        { DeviceMac: not null } => Mac,
        _ => null,
    };
}
