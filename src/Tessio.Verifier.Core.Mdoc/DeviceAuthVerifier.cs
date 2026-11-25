using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies the holder's device authentication: the <c>deviceSignature</c> COSE_Sign1 whose
/// detached payload is <c>DeviceAuthenticationBytes</c> over the session transcript, verified with
/// the device key pinned in the MSO, or the <c>deviceMac</c> over the same bytes
/// (<see cref="DeviceMacVerifier"/>). This is the mdoc analogue of the KB-JWT: it proves the wallet
/// that responded holds the key the issuer bound the credential to, for exactly this request.
/// </summary>
// SPEC: ISO/IEC 18013-5 §9.1.3.4 —
//   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
//   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
internal static class DeviceAuthVerifier
{
    // The protected header label this verifier processes, alg, the only one a crit header may name.
    private static readonly int[] UnderstoodLabels = [1];

    /// <param name="document">The presented document.</param>
    /// <param name="mso">Its Mobile Security Object, which pins the device key.</param>
    /// <param name="sessionTranscript">The transcript the device authenticated, bare rather than tag-24 wrapped.</param>
    /// <param name="macKeys">The reader key for a deviceMac, or null.</param>
    /// <param name="acceptDeviceMac">Whether a deviceMac is checked at all (<see cref="MdocVerifierOptions.AcceptDeviceMac"/>).</param>
    public static List<VerificationError> Verify(
        ParsedDocument document,
        MobileSecurityObject mso,
        byte[] sessionTranscript,
        MdocMacKeySource? macKeys,
        bool acceptDeviceMac)
    {
        if (document.DeviceSigned is not { } deviceSigned)
        {
            return [Error("The document carries no deviceSigned structure; device authentication is required.")];
        }

        var deviceAuthenticationBytes = SessionTranscriptBuilder.BuildDeviceAuthenticationBytes(
            sessionTranscript, document.DocType, deviceSigned.EncodedNameSpacesBytes);

        // Which member is checked is decided by MdocDeviceAuthentication.Of, the same rule a passing result reports
        // the method by, so the two cannot disagree.
        var method = MdocDeviceAuthentication.Of(document);
        if (method is null)
        {
            return [Error("The document carries neither a deviceSignature nor a deviceMac.")];
        }

        if (method == MdocDeviceAuthentication.Mac)
        {
            var deviceMac = deviceSigned.DeviceMac!;
            return acceptDeviceMac
                ? DeviceMacVerifier.Verify(deviceMac, mso, sessionTranscript, deviceAuthenticationBytes, macKeys)
                : [Error("The document authenticates with deviceMac, which this verifier does not accept "
                    + "(MdocVerifierOptions.AcceptDeviceMac is off).")];
        }

        if (CoseSign1Verification.Decode(deviceSigned.DeviceSignature!, out var problem) is not { } message)
        {
            return [Error($"The deviceSignature is not a valid COSE_Sign1: {problem}")];
        }

        try
        {
            // The signed bytes are DeviceAuthentication, which the verifier rebuilds from this request, so the
            // signature is checked detached. One carrying a payload of its own is not that signature.
            if (message.Content is not null)
            {
                return [Error("The deviceSignature carries its payload; it must be detached.")];
            }

            if (!CoseSign1Verification.CriticalHeadersUnderstood(message, UnderstoodLabels))
            {
                return [Error("The deviceSignature marks a header critical that this verifier does not process.")];
            }

            using var deviceKey = ECDsa.Create(CoseKey.ReadEc2PublicKey(mso.DeviceKeyEncoded));
            if (!CoseSign1Verification.VerifyDetached(message, deviceKey, deviceAuthenticationBytes, UnderstoodLabels))
            {
                return [Error("The deviceSignature does not verify over this request's session transcript.")];
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or MdocProcessingException)
        {
            return [Error($"Device authentication could not be verified: {e.Message}")];
        }

        return [];
    }

    private static VerificationError Error(string message) =>
        new() { Code = MdocErrorCodes.DeviceAuthInvalid, Message = message };
}
