using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The verifier's side of an ISO/IEC 18013-7 Annex C presentation over the W3C Digital
/// Credentials API: builds the request pair the browser call carries, and opens the encrypted
/// response into <c>DeviceResponse</c> bytes plus the session transcripts device authentication
/// is verified over. Verification itself stays in <see cref="MdocVerifier"/>.
/// </summary>
public static class Iso18013AnnexC
{
    /// <summary>
    /// Builds the <c>{deviceRequest, encryptionInfo}</c> pair and the response key for one
    /// request. The key is fresh per request and must never be reused: a stable advertised key
    /// would let colluding verifiers correlate the people presenting to it.
    /// </summary>
    public static Iso18013AnnexCRequest CreateRequest(
        string docType, string nameSpace, IReadOnlyList<string> elementIdentifiers)
    {
        // This seam never retains disclosed elements, so IntentToRetain is always false here.
        // DeviceRequestBuilder exposes the flag for callers that do retain.
        var deviceRequest = DeviceRequestBuilder.Build(docType, nameSpace, elementIdentifiers, intentToRetain: false);

        using var responseKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var encryptionInfo = EncryptionInfo.Encode(
            RandomNumberGenerator.GetBytes(EncryptionInfo.NonceLength),
            responseKey.ExportParameters(includePrivateParameters: false));

        return new Iso18013AnnexCRequest
        {
            DeviceRequest = deviceRequest,
            EncryptionInfo = encryptionInfo,
            ResponseKeyPkcs8 = responseKey.ExportPkcs8PrivateKey(),
        };
    }

    /// <summary>
    /// Decrypts an <c>EncryptedResponse</c>. The HPKE keys are derived with the encryption
    /// session transcript as <c>info</c> and no aad, the reference implementations' construction.
    /// Throws <see cref="AuthenticationTagMismatchException"/> when the key, the EncryptionInfo
    /// bytes or the origin do not match what the wallet sealed to.
    /// </summary>
    /// <param name="encryptedResponse">The wallet's response, decoded from base64url.</param>
    /// <param name="responseKeyPkcs8">The stored <see cref="Iso18013AnnexCRequest.ResponseKeyPkcs8"/>.</param>
    /// <param name="encryptionInfo">The stored <see cref="Iso18013AnnexCRequest.EncryptionInfo"/>, byte for byte.</param>
    /// <param name="origin">The origin the browser presented the request from.</param>
    public static Iso18013AnnexCResponse OpenResponse(
        byte[] encryptedResponse, byte[] responseKeyPkcs8, byte[] encryptionInfo, string origin)
    {
        var (enc, cipherText) = EncryptedResponse.Decode(encryptedResponse);
        var parameters = EncryptionInfo.ExtractEncryptionParameters(encryptionInfo);
        var encryptionTranscript = SessionTranscriptBuilder.BuildForIso18013AnnexC(encryptionInfo, origin, parameters);

        using var responseKey = ECDiffieHellman.Create();
        responseKey.ImportPkcs8PrivateKey(responseKeyPkcs8, out _);
        var deviceResponse = Hpke.Open(responseKey, enc, info: encryptionTranscript, aad: [], cipherText);

        return new Iso18013AnnexCResponse
        {
            DeviceResponse = deviceResponse,
            EncryptionSessionTranscript = encryptionTranscript,
            SessionTranscript = SessionTranscriptBuilder.BuildForIso18013AnnexC(
                encryptionInfo, origin, encryptionParameters: null),
        };
    }
}

/// <summary>What the browser call carries, and what the verifier keeps to open the answer.</summary>
public sealed record Iso18013AnnexCRequest
{
    /// <summary>Encoded <c>DeviceRequest</c>; base64url this into the API request's <c>deviceRequest</c>.</summary>
    public required byte[] DeviceRequest { get; init; }

    /// <summary>
    /// Encoded <c>EncryptionInfo</c>; base64url this into the API request's <c>encryptionInfo</c>.
    /// Store the exact bytes: the session transcript digest covers them.
    /// </summary>
    public required byte[] EncryptionInfo { get; init; }

    /// <summary>
    /// The PKCS#8 private key the wallet encrypts its response to. Store it with the session and
    /// pass it to <see cref="Iso18013AnnexC.OpenResponse"/>.
    /// </summary>
    public required byte[] ResponseKeyPkcs8 { get; init; }
}

/// <summary>An opened Annex C response: the decrypted bytes and the transcripts.</summary>
public sealed record Iso18013AnnexCResponse
{
    /// <summary>
    /// The decrypted <c>DeviceResponse</c> bytes, for <see cref="DeviceResponseParser"/> and
    /// <see cref="MdocVerifier"/>.
    /// </summary>
    public required byte[] DeviceResponse { get; init; }

    /// <summary>
    /// The transcript whose second element carries the tag-24 EncryptionParameters. The response's
    /// HPKE keys are derived over it, and the reference implementations verify device
    /// authentication over it: pass it to <see cref="MdocVerificationContext.SessionTranscript"/>.
    /// </summary>
    public required byte[] EncryptionSessionTranscript { get; init; }

    /// <summary>
    /// The base transcript, second element null, the form the profile's examples print for the
    /// response. Kept alongside because published examples and reference code differ on which form
    /// device authentication signs; verify over <see cref="EncryptionSessionTranscript"/> first.
    /// </summary>
    public required byte[] SessionTranscript { get; init; }
}
