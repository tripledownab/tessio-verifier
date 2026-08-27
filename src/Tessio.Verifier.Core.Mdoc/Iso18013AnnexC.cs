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
    /// Decrypts an <c>EncryptedResponse</c>. The HPKE keys are derived with the session transcript
    /// as <c>info</c> and no aad. Throws <see cref="AuthenticationTagMismatchException"/> when the
    /// key, the EncryptionInfo bytes or the origin do not match what the wallet sealed to.
    /// </summary>
    /// <remarks>
    /// The transcript is the plain one, whose second element is null. A wallet reached over the
    /// Digital Credentials API was observed on 2026-08-27 to derive its keys and sign device
    /// authentication over exactly that, and to produce an undecryptable response otherwise.
    /// Some implementations instead derive over a variant carrying the EncryptionParameters, which
    /// this does NOT use; the observed exchange is what governs here.
    /// </remarks>
    /// <param name="encryptedResponse">The wallet's response, decoded from base64url.</param>
    /// <param name="responseKeyPkcs8">The stored <see cref="Iso18013AnnexCRequest.ResponseKeyPkcs8"/>.</param>
    /// <param name="encryptionInfo">The stored <see cref="Iso18013AnnexCRequest.EncryptionInfo"/>, byte for byte.</param>
    /// <param name="origin">The origin the browser presented the request from.</param>
    public static Iso18013AnnexCResponse OpenResponse(
        byte[] encryptedResponse, byte[] responseKeyPkcs8, byte[] encryptionInfo, string origin)
    {
        var (enc, cipherText) = EncryptedResponse.Decode(encryptedResponse);
        var transcript = BuildSessionTranscript(encryptionInfo, origin);

        using var responseKey = ECDiffieHellman.Create();
        responseKey.ImportPkcs8PrivateKey(responseKeyPkcs8, out _);
        var deviceResponse = Hpke.Open(responseKey, enc, info: transcript, aad: [], cipherText);

        return new Iso18013AnnexCResponse
        {
            DeviceResponse = deviceResponse,
            SessionTranscript = transcript,
        };
    }

    /// <summary>
    /// The session transcript for a request: what the response's HPKE keys are derived over, and
    /// what device authentication is signed over. One construction for both, because a wallet was
    /// observed using one.
    /// </summary>
    public static byte[] BuildSessionTranscript(byte[] encryptionInfo, string origin) =>
        SessionTranscriptBuilder.BuildForIso18013AnnexC(encryptionInfo, origin);

    /// <summary>
    /// Produces the <c>EncryptedResponse</c> a wallet would return for a request: seals
    /// <paramref name="deviceResponse"/> to the request's recipient key over the session
    /// transcript, with a fresh ephemeral sender key. For tests, fixtures and mock wallets; a
    /// verifier never seals in production.
    /// </summary>
    public static byte[] SealResponse(byte[] deviceResponse, byte[] encryptionInfo, string origin)
    {
        var transcript = BuildSessionTranscript(encryptionInfo, origin);
        using var recipient = ECDiffieHellman.Create(EncryptionInfo.ReadRecipientKey(encryptionInfo));
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var (enc, cipherText) = Hpke.Seal(ephemeral, recipient, info: transcript, aad: [], deviceResponse);
        return EncryptedResponse.Encode(enc, cipherText);
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

/// <summary>An opened Annex C response: the decrypted bytes and the transcript that binds them.</summary>
public sealed record Iso18013AnnexCResponse
{
    /// <summary>
    /// The decrypted <c>DeviceResponse</c> bytes, for <see cref="DeviceResponseParser"/> and
    /// <see cref="MdocVerifier"/>.
    /// </summary>
    public required byte[] DeviceResponse { get; init; }

    /// <summary>
    /// The transcript this response is bound to. Pass it to
    /// <see cref="MdocVerificationContext.SessionTranscript"/>: the device signature covers it, and
    /// the response was decrypted with it, so a response that opened will verify against this one.
    /// </summary>
    public required byte[] SessionTranscript { get; init; }
}
