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
    /// <remarks>
    /// The request is unsigned. ETSI TS 119 472-2 V1.2.1 ISO/IEC 18013-REQ-01 says "All the elements
    /// of the docRequests array shall contain the readerAuth member", and CIR (EU) 2026/1731 neither
    /// amends nor voids it. Its ISO/IEC 18013-7-API-01 has Annex C presentations comply "as further
    /// profiled in clauses 5.3 and 5.4", although its clause 5.1 calls clause 5.3 specific to the
    /// non-API mechanism. Read either way, a signed request meets it: for an EUDI Wallet, use
    /// <see cref="CreateSignedRequest"/>.
    /// </remarks>
    public static Iso18013AnnexCRequest CreateRequest(
        string docType, string nameSpace, IReadOnlyList<string> elementIdentifiers) =>
        // This seam never retains disclosed elements, so IntentToRetain is always false here.
        // DeviceRequestBuilder exposes the flag for callers that do retain.
        Create(_ => DeviceRequestBuilder.Build(docType, nameSpace, elementIdentifiers, intentToRetain: false));

    /// <summary>
    /// Builds the request pair with the docRequest signed by <paramref name="reader"/>, so the wallet
    /// can authenticate the reader. Otherwise as <see cref="CreateRequest"/>.
    /// </summary>
    /// <remarks>
    /// The signature covers the session transcript, which commits to this request's EncryptionInfo
    /// and to <paramref name="origin"/>. A wallet reached from any other origin computes another
    /// transcript, and the signature does not verify there.
    /// </remarks>
    /// <param name="docType">The requested document type.</param>
    /// <param name="nameSpace">The namespace the elements live in.</param>
    /// <param name="elementIdentifiers">The elements to request.</param>
    /// <param name="origin">
    /// The origin of the page that will make the browser call, serialized as the browser reports it,
    /// for example <c>https://verifier.example.com</c>: no <c>origin:</c> prefix, no trailing slash or
    /// path, a lower-case ASCII host (punycode for an internationalised name), no default port; or an
    /// Android app's <c>android:apk-key-hash:</c> origin. The usual mistakes (a missing scheme, a
    /// trailing slash, upper case, a default port) are refused, because the wallet would compute a
    /// different transcript and the signature would not verify. The check is a syntactic guard, not a
    /// URL parser: a few strings no browser reports, such as non-canonical IPv4, still pass it and
    /// fail at the wallet instead.
    /// </param>
    /// <param name="reader">The reader key and certificate path to sign with.</param>
    /// <param name="registrationCertificate">
    /// The relying party's registration certificate, exactly as issued, carried in the
    /// ItemsRequest's <c>requestInfo</c> under <c>euWrprc</c>, inside the signed bytes. Null for
    /// none, which CIR (EU) 2026/1731 does not allow in a request to an EUDI Wallet (its
    /// ISO/IEC 18013-5-REQ-04 and -REQ-06). Its REQ-07 asks for "a CBOR-encoded registration
    /// certificate", which read plainly means the CWT form of the two ETSI TS 119 475 allows. The
    /// bytes are passed through unchanged: which form they are is not checked here.
    /// </param>
    public static Iso18013AnnexCRequest CreateSignedRequest(
        string docType,
        string nameSpace,
        IReadOnlyList<string> elementIdentifiers,
        string origin,
        MdocReaderKey reader,
        byte[]? registrationCertificate)
    {
        BrowserOrigin.RequireSerialized(origin);
        return Create(encryptionInfo => DeviceRequestBuilder.BuildSigned(
            docType,
            nameSpace,
            elementIdentifiers,
            intentToRetain: false,
            BuildSessionTranscript(encryptionInfo, origin),
            reader,
            registrationCertificate));
    }

    /// <summary>
    /// Mints the response key and EncryptionInfo, then builds the DeviceRequest from them. In that
    /// order because a signed request covers the EncryptionInfo bytes through the transcript.
    /// </summary>
    private static Iso18013AnnexCRequest Create(Func<byte[], byte[]> buildDeviceRequest)
    {
        using var responseKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var encryptionInfo = EncryptionInfo.Encode(
            RandomNumberGenerator.GetBytes(EncryptionInfo.NonceLength),
            responseKey.ExportParameters(includePrivateParameters: false));

        return new Iso18013AnnexCRequest
        {
            DeviceRequest = buildDeviceRequest(encryptionInfo),
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
    /// Encoded <c>EncryptionInfo</c>; base64url this, unpadded, into the API request's
    /// <c>encryptionInfo</c>. Wallets hash the string the page sends into the session transcript,
    /// and this library hashes the unpadded form, so padding breaks decryption and readerAuth alike.
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
