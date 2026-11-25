// What belongs in this file: mdoc answers that authenticate with deviceMac, for a host's tests of what it does with
// one (a host recording which device authentication verified, say) as much as for this repository's own.
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Testing;

public sealed partial class MockWalletResponses
{
    /// <summary>
    /// An encrypted <c>direct_post.jwt</c> answer to a redirect session whose mdoc authenticates with deviceMac,
    /// keyed to the encryption key the session's request published, as a wallet would key it.
    /// </summary>
    public WalletResponseData CreateEncryptedMdocMacResponse(
        VerificationSession session, string docType = EuAgeVerificationDocType, string? mdocNamespace = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        var recipientJwkJson = RequestParameters.TryGetEncryptionJwkJson(session.Request)
            ?? throw new InvalidOperationException("The session published no encryption key, so a deviceMac has no reader key.");
        var transcript = SessionTranscriptBuilder.Build(
            session.Request.ClientId,
            session.Request.Nonce,
            RequestParameters.TryGetEncryptionKeyThumbprint(session.Request),
            RequestParameters.TryGetResponseUri(session.Request)
                ?? throw new InvalidOperationException("The session's request carries no response_uri."));
        var deviceResponse = _mdocIssuer.IssueDeviceResponseOverTranscript(
            ["age_over_18"], docType, mdocNamespace ?? docType, transcript, macReaderKey: ReaderKeyOf(recipientJwkJson));

        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = new Dictionary<string, string[]> { ["credential"] = [deviceResponse] },
            ["state"] = session.Request.State ?? string.Empty,
        });
        return new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["response"] = new[] { EcdhEsJweEncryptor.Encrypt(payload, recipientJwkJson) },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
    }

    /// <summary>
    /// An answer to a Digital Credentials API request whose mdoc authenticates with deviceMac. Keyed to the key the
    /// request published, or to <paramref name="readerKey"/> when given, for a request that published none.
    /// </summary>
    public string CreateDcApiMdocMacResponse(DcApiPresentationRequest request, string origin, ECParameters? readerKey = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var encrypted = RequestParameters.AsksForEncryptedResponse(request);
        var transcript = SessionTranscriptBuilder.BuildForDcApi(
            origin, request.Nonce, encrypted ? RequestParameters.TryGetEncryptionKeyThumbprint(request) : null);
        var key = readerKey
            ?? (RequestParameters.TryGetEncryptionJwkJson(request) is { } jwkJson
                ? ReaderKeyOf(jwkJson)
                : throw new InvalidOperationException("The request published no key; pass the reader key to MAC with."));
        var deviceResponse = _mdocIssuer.IssueDeviceResponseOverTranscript(
            ["age_over_18"], EuAgeVerificationDocType, EuAgeVerificationDocType, transcript, macReaderKey: key);
        return DcApiData(request, deviceResponse);
    }

    private static ECParameters ReaderKeyOf(string jwkJson)
    {
        var jwk = new JsonWebKey(jwkJson);
        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64UrlEncoder.DecodeBytes(jwk.X), Y = Base64UrlEncoder.DecodeBytes(jwk.Y) },
        };
    }
}
