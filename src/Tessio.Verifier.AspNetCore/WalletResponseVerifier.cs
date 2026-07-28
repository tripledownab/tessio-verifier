using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Default <see cref="IWalletResponseVerifier"/>. Parses a wallet response format-aware (from the session's
/// request), then verifies each credential with expectations derived from that same request — audience from
/// <c>client_id</c>, nonce, and the requested <c>vct</c> / docType — rather than from the process-wide
/// <see cref="VerifierOptions"/>. Verifying against the session's own <c>client_id</c> is what makes the seam
/// multi-tenant correct, and it also closes the app-wide-audience gap for the built-in callback endpoint,
/// which routes through <see cref="VerifyParsedAsync"/>.
/// </summary>
public sealed class WalletResponseVerifier : IWalletResponseVerifier
{
    // SPEC: SD-JWT VC format identifier; the default when a request carries no parseable DCQL format.
    private const string DefaultCredentialFormat = "dc+sd-jwt";

    private readonly ICredentialVerifier _verifier;
    private readonly MdocVerifier _mdocVerifier;
    private readonly ResponseEncryptionKeyProvider _encryptionKeys;

    /// <summary>Creates a verifier over the SD-JWT VC and mdoc credential verifiers.</summary>
    public WalletResponseVerifier(
        ICredentialVerifier verifier, MdocVerifier mdocVerifier, ResponseEncryptionKeyProvider encryptionKeys)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(mdocVerifier);
        ArgumentNullException.ThrowIfNull(encryptionKeys);
        _verifier = verifier;
        _mdocVerifier = mdocVerifier;
        _encryptionKeys = encryptionKeys;
    }

    /// <inheritdoc />
    public async Task<VerificationResult> VerifyAsync(
        VerificationSession session, WalletResponseData response, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(response);

        ParsedWalletResponse parsed;
        try
        {
            // Format comes from the session's own request, not a process-wide pin, so one process can
            // parse both SD-JWT and mdoc tenants. Decryption uses the app-wide response key (see remarks
            // on IWalletResponseVerifier for the encrypted-multi-tenant caveat).
            var parser = new WalletResponseParser(new WalletResponseParserOptions
            {
                ResponseDecryptionKey = _encryptionKeys.DecryptionKey,
                PresentationFormat = RequestObjectPayload.TryGetRequestedFormat(session.Request.SignedRequestObject)
                    ?? DefaultCredentialFormat,
            });
            parsed = await parser.ParseDetailedAsync(response, ct).ConfigureAwait(false);
        }
        catch (WalletResponseException e)
        {
            return VerificationResult.Invalid(new VerificationError
            {
                Code = "response_invalid",
                Message = e.Message,
            });
        }

        return await VerifyParsedAsync(session, parsed, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies an already-parsed response. Used by the built-in callback endpoint, which parses first to
    /// correlate the session by <c>state</c>. Derives every expectation from the session's request.
    /// </summary>
    internal async Task<VerificationResult> VerifyParsedAsync(
        VerificationSession session, ParsedWalletResponse response, CancellationToken ct)
    {
        // Transaction data is bound into the request object; the KB-JWT must acknowledge these exact bytes.
        var transactionData = RequestObjectPayload.TryGetTransactionData(session.Request.SignedRequestObject) is { } tds
            ? new TransactionDataExpectation { TransactionData = tds }
            : null;

        VerificationResult? first = null;
        foreach (var credential in response.Credentials)
        {
            var result = string.Equals(credential.Format, MdocVerifier.Format, StringComparison.Ordinal)
                ? await _mdocVerifier.VerifyAsync(credential, BuildMdocContext(session), ct).ConfigureAwait(false)
                : await VerifySdJwtAsync(credential, session, transactionData, ct).ConfigureAwait(false);

            if (!result.IsValid)
            {
                return result; // Session completes with the first failure.
            }

            first ??= result;
        }

        // A response the parser accepted but that carries no credentials cannot be verified.
        return first ?? VerificationResult.Invalid(new VerificationError
        {
            Code = "no_credentials",
            Message = "The wallet response contained no credentials to verify.",
        });
    }

    private async Task<VerificationResult> VerifySdJwtAsync(
        PresentedCredential credential,
        VerificationSession session,
        TransactionDataExpectation? transactionData,
        CancellationToken ct)
    {
        var context = new VerificationContext
        {
            // Audience and nonce come from the session's own request, not app-wide options: in a
            // multi-tenant process each session was issued under its tenant's client_id.
            Nonce = session.Request.Nonce,
            Audience = session.Request.ClientId,
            ExpectedVct = RequestObjectPayload.TryGetExpectedVct(session.Request.SignedRequestObject),
        };

        // Only the concrete SD-JWT verifier carries the transaction-data overload; fall back for any
        // custom ICredentialVerifier a host has registered.
        return _verifier is SdJwtVcVerifier sdJwt
            ? await sdJwt.VerifyAsync(credential, context, transactionData, ct).ConfigureAwait(false)
            : await _verifier.VerifyAsync(credential, context, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The mdoc device signature covers the session transcript: this request's client_id and nonce, the
    /// thumbprint of the encryption key the wallet encrypted to (only for encrypted <c>direct_post.jwt</c>
    /// responses) and the response_uri, all read from the session's request.
    /// </summary>
    private MdocVerificationContext BuildMdocContext(VerificationSession session)
    {
        var encrypted = string.Equals(
            RequestObjectPayload.TryGetResponseMode(session.Request.SignedRequestObject),
            "direct_post.jwt",
            StringComparison.Ordinal);

        return new MdocVerificationContext
        {
            ExpectedDocType = RequestObjectPayload.TryGetExpectedDocType(session.Request.SignedRequestObject),
            ClientId = session.Request.ClientId,
            Nonce = session.Request.Nonce,
            EncryptionKeyThumbprint = encrypted ? _encryptionKeys.ThumbprintBytes : null,
            ResponseUri = RequestObjectPayload.TryGetResponseUri(session.Request.SignedRequestObject),
        };
    }
}
