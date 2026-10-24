using Microsoft.IdentityModel.Tokens;
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
/// which routes through <see cref="VerifyParsedAsync"/>. A response returned through the Digital Credentials
/// API is verified by <see cref="VerifyDcApiAsync"/>, with the same checks bound to the page's origin instead
/// of a <c>client_id</c>.
/// </summary>
public sealed partial class WalletResponseVerifier : IWalletResponseVerifier
{
    // SPEC: SD-JWT VC format identifier; the default when a request carries no parseable DCQL format.
    private const string DefaultCredentialFormat = "dc+sd-jwt";

    private readonly ICredentialVerifier _verifier;
    private readonly MdocVerifier _mdocVerifier;
    private readonly ResponseEncryptionKeyStore _encryptionKeys;
    private readonly TimeProvider _clock;

    /// <summary>Creates a verifier over the SD-JWT VC and mdoc credential verifiers, on the system clock.</summary>
    public WalletResponseVerifier(
        ICredentialVerifier verifier, MdocVerifier mdocVerifier, ResponseEncryptionKeyStore encryptionKeys)
        : this(verifier, mdocVerifier, encryptionKeys, TimeProvider.System)
    {
    }

    /// <summary>
    /// Creates a verifier over the SD-JWT VC and mdoc credential verifiers. <paramref name="clock"/> decides when a
    /// Digital Credentials API request has expired.
    /// </summary>
    public WalletResponseVerifier(
        ICredentialVerifier verifier, MdocVerifier mdocVerifier, ResponseEncryptionKeyStore encryptionKeys, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(mdocVerifier);
        ArgumentNullException.ThrowIfNull(encryptionKeys);
        ArgumentNullException.ThrowIfNull(clock);
        _verifier = verifier;
        _mdocVerifier = mdocVerifier;
        _encryptionKeys = encryptionKeys;
        _clock = clock;
    }

    /// <summary>
    /// Whether a stored request still carries the DCQL query verification checks a response against. It
    /// is a check on the request being present and readable, not on every parameter in it: a request that
    /// passes here can still be missing a <c>response_uri</c>, and an mdoc response would then fail
    /// device authentication.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For a host that persists sessions itself. A request delivers its parameters either as claims in
    /// its signed request object or as plain query parameters, and rows written before a host persisted
    /// either one have neither. Call this first and refuse such a session.
    /// </para>
    /// <para>
    /// Verifying one instead does not fail cleanly, it fails in two different wrong ways. The audience
    /// and nonce still hold, because those come from the session rather than from the request, but the
    /// credential type goes unchecked: no expected type skips the type comparison
    /// (<c>SdJwtVcVerifier</c>) and a null <c>ExpectedDocType</c> skips the document-type comparison
    /// (<c>MdocVerifier</c>), so a credential of the wrong type passes. Meanwhile an mdoc response fails
    /// device authentication, because the transcript it signs covers a response_uri this session can no
    /// longer produce. Neither outcome tells the caller what actually went wrong.
    /// </para>
    /// </remarks>
    public static bool CanVerify(PresentationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return RequestParameters.AreRecoverable(request);
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
            // Decryption resolves the session's own ephemeral key by the kid the wallet echoes, so multiple
            // tenants and multiple in-flight requests each get their own key rather than one shared one.
            var parser = ParserFor(RequestParameters.TryGetRequestedFormat(session.Request), _encryptionKeys.DecryptionKeyFor);
            parsed = await parser.ParseDetailedAsync(response, ct).ConfigureAwait(false);
        }
        catch (WalletResponseException e)
        {
            return ResponseInvalid(e.Message);
        }

        return await VerifyParsedAsync(session, parsed, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The parser for one request's response. The format comes from the request itself, not a process-wide pin,
    /// so one process can parse both SD-JWT and mdoc tenants. Error responses are read, because
    /// <see cref="VerifyAgainstAsync"/> reads Error before the credentials.
    /// </summary>
    private static WalletResponseParser ParserFor(string? requestedFormat, Func<string?, SecurityKey?>? decryptionKeys) =>
        new(new WalletResponseParserOptions
        {
            ResponseDecryptionKeyResolver = decryptionKeys,
            PresentationFormat = requestedFormat ?? DefaultCredentialFormat,
            ReadErrorResponses = true,
        });

    /// <summary>A response this verifier could not read: malformed, undecryptable or not in the mode asked for.</summary>
    private static VerificationResult ResponseInvalid(string message) => Invalid("response_invalid", message);

    private static VerificationResult Invalid(string code, string message) =>
        VerificationResult.Invalid(new VerificationError { Code = code, Message = message });

    /// <summary>
    /// Verifies an already-parsed response. Used by the built-in callback endpoint, which parses first to
    /// correlate the session by <c>state</c>. Derives every expectation from the session's request.
    /// </summary>
    internal Task<VerificationResult> VerifyParsedAsync(
        VerificationSession session, ParsedWalletResponse response, CancellationToken ct) =>
        VerifyAgainstAsync(() => Expectations.For(session), response, ct);

    /// <summary>
    /// Checks a parsed response against the expectations <paramref name="expectationsOf"/> builds from its request,
    /// which is called only after a wallet error has been answered.
    /// </summary>
    private async Task<VerificationResult> VerifyAgainstAsync(
        Func<Expectations> expectationsOf, ParsedWalletResponse response, CancellationToken ct)
    {
        // A wallet's error response is its answer, and there is nothing to verify in it. Without this it would
        // fall through to "no credentials" below, which misdescribes it.
        if (response.Error is { } walletError)
        {
            return VerificationResult.Invalid(new VerificationError
            {
                Code = ErrorCodes.WalletError,
                Message = $"The wallet answered with an Authorization Error Response: {walletError}.",
            });
        }

        // The request is read only from here on, and each format's expectations only in its own branch: a request
        // a host stored in a shape these readers cannot take must not turn a wallet's decline into an exception,
        // nor an SD-JWT answer into a failure over an mdoc-only parameter.
        var expected = expectationsOf();
        var transactionData = expected.TransactionData();

        VerificationResult? first = null;
        foreach (var credential in response.Credentials)
        {
            var result = string.Equals(credential.Format, MdocVerifier.Format, StringComparison.Ordinal)
                ? await _mdocVerifier.VerifyAsync(credential, expected.Mdoc(), ct).ConfigureAwait(false)
                : await VerifySdJwtAsync(credential, expected, transactionData, ct).ConfigureAwait(false);

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
        Expectations expected,
        TransactionDataExpectation? transactionData,
        CancellationToken ct)
    {
        var vctValues = expected.VctValues();
        var context = new VerificationContext
        {
            Nonce = expected.Nonce,
            Audience = expected.Audience,
            // Both properties, from the one array. ExpectedVctValues is what SdJwtVcVerifier reads.
            // ExpectedVct is set too, so a host-registered ICredentialVerifier that knows only the
            // older property still compares against a type instead of silently skipping its check.
            ExpectedVct = vctValues?[0],
            ExpectedVctValues = vctValues,
        };

        // Only the concrete SD-JWT verifier carries the transaction-data overload; fall back for any
        // custom ICredentialVerifier a host has registered.
        return _verifier is SdJwtVcVerifier sdJwt
            ? await sdJwt.VerifyAsync(credential, context, transactionData, ct).ConfigureAwait(false)
            : await _verifier.VerifyAsync(credential, context, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// What a response must match, read from the request it answers: one shape for both transports, so a
    /// redirect response and a Digital Credentials API response are checked by the same code. The parts read
    /// from the request are deferred, so <see cref="VerifyAgainstAsync"/> reads each only where it is needed.
    /// </summary>
    /// <param name="Nonce">The request's nonce.</param>
    /// <param name="Audience">The audience a Key Binding JWT must name.</param>
    /// <param name="VctValues">
    /// Every SD-JWT VC type the query accepts: the whole array, because one DCQL entry may offer several types
    /// and the wallet may answer with any of them.
    /// </param>
    /// <param name="TransactionData">
    /// Transaction data bound into the request, whose exact bytes the Key Binding JWT must acknowledge.
    /// </param>
    /// <param name="Mdoc">The mdoc expectations, including what the device signature's transcript covers.</param>
    private sealed record Expectations(
        string Nonce,
        string Audience,
        Func<IReadOnlyList<string>?> VctValues,
        Func<TransactionDataExpectation?> TransactionData,
        Func<MdocVerificationContext> Mdoc)
    {
        /// <summary>
        /// A redirect session's expectations. Audience and nonce come from the session's own request, not
        /// app-wide options: in a multi-tenant process each session was issued under its tenant's client_id.
        /// </summary>
        public static Expectations For(VerificationSession session) => new(
            session.Request.Nonce,
            session.Request.ClientId,
            () => RequestParameters.TryGetExpectedVctValues(session.Request),
            () => TransactionDataOf(RequestParameters.TryGetTransactionData(session.Request)),
            () => BuildMdocContext(session));

        public static TransactionDataExpectation? TransactionDataOf(IReadOnlyList<string>? transactionData) =>
            transactionData is null ? null : new TransactionDataExpectation { TransactionData = transactionData };
    }

    /// <summary>
    /// The mdoc device signature covers the session transcript: this request's client_id and nonce, the
    /// thumbprint of the encryption key the wallet encrypted to (only for encrypted <c>direct_post.jwt</c>
    /// responses) and the response_uri, all read from the session's request.
    /// </summary>
    private static MdocVerificationContext BuildMdocContext(VerificationSession session)
    {
        var encrypted = RequestParameters.AsksForEncryptedResponse(session.Request);

        return new MdocVerificationContext
        {
            ExpectedDocType = RequestParameters.TryGetExpectedDocType(session.Request),
            ClientId = session.Request.ClientId,
            Nonce = session.Request.Nonce,
            // From the session's own request, because that is the key THIS session advertised. The
            // process-wide singleton this used to read from is gone: with ephemeral keys there is no one
            // thumbprint, and using the wrong session's would fail the device signature.
            EncryptionKeyThumbprint = encrypted ? RequestParameters.TryGetEncryptionKeyThumbprint(session.Request) : null,
            ResponseUri = RequestParameters.TryGetResponseUri(session.Request),
        };
    }
}
