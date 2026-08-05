using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Testing;

/// <summary>
/// Builds the wallet response for a session the way MOCK mode does, but callable by a consumer.
/// </summary>
/// <remarks>
/// MOCK mode only fires from the built-in <c>/start</c> endpoint. A host that self-drives the protocol
/// (serving its own <c>request_uri</c> and <c>response_uri</c>) cannot reuse it, so it has no way to
/// exercise its own callback in an automated test. This helper closes that gap: it mints a real,
/// signed SD-JWT VC presentation bound to the session and wraps it exactly as a wallet would POST it.
/// Additive to contracts-v0; nothing existing changes.
/// <para>
/// Trust: the presentation is signed by an ephemeral mock issuer. Register
/// <see cref="IssuerCertificate"/> for <see cref="IssuerId"/> on the trust list under test, or
/// verification will correctly reject it as untrusted.
/// </para>
/// </remarks>
public sealed class MockWalletResponses : IDisposable
{
    /// <summary>
    /// docType of the EU age-verification attestation, the mdoc-only credential purpose-built for age
    /// checks. It carries <c>age_over_N</c> booleans and no identity attributes.
    /// </summary>
    public const string EuAgeVerificationDocType = "eu.europa.ec.av.1";

    private readonly MockCredentialIssuer _issuer = new();
    private readonly MockMdocIssuer _mdocIssuer = new();

    /// <summary>The mock issuer identifier. Its host matches the certificate SAN.</summary>
    public static string IssuerId => MockCredentialIssuer.Issuer;

    /// <summary>The mock issuer's self-signed certificate, to register as the trust anchor under test.</summary>
    public X509Certificate2 IssuerCertificate => _issuer.Certificate;

    /// <summary>The mdoc IACA root, to register as the trust anchor when verifying an mdoc response.</summary>
    public X509Certificate2 MdocIacaCertificate => _mdocIssuer.IacaCertificate;

    /// <summary>
    /// The mdoc issuer identifier, which is the Document Signer certificate's subject rather than a URL.
    /// This is the value to put on the trust list; the docType is not an issuer.
    /// </summary>
    public string MdocIssuerId => _mdocIssuer.DsCertificate.Subject;

    /// <summary>
    /// Issues an SD-JWT VC presentation bound to the session's nonce, audience and transaction data,
    /// wrapped in the cleartext <c>direct_post</c> form a wallet POSTs to the <c>response_uri</c>.
    /// </summary>
    /// <param name="session">The pending session to answer. Its request supplies nonce, audience and state.</param>
    /// <param name="claims">Claims to disclose. Defaults to <c>age_over_18</c>.</param>
    /// <param name="vct">Credential type. Defaults to the demo VCT.</param>
    /// <param name="audience">
    /// KB-JWT audience. Defaults to the session's <c>client_id</c>, which is what the verifier checks.
    /// </param>
    /// <param name="claimValues">
    /// Values to disclose, by claim name, overriding the sample persona. See the remarks on
    /// <see cref="CreateMdocResponse"/> for why a test needs to choose these.
    /// </param>
    /// <returns>A response ready to hand to a callback endpoint or <c>IWalletResponseVerifier</c>.</returns>
    public WalletResponseData CreateSdJwtResponse(
        VerificationSession session,
        IEnumerable<string>? claims = null,
        string? vct = null,
        string? audience = null,
        IReadOnlyDictionary<string, object>? claimValues = null)
    {
        ArgumentNullException.ThrowIfNull(session);

        var presentation = _issuer.IssuePresentation(
            claims ?? ["age_over_18"],
            vct ?? DemoRequestOptionsFactory.DefaultVct,
            session.Request.Nonce,
            audience ?? session.Request.ClientId,
            RequestObjectPayload.TryGetTransactionData(session.Request.SignedRequestObject),
            claimValues);

        return new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                ["state"] = new[] { session.Request.State ?? string.Empty },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
    }

    /// <summary>
    /// Issues an ISO 18013-5 mdoc DeviceResponse bound to the session, wrapped in the cleartext
    /// <c>direct_post</c> form a wallet POSTs to the <c>response_uri</c>.
    /// </summary>
    /// <remarks>
    /// The mdoc counterpart of <see cref="CreateSdJwtResponse"/>. It matters separately because the two
    /// formats fail in different places: an mdoc device signature covers the session transcript
    /// (client_id, nonce, response_uri), so a host that only ever exercises SD-JWT has never tested the
    /// binding a real mdoc wallet actually performs. The EU age-verification attestation is mdoc-only,
    /// which makes this the shape an age check has to handle.
    /// <para>
    /// Trust: register <see cref="MdocIacaCertificate"/> as the trust anchor under test, not
    /// <see cref="IssuerCertificate"/>. The mdoc chain is issued by a separate ephemeral IACA root.
    /// </para>
    /// </remarks>
    /// <param name="session">The pending session to answer. Supplies client_id, nonce, response_uri and state.</param>
    /// <param name="claimNames">Elements to disclose. Defaults to <c>age_over_18</c>.</param>
    /// <param name="docType">mdoc docType. Defaults to the EU age-verification attestation.</param>
    /// <param name="mdocNamespace">Namespace holding the elements. Defaults to <paramref name="docType"/>.</param>
    /// <param name="encryptionKeyThumbprint">
    /// Set only for an encrypted <c>direct_post.jwt</c> response, whose transcript binds the key thumbprint.
    /// </param>
    /// <param name="claimValues">
    /// Values to disclose, by claim name, overriding the sample persona (which answers every age question
    /// with true).
    /// </param>
    /// <remarks>
    /// Choosing values matters more than it looks. A wallet answering <c>age_over_18</c> with <c>false</c>
    /// produces a completely valid presentation: correct issuer, valid signature, intact device binding.
    /// A host that can only ever be handed a true one cannot tell whether it reads the disclosed answer or
    /// merely the signature, and those two behaviours differ by whether a minor passes an age check.
    /// </remarks>
    public WalletResponseData CreateMdocResponse(
        VerificationSession session,
        IEnumerable<string>? claimNames = null,
        string? docType = null,
        string? mdocNamespace = null,
        byte[]? encryptionKeyThumbprint = null,
        IReadOnlyDictionary<string, object>? claimValues = null)
    {
        ArgumentNullException.ThrowIfNull(session);

        var type = docType ?? EuAgeVerificationDocType;

        // An encrypted response binds the encryption key thumbprint into the session transcript. Without
        // it the device signature simply fails to verify, which reads as a crypto bug rather than the
        // missing argument it is, so refuse up front and say which one is missing.
        var encrypted = string.Equals(
            RequestObjectPayload.TryGetResponseMode(session.Request.SignedRequestObject),
            "direct_post.jwt",
            StringComparison.Ordinal);
        if (encrypted && encryptionKeyThumbprint is null)
        {
            throw new ArgumentNullException(
                nameof(encryptionKeyThumbprint),
                "This session uses direct_post.jwt, whose session transcript covers the response encryption " +
                "key thumbprint. Pass ResponseEncryptionKeyProvider.ThumbprintBytes, or build the session " +
                "with ResponseMode.DirectPost.");
        }
        // The device signature covers the response_uri, which is only readable from the signed request
        // object. Guessing one would produce a response that fails verification for a reason unrelated to
        // whatever the test is actually checking, so say so plainly instead.
        var responseUri = RequestObjectPayload.TryGetResponseUri(session.Request.SignedRequestObject)
            ?? throw new InvalidOperationException(
                "An mdoc response needs a signed request object carrying response_uri, because the device " +
                "signature covers it. Build the session with a signing credential source.");

        var deviceResponse = _mdocIssuer.IssueDeviceResponse(
            claimNames ?? ["age_over_18"],
            type,
            mdocNamespace ?? type,
            session.Request.ClientId,
            session.Request.Nonce,
            encryptionKeyThumbprint,
            responseUri,
            claimValues);

        return new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{deviceResponse}}"]}""" },
                ["state"] = new[] { session.Request.State ?? string.Empty },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
    }

    /// <summary>Releases the ephemeral issuer keys and certificates.</summary>
    public void Dispose()
    {
        _issuer.Dispose();
        _mdocIssuer.Dispose();
    }
}
