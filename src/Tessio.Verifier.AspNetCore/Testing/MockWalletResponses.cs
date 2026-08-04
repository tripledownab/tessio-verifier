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
    private readonly MockCredentialIssuer _issuer = new();

    /// <summary>The mock issuer identifier. Its host matches the certificate SAN.</summary>
    public static string IssuerId => MockCredentialIssuer.Issuer;

    /// <summary>The mock issuer's self-signed certificate, to register as the trust anchor under test.</summary>
    public X509Certificate2 IssuerCertificate => _issuer.Certificate;

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
    /// <returns>A response ready to hand to a callback endpoint or <c>IWalletResponseVerifier</c>.</returns>
    public WalletResponseData CreateSdJwtResponse(
        VerificationSession session,
        IEnumerable<string>? claims = null,
        string? vct = null,
        string? audience = null)
    {
        ArgumentNullException.ThrowIfNull(session);

        var presentation = _issuer.IssuePresentation(
            claims ?? ["age_over_18"],
            vct ?? DemoRequestOptionsFactory.DefaultVct,
            session.Request.Nonce,
            audience ?? session.Request.ClientId,
            RequestObjectPayload.TryGetTransactionData(session.Request.SignedRequestObject));

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

    /// <summary>Releases the ephemeral issuer keys and certificate.</summary>
    public void Dispose() => _issuer.Dispose();
}
