using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Configuration for the Tessio verifier, supplied via
/// <see cref="TessioVerifierServiceCollectionExtensions.AddTessioVerifier"/>.
/// </summary>
public sealed class VerifierOptions
{
    /// <summary>
    /// Operating mode. Defaults to <see cref="VerifierMode.Demo"/> so a fresh install runs end-to-end
    /// without a wallet.
    /// </summary>
    public VerifierMode Mode { get; set; } = VerifierMode.Demo;

    /// <summary>
    /// Claims to request via selective disclosure (the DCQL query is generated from these). Ask only for
    /// what you need. When empty, the verifier requests <c>age_over_18</c> so the demo always shows something.
    /// </summary>
    public IList<string> RequestedClaims { get; set; } = new List<string>();

    /// <summary>
    /// Verifier identifier (OpenID4VP <c>client_id</c>). Per OpenID4VP 1.0 this may carry a
    /// client-identifier-scheme prefix (e.g. <c>x509_san_dns:verifier.example.com</c>) in production.
    /// </summary>
    public string ClientId { get; set; } = "tessio-demo-verifier";

    /// <summary>
    /// Optional expected credential type (SD-JWT VC <c>vct</c>) to constrain the DCQL query. When unset a
    /// demo default is used.
    /// </summary>
    public string? ExpectedVct { get; set; }

    /// <summary>
    /// Credential format to request and verify: <c>dc+sd-jwt</c> (default) or <c>mso_mdoc</c>
    /// (ISO mobile documents, e.g. the mDL).
    /// </summary>
    public string CredentialFormat { get; set; } = "dc+sd-jwt";

    /// <summary>
    /// Expected mdoc document type when <see cref="CredentialFormat"/> is <c>mso_mdoc</c>.
    /// Defaults to the mobile driving licence (<c>org.iso.18013.5.1.mDL</c>).
    /// </summary>
    public string ExpectedDocType { get; set; } = "org.iso.18013.5.1.mDL";

    /// <summary>
    /// Namespace for requested mdoc claims (DCQL paths are <c>[namespace, element]</c>).
    /// Defaults to the mDL namespace.
    /// </summary>
    public string MdocNamespace { get; set; } = "org.iso.18013.5.1";

    /// <summary>
    /// OpenID4VP response delivery mode written into the generated request. Defaults to
    /// <see cref="ResponseMode.DirectPostJwt"/> (the HAIP default).
    /// </summary>
    public ResponseMode ResponseMode { get; set; } = ResponseMode.DirectPostJwt;

    /// <summary>
    /// Transaction data to bind into the presentation (OpenID4VP transaction_data): each entry is a
    /// JSON object string with at least a <c>type</c> member; <c>credential_ids</c> defaults to the
    /// query's credential id. The wallet acknowledges each entry with a hash in the KB-JWT, which is
    /// verified. SD-JWT VC flows only.
    /// </summary>
    public IList<string> TransactionData { get; set; } = new List<string>();

    /// <summary>How long a created session (and its request) remains valid. Default: 5 minutes.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// In <see cref="VerifierMode.Demo"/>, how long to wait before auto-completing a session with a
    /// synthesized result. Default: 2 seconds. Set to <see cref="TimeSpan.Zero"/> to complete immediately.
    /// </summary>
    public TimeSpan DemoCompletionDelay { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// URL path prefix under which <see cref="TessioVerifierEndpointRouteBuilderExtensions.MapTessioVerifier"/>
    /// mounts its endpoints. Default: <c>/verify</c>.
    /// </summary>
    public string RoutePrefix { get; set; } = "/verify";

    /// <summary>
    /// Trust list identifiers that may be disclosed to an ANONYMOUS caller. Empty by default, which
    /// discloses none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why an allowlist and not a redaction rule.</b> The session status endpoint and its SSE stream
    /// are reachable by whoever holds a session id, and a session id is self-served by
    /// <c>GET {prefix}/start</c>, so treat that surface as anonymous. It carries
    /// <see cref="Core.IssuerInfo.TrustListSource"/>, which a resolver may set to anything: the built-in
    /// <see cref="Trust.TrustListLoader"/> passes the path or URL it was handed straight through, so the
    /// value can be a server filesystem path, and a directory of anchor files can name the parties a
    /// deployment tests against.
    /// </para>
    /// <para>
    /// A redaction rule would ask "does this look sensitive", which is a judgement that fails open on the
    /// first string nobody anticipated. This inverts it: a source is emitted only if it appears here, and
    /// anything else becomes <see cref="UndisclosedTrustListSource"/>. That fails closed by construction.
    /// </para>
    /// <para>
    /// Nothing a caller needs is lost. "A trust list was consulted and your issuer was not on it" is the
    /// useful part, and the token still says it. Put a genuinely public list here, such as a
    /// Commission-published trusted list URL, where naming it helps an integrator and discloses nothing.
    /// The full value is untouched on any surface you authorise and scope yourself.
    /// </para>
    /// </remarks>
    public ISet<string> PublicTrustListSources { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// What an anonymous caller sees in place of a trust list identifier that is not on
    /// <see cref="PublicTrustListSources"/>.
    /// </summary>
    /// <remarks>
    /// A fixed token rather than null, because the two say different things: null means no list was
    /// consulted, and this means one was and is not named on this surface.
    /// </remarks>
    public const string UndisclosedTrustListSource = "undisclosed";

    /// <summary>
    /// What an anonymous caller reads in place of a failure message.
    /// </summary>
    /// <remarks>
    /// <see cref="Core.VerificationError.Code"/> is append-only observable behaviour and is what a caller
    /// acts on, so the code still travels. The message is prose written by whoever produced the failure,
    /// and the reader of this surface is whoever holds a session id. A sentence rather than a token,
    /// because an integrator meeting it needs to know the message exists elsewhere rather than that the
    /// failure had no explanation.
    /// </remarks>
    public const string UndisclosedErrorMessage =
        "The failure message is not disclosed on this surface. Read the code, or the stored result.";
}
