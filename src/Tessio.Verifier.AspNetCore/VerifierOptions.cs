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
}
