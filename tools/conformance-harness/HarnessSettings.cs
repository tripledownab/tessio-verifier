using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.ConformanceHarness;

/// <summary>
/// The harness configuration, read once and validated at startup.
/// </summary>
/// <remarks>
/// Validation happens here rather than at first use because every one of these being wrong fails the
/// same way twenty seconds into a flow: a timeout with nothing attached saying which value was at fault.
/// </remarks>
internal sealed record HarnessSettings
{
    public required Uri PublicBaseUri { get; init; }
    public required string AuthorizationEndpoint { get; init; }
    public required string Issuer { get; init; }
    public required string CredentialFormat { get; init; }
    public required ResponseMode ResponseMode { get; init; }
    public required string RequestedClaim { get; init; }
    public required IReadOnlyList<X509Certificate2> TrustAnchors { get; init; }

    /// <summary>SD-JWT VC credential type. Null when running the mdoc variant.</summary>
    public string? ExpectedVct { get; init; }

    /// <summary>mdoc document type. Null when running the SD-JWT VC variant.</summary>
    public string? ExpectedDocType { get; init; }

    /// <summary>mdoc claim namespace. Null when running the SD-JWT VC variant.</summary>
    public string? MdocNamespace { get; init; }

    public bool IsMdoc => CredentialFormat == "mso_mdoc";

    public string ClientId { get; init; } = "";

    /// <summary>
    /// Our request-object signing certificate as PEM. This is the plan's one configuration field,
    /// client.request_object_trust_anchor_pem, so the landing page shows it for copying.
    /// </summary>
    public string RequestObjectTrustAnchorPem { get; init; } = "";

    public static HarnessSettings Load(IConfiguration cfg)
    {
        string Required(string key) => cfg[key] is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                $"Missing configuration '{key}'. Create the test plan in the suite first, then copy its "
                + "values into appsettings.Local.json. See README.md.");

        var format = cfg["Request:CredentialFormat"] ?? "dc+sd-jwt";
        if (format is not ("dc+sd-jwt" or "mso_mdoc"))
        {
            throw new InvalidOperationException(
                $"Request:CredentialFormat must be 'dc+sd-jwt' or 'mso_mdoc', not '{format}'.");
        }

        var anchors = LoadTrustAnchors(cfg);
        var isMdoc = format == "mso_mdoc";

        // mdoc trust is X.509 only: the issuer signature is carried by an x5chain and
        // StaticTrustListResolver rejects every x5c credential when no anchors are configured. Without
        // this check the whole plan would reject, the four positive modules would fail, and the eight
        // negative modules would appear to pass while actually rejecting for the wrong reason.
        if (isMdoc && anchors.Count == 0)
        {
            throw new InvalidOperationException(
                "Request:CredentialFormat is 'mso_mdoc', which needs Suite:TrustAnchors: mdoc trust is "
                + "X.509 only, so an identifier-only trust list rejects every credential. Export the "
                + "suite's issuer certificate and list its path.");
        }

        return new HarnessSettings
        {
            PublicBaseUri = new Uri(Required("PublicBaseUri")),
            AuthorizationEndpoint = Required("Suite:AuthorizationEndpoint"),
            Issuer = Required("Suite:Issuer"),
            CredentialFormat = format,
            ResponseMode = Enum.Parse<ResponseMode>(
                cfg["Request:ResponseMode"] ?? nameof(ResponseMode.DirectPostJwt)),
            RequestedClaim = cfg["Request:Claim"] ?? "age_over_18",
            TrustAnchors = anchors,

            // Each format uses its own identifiers. Setting the other one is not merely useless, it
            // reads as a configuration the harness honours when it does not.
            ExpectedVct = isMdoc ? null : cfg["Request:ExpectedVct"],
            ExpectedDocType = isMdoc ? cfg["Request:ExpectedDocType"] ?? "org.iso.18013.5.1.mDL" : null,
            MdocNamespace = isMdoc ? cfg["Request:MdocNamespace"] ?? "org.iso.18013.5.1" : null,
        };
    }

    /// <summary>
    /// Loads the certificates an x5c or x5chain must anchor on. Accepts PEM or DER.
    /// </summary>
    private static List<X509Certificate2> LoadTrustAnchors(IConfiguration cfg)
    {
        var paths = cfg.GetSection("Suite:TrustAnchors").Get<string[]>() ?? [];
        var anchors = new List<X509Certificate2>(paths.Length);

        foreach (var path in paths)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"Suite:TrustAnchors lists '{path}', which does not exist.", path);
            }

            var bytes = File.ReadAllBytes(path);
            anchors.Add(System.Text.Encoding.ASCII.GetString(bytes).Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)
                ? X509Certificate2.CreateFromPem(File.ReadAllText(path))
                : X509CertificateLoader.LoadCertificate(bytes));
        }

        return anchors;
    }
}
