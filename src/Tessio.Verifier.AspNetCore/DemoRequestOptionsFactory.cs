using System.Text.Json.Nodes;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Turns high-level <see cref="VerifierOptions"/> into a per-request <see cref="PresentationRequestOptions"/>,
/// generating the nonce/state and the DCQL query from the requested claims.
/// </summary>
internal static class DemoRequestOptionsFactory
{
    /// <summary>Credential type used when <see cref="VerifierOptions.ExpectedVct"/> is unset.</summary>
    internal const string DefaultVct = "https://demo-issuer.tessio.dev/vct/identity";

    /// <summary>Whether this deployment asks for an mdoc rather than an SD-JWT VC.</summary>
    /// <remarks>
    /// One owner for the test, because more than one place branches on it: the query built below, and
    /// the type a demo result reports. Separate copies would let a deployment request one format and
    /// report the other.
    /// </remarks>
    internal static bool IsMdoc(VerifierOptions options) =>
        string.Equals(options.CredentialFormat, MdocVerifier.Format, StringComparison.Ordinal);

    /// <summary>
    /// The credential type this deployment asks for: the docType under mdoc, the vct otherwise.
    /// </summary>
    /// <remarks>
    /// Demo mode synthesizes its result rather than verifying one, so nothing reads a type off a real
    /// credential. Without this the demo reports no type where a live verification reports one, and a
    /// caller building against demo meets a field that is null until it suddenly is not.
    /// </remarks>
    internal static string CredentialTypeFor(VerifierOptions options) =>
        IsMdoc(options) ? options.ExpectedDocType : options.ExpectedVct ?? DefaultVct;

    public static PresentationRequestOptions Create(
        VerifierOptions options, Uri responseUri, JsonObject? responseEncryptionJwk = null)
    {
        var claims = options.RequestedClaims is { Count: > 0 }
            ? options.RequestedClaims
            : new[] { "age_over_18" };

        return new PresentationRequestOptions
        {
            ClientId = options.ClientId,
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = IsMdoc(options)
                ? BuildMdocDcqlQuery(claims, options.ExpectedDocType, options.MdocNamespace)
                : BuildDcqlQuery(claims, options.ExpectedVct),
            ResponseUri = responseUri,
            ResponseMode = options.ResponseMode,
            RequestLifetime = options.SessionLifetime,
            ClientMetadataJson = BuildClientMetadata(options, responseEncryptionJwk),
            TransactionDataJson = BuildTransactionData(options),
        };
    }

    // The DCQL query shapes live in the public Dcql helper so hosts building their own requests share
    // exactly the query the verifier expects.
    private static string BuildDcqlQuery(IEnumerable<string> claims, string? expectedVct) =>
        Dcql.SdJwtVc(expectedVct ?? DefaultVct, claims.ToArray());

    private static string BuildMdocDcqlQuery(IEnumerable<string> claims, string docType, string mdocNamespace) =>
        Dcql.Mdoc(docType, mdocNamespace, claims.ToArray());

    // SPEC: OpenID4VP 1.0 §5.1/Annex B.3.3 — transaction_data is an array of base64url-encoded JSON
    // objects; each needs type and credential_ids. The KB-JWT hashes are computed over these exact strings.
    private static string? BuildTransactionData(VerifierOptions options)
    {
        if (options.TransactionData.Count == 0)
        {
            return null;
        }

        // Serialized via JsonSerializer, not a JsonArray of strings: on net8, implicitly converted
        // JsonValues fail to serialize under custom JsonSerializerOptions.
        var entries = new List<string>();
        foreach (var entry in options.TransactionData)
        {
            var node = (JsonObject)JsonNode.Parse(entry)!;
            node["credential_ids"] ??= JsonNode.Parse("""["credential"]""");
            entries.Add(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(node.ToJsonString(JsonDefaults.Relaxed)));
        }

        return System.Text.Json.JsonSerializer.Serialize(entries);
    }

    /// <summary>
    /// Delegates to <see cref="Tessio.Verifier.OpenId4Vp.ClientMetadata"/>, which is the single builder
    /// for this object. It used to be assembled here and again in a consuming application; the two
    /// drifted, and the conformance suite caught the consumer advertising values HAIP rejects.
    /// </summary>
    private static string BuildClientMetadata(VerifierOptions options, JsonObject? responseEncryptionJwk) =>
        Tessio.Verifier.OpenId4Vp.ClientMetadata.Build(options.CredentialFormat, responseEncryptionJwk);
}
