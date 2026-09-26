using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builders for the common OpenID4VP DCQL (Digital Credentials Query Language) queries, producing the
/// JSON string expected by <see cref="PresentationRequestOptions.DcqlQueryJson"/>. These cover the shapes
/// the verifier itself requests (single credential, top-level claims); hand-write the JSON for anything
/// more exotic (nested claim paths, multiple credentials, claim value constraints).
/// </summary>
// SPEC: OpenID4VP 1.0 uses DCQL, not Presentation Exchange.
public static class Dcql
{
    // SPEC: SD-JWT VC credential format identifier is "dc+sd-jwt" (not the legacy "vc+sd-jwt").
    private const string SdJwtVcFormat = "dc+sd-jwt";
    private const string MdocFormat = "mso_mdoc";

    /// <summary>The credential id this builder puts on a single-credential query.</summary>
    /// <remarks>
    /// Nothing on the verify side REQUIRES this value. <c>WalletResponseParser.ExtractCredentials</c>
    /// enumerates every property of the <c>vp_token</c> object whatever its key, per OpenID4VP 1.0
    /// section 8.1, so a query using other ids parses fine. Said the other way because the previous
    /// wording said the pipeline "expects" it, which reads as a constraint that is not there.
    /// </remarks>
    public const string DefaultCredentialId = "credential";

    /// <summary>
    /// A query for a single SD-JWT VC credential of type <paramref name="vct"/>, requesting each of
    /// <paramref name="claims"/> by selective disclosure. Each entry is a top-level claim name.
    /// </summary>
    public static string SdJwtVc(string vct, params string[] claims)
    {
        ArgumentException.ThrowIfNullOrEmpty(vct);
        return SdJwtVc([vct], claims);
    }

    /// <summary>
    /// A query for a single SD-JWT VC credential of ANY of <paramref name="vctValues"/>, requesting each
    /// of <paramref name="claims"/> by selective disclosure. Use this where one credential entry should
    /// accept several types, for example a base PID type and a member state's own.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 §B.3.5 defines <c>vct_values</c> as "A non-empty array of strings that
    /// specifies allowed values for the type of the requested Verifiable Credential", so an empty list
    /// is refused here rather than emitted. The verifier accepts a credential whose <c>vct</c> is any
    /// member of the array it sent.
    /// </remarks>
    public static string SdJwtVc(IReadOnlyList<string> vctValues, params string[] claims)
    {
        ArgumentNullException.ThrowIfNull(vctValues);
        ArgumentNullException.ThrowIfNull(claims);
        if (vctValues.Count == 0)
        {
            throw new ArgumentException("A DCQL query needs at least one vct value.", nameof(vctValues));
        }

        var values = new JsonArray();
        foreach (var vct in vctValues)
        {
            ArgumentException.ThrowIfNullOrEmpty(vct);
            values.Add(vct);
        }

        var claimsArray = new JsonArray();
        foreach (var claim in claims)
        {
            ArgumentException.ThrowIfNullOrEmpty(claim);
            claimsArray.Add(new JsonObject { ["path"] = new JsonArray(claim) });
        }

        return SingleCredential(SdJwtVcFormat, new JsonObject { ["vct_values"] = values }, claimsArray);
    }

    /// <summary>
    /// Convenience for the common age check: a single SD-JWT VC credential of type <paramref name="vct"/>
    /// requesting the boolean <c>age_over_{age}</c> claim.
    /// </summary>
    public static string AgeOver(int age, string vct)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(age);
        return SdJwtVc(vct, $"age_over_{age}");
    }

    /// <summary>
    /// A query for a single mdoc credential of document type <paramref name="docType"/>, requesting each
    /// of <paramref name="elements"/> from <paramref name="nameSpace"/> (mdoc DCQL paths are
    /// <c>[namespace, element]</c>).
    /// </summary>
    // SPEC: OpenID4VP 1.0 Annex B.2 — mdoc queries use meta.doctype_value and two-element claim paths.
    public static string Mdoc(string docType, string nameSpace, params string[] elements)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);
        ArgumentNullException.ThrowIfNull(elements);

        var claimsArray = new JsonArray();
        foreach (var element in elements)
        {
            ArgumentException.ThrowIfNullOrEmpty(element);
            claimsArray.Add(new JsonObject { ["path"] = new JsonArray(nameSpace, element) });
        }

        return SingleCredential(MdocFormat, new JsonObject { ["doctype_value"] = docType }, claimsArray);
    }

    private static string SingleCredential(string format, JsonObject meta, JsonArray claims)
    {
        var query = new JsonObject
        {
            ["credentials"] = new JsonArray(
                new JsonObject
                {
                    ["id"] = DefaultCredentialId,
                    ["format"] = format,
                    ["meta"] = meta,
                    ["claims"] = claims,
                }),
        };

        return query.ToJsonString(JsonDefaults.Relaxed);
    }
}
