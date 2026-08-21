using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Reads the parameters of an issued authorization request back out of it. The verifier derives
/// per-session expectations from here so it never has to consult the process-wide
/// <see cref="VerifierOptions"/>: the request carries the response_uri, response_mode, transaction data,
/// and the requested credential format / <c>vct</c> / docType in its DCQL. The frozen
/// <see cref="PresentationRequest"/> contract does not retain these, but the request itself always does.
/// </summary>
/// <remarks>
/// <para>
/// A request delivers those parameters in one of two encodings, and this reads either. A JAR request
/// carries them as claims in the signed request object. An EU Age Verification request has no request
/// object at all and carries them as plain query parameters on the authorization request URI. The signed
/// object wins where both are present, because it is the copy whose integrity is protected.
/// </para>
/// <para>
/// Reading only the request object is what made an AV session unverifiable. Every accessor returned
/// null, so the credential format fell back to <c>dc+sd-jwt</c> and an mdoc age attestation was parsed
/// as an SD-JWT VC, with no docType compared and no response_uri for the device transcript.
/// </para>
/// </remarks>
internal static class RequestParameters
{
    // SPEC: OpenID4VP 1.0 §5.1 defines dcql_query as "A JSON object containing a DCQL query" and
    // client_metadata as "A JSON object containing the Verifier metadata values", and §5.1 states: "In
    // the context of an authorization request according to RFC6749, parameters containing objects are
    // transferred as JSON-serialized strings". So in a query string these two carry JSON and every other
    // parameter carries a plain string.
    //
    // transaction_data is deliberately absent. §5.1 defines it as a "Non-empty array of strings", not an
    // object, so the sentence above does not settle how it is encoded here, and no builder in this
    // library puts it in a query string. FromQuery refuses a request that carries one rather than
    // guessing: guessing wrong would drop a binding the wallet's Key Binding JWT must acknowledge.
    private static readonly string[] JsonValued = ["dcql_query", "client_metadata"];

    /// <summary>The base64url transaction_data strings from the request, or null.</summary>
    public static IReadOnlyList<string>? TryGetTransactionData(PresentationRequest request) =>
        Read<IReadOnlyList<string>>(request, root =>
        {
            if (!root.TryGetProperty("transaction_data", out var td) || td.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var entries = td.EnumerateArray()
                .Where(static e => e.ValueKind == JsonValueKind.String)
                .Select(static e => e.GetString()!)
                .ToList();
            return entries.Count > 0 ? entries : null;
        });

    /// <summary>The request's <c>response_uri</c>, or null.</summary>
    public static string? TryGetResponseUri(PresentationRequest request) =>
        Read(request, root => TryGetString(root, "response_uri"));

    /// <summary>The request's <c>response_mode</c> (e.g. <c>direct_post</c> or <c>direct_post.jwt</c>), or null.</summary>
    public static string? TryGetResponseMode(PresentationRequest request) =>
        Read(request, root => TryGetString(root, "response_mode"));

    /// <summary>
    /// The credential format the request's DCQL asks for (<c>dcql_query.credentials[0].format</c>, e.g.
    /// <c>dc+sd-jwt</c> or <c>mso_mdoc</c>), or null. Lets the callback parse per session instead of from a
    /// process-wide format pin.
    /// </summary>
    public static string? TryGetRequestedFormat(PresentationRequest request) =>
        Read(request, root =>
            TryGetFirstCredential(root, out var credential) ? TryGetString(credential, "format") : null);

    /// <summary>
    /// The requested SD-JWT VC type from the request's DCQL query
    /// (<c>dcql_query.credentials[0].meta.vct_values[0]</c>), or null for a non-SD-JWT request. This is the
    /// type the session asked for, so the verifier enforces it per session rather than from options.
    /// </summary>
    public static string? TryGetExpectedVct(PresentationRequest request) =>
        Read(request, root =>
            TryGetFirstCredential(root, out var credential)
            && credential.TryGetProperty("meta", out var meta)
            && meta.TryGetProperty("vct_values", out var vctValues)
            && vctValues.ValueKind == JsonValueKind.Array
            && vctValues.GetArrayLength() > 0
            && vctValues[0].ValueKind == JsonValueKind.String
                ? vctValues[0].GetString()
                : null);

    /// <summary>
    /// The requested mdoc document type from the request's DCQL query
    /// (<c>dcql_query.credentials[0].meta.doctype_value</c>), or null for a non-mdoc request.
    /// </summary>
    public static string? TryGetExpectedDocType(PresentationRequest request) =>
        Read(request, root =>
            TryGetFirstCredential(root, out var credential) && credential.TryGetProperty("meta", out var meta)
                ? TryGetString(meta, "doctype_value")
                : null);

    /// <summary>
    /// The response-encryption public JWK this request advertised in <c>client_metadata.jwks</c>, as
    /// raw JSON. Null when the request carries none (direct_post).
    /// </summary>
    /// <remarks>
    /// This is the honest source for anything that needs "the key the wallet saw": the mock wallet
    /// encrypts to it and the verifier derives the mdoc session-transcript thumbprint from it. Reading
    /// it from a process-wide singleton instead is how key reuse survived until the conformance suite
    /// flagged it.
    /// </remarks>
    public static string? TryGetEncryptionJwkJson(PresentationRequest request) =>
        Read(request, root =>
            root.TryGetProperty("client_metadata", out var cm)
            && cm.TryGetProperty("jwks", out var jwks)
            && jwks.TryGetProperty("keys", out var keys)
            && keys.ValueKind == JsonValueKind.Array
            && keys.GetArrayLength() > 0
                ? keys[0].GetRawText()
                : null);

    /// <summary>
    /// The RFC 7638 thumbprint of the encryption JWK this request advertised, from its <c>kid</c>. Null
    /// when the request advertised no key.
    /// </summary>
    public static byte[]? TryGetEncryptionKeyThumbprint(PresentationRequest request)
    {
        if (TryGetEncryptionJwkJson(request) is not { } jwkJson)
        {
            return null;
        }

        using var jwk = JsonDocument.Parse(jwkJson);
        return jwk.RootElement.TryGetProperty("kid", out var kid) && kid.GetString() is { Length: > 0 } value
            ? Base64UrlEncoder.DecodeBytes(value)
            : null;
    }

    /// <summary>
    /// Whether this request's parameters can be recovered, in either encoding. False means neither
    /// encoding yields a DCQL query, so nothing a wallet returns can be checked against what was asked
    /// for: not the credential format, not the <c>vct</c>, not the docType.
    /// </summary>
    /// <remarks>
    /// The DCQL is the test rather than "did anything parse", because a request object that parses but
    /// carries no query leaves every expectation null just as surely as no request object at all.
    /// </remarks>
    public static bool AreRecoverable(PresentationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var root = TryReadRoot(request);
        return root is not null && TryGetFirstCredential(root.RootElement, out _);
    }

    private static bool TryGetFirstCredential(JsonElement root, out JsonElement credential)
    {
        if (root.TryGetProperty("dcql_query", out var dcql)
            && dcql.TryGetProperty("credentials", out var credentials)
            && credentials.ValueKind == JsonValueKind.Array
            && credentials.GetArrayLength() > 0)
        {
            credential = credentials[0];
            return true;
        }

        credential = default;
        return false;
    }

    private static string? TryGetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static T? Read<T>(PresentationRequest request, Func<JsonElement, T?> read)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var root = TryReadRoot(request);
        return root is null ? default : read(root.RootElement);
    }

    /// <summary>
    /// The request's parameters as one JSON object, from the signed request object where there is one and
    /// from the query string otherwise. Null when neither encoding yields anything readable.
    /// </summary>
    private static JsonDocument? TryReadRoot(PresentationRequest request) =>
        FromRequestObject(request.SignedRequestObject) ?? FromQuery(request.AuthorizationRequestUri);

    private static JsonDocument? FromRequestObject(string requestObject)
    {
        var parts = requestObject.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The parameters of a plain-parameter request, as the same JSON shape a request object would carry.
    /// Requires <c>dcql_query</c>: without it there is no request to check a response against, and every
    /// caller here would read null from a URI that merely happened to have a query string.
    /// </summary>
    private static JsonDocument? FromQuery(Uri authorizationRequestUri)
    {
        var query = QueryHelpers.ParseQuery(authorizationRequestUri.Query);
        if (!query.TryGetValue("dcql_query", out var dcql) || dcql.Count != 1 || string.IsNullOrEmpty(dcql[0]))
        {
            return null;
        }

        // See JsonValued: this encoding of transaction_data is not settled, and reading it wrong would
        // drop a binding rather than fail. Report the whole request as unreadable instead, which a host
        // surfaces as a refusal it can act on.
        if (query.ContainsKey("transaction_data"))
        {
            return null;
        }

        try
        {
            var root = new JsonObject();
            foreach (var (name, values) in query)
            {
                if (values.Count != 1 || values[0] is not { Length: > 0 } value)
                {
                    continue;
                }

                root[name] = JsonValued.Contains(name, StringComparer.Ordinal)
                    ? JsonNode.Parse(value)
                    : JsonValue.Create(value);
            }

            return JsonDocument.Parse(root.ToJsonString());
        }
        catch (JsonException)
        {
            // A JSON-valued parameter that is not JSON. Unreadable is unreadable: report it as such
            // rather than returning the half of the request that did parse.
            return null;
        }
    }
}
