using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Reads fields out of a stored request object (the signed JAR, or the demo builder's unsigned form).
/// The verifier derives per-session expectations from here so it never has to consult the process-wide
/// <see cref="VerifierOptions"/>: the request carries the response_uri, response_mode, transaction data,
/// and the requested credential format / <c>vct</c> / docType in its DCQL. The frozen
/// <see cref="Tessio.Verifier.OpenId4Vp.PresentationRequest"/> contract does not retain these, but the
/// request object itself always does.
/// </summary>
internal static class RequestObjectPayload
{
    /// <summary>The base64url transaction_data strings from the request object, or null.</summary>
    public static IReadOnlyList<string>? TryGetTransactionData(string requestObject) =>
        ReadFromPayload<IReadOnlyList<string>>(requestObject, root =>
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
    public static string? TryGetResponseUri(string requestObject) =>
        ReadFromPayload(requestObject, root => TryGetString(root, "response_uri"));

    /// <summary>The request's <c>response_mode</c> (e.g. <c>direct_post</c> or <c>direct_post.jwt</c>), or null.</summary>
    public static string? TryGetResponseMode(string requestObject) =>
        ReadFromPayload(requestObject, root => TryGetString(root, "response_mode"));

    /// <summary>
    /// The credential format the request's DCQL asks for (<c>dcql_query.credentials[0].format</c>, e.g.
    /// <c>dc+sd-jwt</c> or <c>mso_mdoc</c>), or null. Lets the callback parse per session instead of from a
    /// process-wide format pin.
    /// </summary>
    public static string? TryGetRequestedFormat(string requestObject) =>
        ReadFromPayload(requestObject, root =>
            TryGetFirstCredential(root, out var credential) ? TryGetString(credential, "format") : null);

    /// <summary>
    /// The requested SD-JWT VC type from the request's DCQL query
    /// (<c>dcql_query.credentials[0].meta.vct_values[0]</c>), or null for a non-SD-JWT request. This is the
    /// type the session asked for, so the verifier enforces it per session rather than from options.
    /// </summary>
    public static string? TryGetExpectedVct(string requestObject) =>
        ReadFromPayload(requestObject, root =>
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
    public static string? TryGetExpectedDocType(string requestObject) =>
        ReadFromPayload(requestObject, root =>
            TryGetFirstCredential(root, out var credential) && credential.TryGetProperty("meta", out var meta)
                ? TryGetString(meta, "doctype_value")
                : null);

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

    private static T? ReadFromPayload<T>(string requestObject, Func<JsonElement, T?> read)
    {
        var parts = requestObject.Split('.');
        if (parts.Length < 2)
        {
            return default;
        }

        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
            return read(payload.RootElement);
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return default;
        }
    }
}
