using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core;

/// <summary>
/// Converts <see cref="JsonNode"/> values into the plain CLR shapes the
/// <see cref="VerificationResult.DisclosedClaims"/> contract documents:
/// string, bool, long/double, <c>List&lt;object?&gt;</c>, <c>Dictionary&lt;string, object?&gt;</c>, or null.
/// </summary>
internal static class JsonValueConverter
{
    public static object? ToClrValue(JsonNode? node) => node switch
    {
        null => null,
        JsonObject obj => obj.ToDictionary(p => p.Key, p => ToClrValue(p.Value), StringComparer.Ordinal),
        JsonArray array => array.Select(ToClrValue).ToList(),
        _ => ScalarToClr(node),
    };

    private static object? ScalarToClr(JsonNode node) => node.GetValueKind() switch
    {
        JsonValueKind.String => node.GetValue<string>(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => NumberToClr(node),
        _ => null,
    };

    private static object NumberToClr(JsonNode node)
    {
        var element = node.GetValue<JsonElement>();
        return element.TryGetInt64(out var integer) ? integer : element.GetDouble();
    }
}
