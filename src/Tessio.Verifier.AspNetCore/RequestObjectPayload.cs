using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Reads claims out of a stored request object (the signed JAR, or the demo builder's unsigned
/// form). The mdoc session transcript needs the request's <c>response_uri</c>, which the frozen
/// <see cref="Tessio.Verifier.OpenId4Vp.PresentationRequest"/> contract does not retain; the
/// request object itself always carries it.
/// </summary>
internal static class RequestObjectPayload
{
    public static string? TryGetResponseUri(string requestObject)
    {
        var parts = requestObject.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
            return payload.RootElement.TryGetProperty("response_uri", out var uri)
                   && uri.ValueKind == JsonValueKind.String
                ? uri.GetString()
                : null;
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }
}
