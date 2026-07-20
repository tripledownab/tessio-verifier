using System.Text.Encodings.Web;
using System.Text.Json;

namespace Tessio.Verifier.AspNetCore;

/// <summary>Shared JSON settings for protocol payloads.</summary>
internal static class JsonDefaults
{
    /// <summary>
    /// Relaxed escaping so protocol payloads (DCQL query, request object) keep characters such as
    /// <c>+</c> literal (e.g. <c>dc+sd-jwt</c>) instead of emitting <c>+</c>. These are JWT/JSON
    /// payloads, not HTML, so HTML-escaping is unnecessary and hurts readability/interop.
    /// </summary>
    public static readonly JsonSerializerOptions Relaxed = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
