using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The scheme and host a request names, as the start of a URI: what the routes that hand a wallet a
/// <c>response_uri</c> or a <c>redirect_uri</c> build it from.
/// </summary>
/// <remarks>
/// The host is the caller's to send, and some values make no URI: a port out of range, or a name the
/// <see cref="HttpRequest.Host"/> getter cannot decode, which it throws for. One owner, so every route that
/// builds a URI from the request refuses those the same way instead of failing while it builds one.
/// </remarks>
internal static class RequestOrigin
{
    /// <summary>
    /// <c>{scheme}://{host}</c> for <paramref name="request"/>, or false when its scheme is not http or https or
    /// its host makes no URI.
    /// </summary>
    public static bool TryGet(HttpRequest request, [NotNullWhen(true)] out string? origin)
    {
        // A wallet is handed an http or https URI and nothing else, whatever a forwarding proxy has set.
        if (!string.Equals(request.Scheme, "https", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(request.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            origin = null;
            return false;
        }

        string host;
        try
        {
            host = request.Host.ToUriComponent();
        }
        catch (ArgumentException)
        {
            origin = null;
            return false;
        }

        var candidate = $"{request.Scheme}://{host}";
        origin = Uri.TryCreate(candidate, UriKind.Absolute, out _) ? candidate : null;
        return origin is not null;
    }
}
