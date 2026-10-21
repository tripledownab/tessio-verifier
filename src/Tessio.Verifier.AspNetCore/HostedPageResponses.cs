using Microsoft.AspNetCore.Http;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// How a hosted page goes out over HTTP: the headers every one carries, and the content security policy
/// that confines it to the script and style it was built with.
/// </summary>
internal static class HostedPageResponses
{
    /// <summary>
    /// The policy for a page whose inline script and style are <paramref name="script"/> and
    /// <see cref="HostedPageAssets.Style"/>. Only those run, named by hash, so no other inline script,
    /// event handler or style does, including one that markup carried in a value might hold. The page
    /// connects to this origin only, loads images from it only, submits no form and cannot be framed.
    /// </summary>
    /// <remarks>
    /// The configuration block is <c>type="application/json"</c>, which a browser does not run as script.
    /// The QR code is inline SVG built from attributes, which needs no style or image source. Images from
    /// this origin are allowed for the site's favicon, which a browser fetches for any page it shows.
    /// </remarks>
    public static string ContentSecurityPolicy(HostedPageAssets.InlineAsset script) =>
        $"default-src 'none'; script-src {script.HashSource}; style-src {HostedPageAssets.Style.HashSource}; "
        + "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    /// <summary>Writes a hosted page with the headers every one of them carries.</summary>
    /// <remarks>
    /// no-store, because a page carries a session's authorization request or its result, and a cache handing
    /// it to the next visitor would give two people one session.
    /// </remarks>
    public static Task WritePageAsync(HttpContext http, HostedPage page)
    {
        http.Response.ContentType = "text/html; charset=utf-8";
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.ContentSecurityPolicy = page.ContentSecurityPolicy;
        http.Response.Headers.XContentTypeOptions = "nosniff";
        return http.Response.WriteAsync(page.Html, http.RequestAborted);
    }
}

/// <summary>A rendered hosted page and the policy it must be served with to work.</summary>
internal sealed record HostedPage(string Html, string ContentSecurityPolicy);
