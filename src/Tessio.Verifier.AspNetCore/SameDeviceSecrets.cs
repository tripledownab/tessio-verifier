using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The secrets of the same-device flow: the browser binding cookie, the response code, and how each is
/// hashed before a store sees it.
/// </summary>
internal static class SameDeviceSecrets
{
    /// <summary>
    /// The binding cookie. <c>__Host-</c>, so a browser accepts it only from this exact origin over HTTPS
    /// with <c>Path=/</c> and no <c>Domain</c>: a sibling host under the same parent domain cannot plant one.
    /// </summary>
    public const string BindingCookie = "__Host-tessio-verifier-binding";

    /// <summary>
    /// Longer than any secret this flow mints, so a pasted page of text is refused unread.
    /// </summary>
    public const int MaxSecretLength = 128;

    /// <summary>
    /// How long a held presentation waits for its browser to come back. The hop it covers is a wallet app
    /// handing a URL to the browser, which takes seconds. Two minutes leaves room for a slow device without
    /// keeping a presentation waiting long after anyone could still be coming back for it.
    /// </summary>
    public static readonly TimeSpan RedemptionWindow = TimeSpan.FromMinutes(2);

    /// <summary>
    /// A day rather than a session cookie, which is lost if the browser is closed while the wallet has the
    /// screen, as a mobile system may do to free memory.
    /// </summary>
    private static readonly TimeSpan BindingCookieLifetime = TimeSpan.FromDays(1);

    public static CookieOptions BindingCookieOptions() => new()
    {
        HttpOnly = true,
        Secure = true,
        // Lax, not Strict: the redirect back from the wallet is a top-level navigation from another app, and
        // the page it lands on redeems with a same-origin request, which carries a Lax cookie.
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = BindingCookieLifetime,
    };

    /// <summary>A 256-bit random value, base64url encoded: a browser secret or a response code.</summary>
    public static string NewSecret() => Tokens.NewNonce();

    /// <summary>The browser's secret from its binding cookie, or null when it has none or it is malformed.</summary>
    public static string? BrowserSecret(HttpRequest request) =>
        request.Cookies[BindingCookie] is { Length: > 0 and <= MaxSecretLength } secret ? secret : null;

    /// <summary>
    /// The hash a store keeps for a response code or a browser secret. A store holding only hashes cannot
    /// redeem a presentation or impersonate a browser.
    /// </summary>
    public static byte[] Hash(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));
}
