using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Renders the HTML pages the built-in endpoints serve to a browser: the start page a verification begins
/// on, and the return page a same-device wallet's redirect lands on. The markup and scripts themselves are
/// in <see cref="HostedPageAssets"/>.
/// </summary>
/// <remarks>
/// Values reach a page's script as a JSON configuration block, never spliced into script text, so the
/// scripts are fixed text that no session id or URL can change. Values in markup are HTML encoded.
/// </remarks>
internal static partial class HostedPages
{
    private static readonly JsonSerializerOptions ConfigOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Renders the authorization request URI as an SVG QR code for cross-device scanning. Returns an
    /// empty string when the payload exceeds QR capacity (huge by-value JARs); the page then shows
    /// the URI only. Keep requests scannable with by-reference delivery (see docs/going-live.md).
    /// </summary>
    internal static string RenderQrCode(string payload)
    {
        try
        {
            using var generator = new QRCoder.QRCodeGenerator();
            using var data = generator.CreateQrCode(payload, QRCoder.QRCodeGenerator.ECCLevel.L);
            return new QRCoder.SvgQRCode(data).GetGraphic(
                4, "#000000", "#ffffff", sizingMode: QRCoder.SvgQRCode.SizingMode.ViewBoxAttribute);
        }
        catch (QRCoder.Exceptions.DataTooLongException)
        {
            return string.Empty;
        }
    }

    /// <param name="sessionId">The session the page shows.</param>
    /// <param name="prefix">The route prefix the endpoints are mapped under.</param>
    /// <param name="mode">The verifier mode, shown on the page.</param>
    /// <param name="authorizationRequestUri">The request a wallet is handed, as a QR code and as text.</param>
    /// <param name="offerSameDevice">Whether to show the button that opens a wallet on this device.</param>
    public static string Start(
        string sessionId, string prefix, VerifierMode mode, string authorizationRequestUri, bool offerSameDevice)
    {
        var body = Fill(HostedPageAssets.StartBody, new Dictionary<string, string>
        {
            ["SESSION_ID"] = WebUtility.HtmlEncode(sessionId),
            ["MODE"] = WebUtility.HtmlEncode(mode.ToString()),
            ["SAME_DEVICE_BUTTON"] = offerSameDevice ? HostedPageAssets.SameDeviceButton : "",
            // In Live mode scanning IS the flow; open the request section by default.
            ["DETAILS_OPEN"] = mode == VerifierMode.Live ? "open" : "",
            ["STATUS_URL"] = WebUtility.HtmlEncode(SessionUrl(prefix, sessionId, "")),
            ["AUTH_URI"] = WebUtility.HtmlEncode(authorizationRequestUri),
            ["QR_SVG"] = RenderQrCode(authorizationRequestUri),
        });

        var config = new PageConfig
        {
            StreamUrl = SessionUrl(prefix, sessionId, "/stream"),
            SameDeviceUrl = offerSameDevice ? $"{prefix}/same-device" : null,
        };
        return Page(body, config, HostedPageAssets.StartScript);
    }

    /// <param name="sessionId">The session the wallet's redirect names.</param>
    /// <param name="prefix">The route prefix the endpoints are mapped under.</param>
    /// <param name="offerRedemption">
    /// Whether the page redeems the response code, which it can only when the store runs the same-device flow.
    /// </param>
    public static string Return(string sessionId, string prefix, bool offerRedemption)
    {
        var body = Fill(HostedPageAssets.ReturnBody, new Dictionary<string, string>
        {
            ["SESSION_ID"] = WebUtility.HtmlEncode(sessionId),
        });
        var config = new PageConfig
        {
            StreamUrl = SessionUrl(prefix, sessionId, "/stream"),
            RedeemUrl = offerRedemption ? SessionUrl(prefix, sessionId, "/redeem") : null,
        };
        return Page(body, config, HostedPageAssets.ReturnScript);
    }

    /// <summary>
    /// The page around <paramref name="body"/>, with <paramref name="config"/> in a JSON block and the
    /// shared script followed by the page's own in one module.
    /// </summary>
    /// <remarks>
    /// The serializer's default encoder escapes <c>&lt;</c>, <c>&gt;</c> and <c>&amp;</c>, so no value in the
    /// configuration can close the script element it sits in. A session id is whatever the store minted,
    /// and a host's store is free to mint ids this library would not.
    /// </remarks>
    private static string Page(string body, PageConfig config, string pageScript) =>
        Fill(HostedPageAssets.PageTemplate, new Dictionary<string, string>
        {
            ["BODY"] = body,
            ["CONFIG"] = JsonSerializer.Serialize(config, ConfigOptions),
            ["SCRIPT"] = HostedPageAssets.SharedScript + pageScript,
        });

    /// <summary>A URL under one session, its id escaped as a path segment.</summary>
    private static string SessionUrl(string prefix, string sessionId, string suffix) =>
        $"{prefix}/{Uri.EscapeDataString(sessionId)}{suffix}";

    /// <summary>
    /// Replaces every <c>__NAME__</c> placeholder in <paramref name="template"/> in a single pass, so a value
    /// is never read again for placeholders: a session id that happens to contain <c>__BODY__</c> stays text.
    /// A placeholder with no value throws, so a template and its caller cannot drift apart unnoticed.
    /// </summary>
    private static string Fill(string template, Dictionary<string, string> values) =>
        Placeholder().Replace(template, match => values.TryGetValue(match.Groups[1].Value, out var value)
            ? value
            : throw new InvalidOperationException($"The page template has no value for {match.Value}."));

    [GeneratedRegex("__([A-Z_]+?)__")]
    private static partial Regex Placeholder();

    /// <summary>What a page's script reads from its configuration block.</summary>
    private sealed record PageConfig
    {
        public required string StreamUrl { get; init; }

        public string? SameDeviceUrl { get; init; }

        public string? RedeemUrl { get; init; }
    }
}
