// What belongs in this file: the rules this library holds an origin to, in one place, because the
// transcripts, the signed request and the response all hash the same string. Every transcript refuses
// the 'origin:' prefix; the fuller syntactic check runs only before signing.
using System.Globalization;
using System.Text.RegularExpressions;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Checks on the origin a Digital Credentials API presentation is bound to.</summary>
internal static partial class BrowserOrigin
{
    // The prefix an Android app's origin carries when it calls the Digital Credentials API itself
    // rather than through a browser. multipaz builds the rest as the base64 SHA-256 of the app's
    // signing certificate (DigitalCredentialsExt.android.kt): 43 characters of base64 with the padding
    // trimmed. Either base64 alphabet is accepted, and one trailing '=' in case a caller padded it.
    private const string AndroidAppPrefix = "android:apk-key-hash:";

    // The default ports the URL Standard leaves out of an origin.
    private const int HttpsDefaultPort = 443;
    private const int HttpDefaultPort = 80;

    /// <summary>
    /// The <c>origin:</c> prefix belongs to the Client Identifier, never to a transcript. Refuse
    /// rather than strip it: a caller passing the prefixed form has confused the two values, and
    /// silently accepting it would produce a transcript that verifies here and nowhere else.
    /// </summary>
    public static void RequireBare(string origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (origin.StartsWith("origin:", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The Origin must not carry the 'origin:' Client Identifier Prefix. Pass the bare origin, " +
                "for example https://verifier.example.com.", nameof(origin));
        }
    }

    /// <summary>
    /// Refuses the origins a caller is likely to get wrong: a missing scheme, a path or trailing
    /// slash, upper case, a default port, stray whitespace or a non-ASCII host. A signed request is
    /// the first place a wrong origin shows: before signing, it surfaced only as a response that would
    /// not decrypt. This is a syntactic guard, not a URL parser: it never says what the browser would
    /// report, and it accepts some strings no browser reports (among others non-canonical IPv4 such
    /// as <c>https://127.1</c>, IPv6 not in the serializer's exact form, hosts no URL parser accepts),
    /// which then fail at the wallet as any wrong origin did before.
    /// </summary>
    // SPEC: the HTML Standard's serialization of a tuple origin is scheme "://" host, then ":" port
    // only when the origin's port is non-null, which the URL Standard sets to null for the scheme's
    // default port. Its host parser runs domain-to-ASCII, so a domain is lower-case ASCII, punycode
    // for anything else; its IPv6 serializer writes each piece as "the shortest possible lowercase
    // hexadecimal number" and has no dotted IPv4 form. The pattern holds what a regular expression
    // holds cheaply; the summary lists what it accepts anyway.
    public static void RequireSerialized(string origin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        if (AndroidAppOrigin().IsMatch(origin))
        {
            return;
        }

        var match = WebOrigin().Match(origin);
        if (!match.Success)
        {
            throw new ArgumentException(
                $"'{origin}' is not an origin as a browser serializes one: http or https, '://', a lower-case ASCII "
                + "host (punycode for an internationalised name), and a port only when it is not the default, with no "
                + $"path or trailing slash. An Android app's origin starts '{AndroidAppPrefix}'.",
                nameof(origin));
        }

        if (match.Groups["port"].Success)
        {
            var port = int.Parse(match.Groups["port"].Value, CultureInfo.InvariantCulture);
            var defaultPort = match.Groups["scheme"].Value == "https" ? HttpsDefaultPort : HttpDefaultPort;
            if (port == defaultPort || port > ushort.MaxValue)
            {
                throw new ArgumentException(
                    $"'{origin}' carries port {port}, which a browser never reports: it leaves out the scheme's default "
                    + "port and has none above 65535.", nameof(origin));
            }
        }
    }

    // scheme://host[:port] and nothing after. A host is lower-case ASCII labels (letters, digits,
    // hyphen and underscore, which the URL Standard allows; this covers IPv4 and punycode) with an
    // optional trailing dot, or a bracketed lower-case hexadecimal IPv6 address. A port has no
    // leading zero.
    [GeneratedRegex(
        @"\A(?<scheme>https?)://(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?|\[[0-9a-f:]+\])(?::(?<port>[1-9][0-9]{0,4}))?\z",
        RegexOptions.CultureInvariant)]
    private static partial Regex WebOrigin();

    [GeneratedRegex(@"\Aandroid:apk-key-hash:[A-Za-z0-9_+/-]{43}=?\z", RegexOptions.CultureInvariant)]
    private static partial Regex AndroidAppOrigin();
}
