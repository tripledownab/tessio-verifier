using System.Security.Cryptography;
using System.Text;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The hosted pages' markup, styles and scripts, read once from the files under <c>PageAssets/</c> that the
/// build embeds, and the content security policy hashes that let exactly those scripts and styles run.
/// <see cref="HostedPages"/> fills in the markup's placeholders; nothing here is built from a value.
/// </summary>
/// <remarks>
/// <para>
/// The scripts and styles are files rather than C# strings so that tools read them as what they are:
/// CodeQL's JavaScript analysis scans <c>PageAssets/*.js</c>, which it cannot do for a script inside a
/// string. It reads each file on its own, so a value that crosses files, such as a result arriving on the
/// stream in <c>shared.js</c>, is not followed from one to the next. The rule that such values reach the
/// page only as text is held by a unit test as well.
/// </para>
/// <para>
/// A page still carries them inline, so it is one response that cannot load a script from another build.
/// Its policy names each inline script and style by its SHA-256 hash, and a browser runs nothing else
/// inline: not an injected script, not an event handler attribute.
/// </para>
/// </remarks>
internal static class HostedPageAssets
{
    /// <summary>The prefix the build gives every embedded page asset, in the project file.</summary>
    private const string ResourcePrefix = "Tessio.Verifier.AspNetCore.PageAssets.";

    public static readonly string PageTemplate = Read("page.html");

    public static readonly string StartBody = Read("start.html");

    public static readonly string SameDeviceButton = Read("same-device-button.html");

    public static readonly string ReturnBody = Read("return.html");

    /// <summary>The stylesheet every page carries inline.</summary>
    public static readonly InlineAsset Style = new(Read("pages.css"));

    /// <summary>
    /// The start page's module: the shared script, then the page's own. One module, because a page has one
    /// inline script and an inline module cannot import another.
    /// </summary>
    public static readonly InlineAsset StartScript = new(Read("shared.js") + Read("start.js"));

    /// <summary>The return page's module, built as <see cref="StartScript"/> is.</summary>
    public static readonly InlineAsset ReturnScript = new(Read("shared.js") + Read("return.js"));

    /// <summary>A script or stylesheet a page carries inline, with the hash its policy allows it by.</summary>
    public sealed record InlineAsset
    {
        /// <param name="content">
        /// The text, with its line breaks made <c>\n</c>. A browser hashes the text between the element's tags
        /// after the HTML parser has turned every CRLF and lone CR into LF, so hashing a CRLF checkout's bytes
        /// as they stand would name a script the browser never sees, and every page would stop working.
        /// </param>
        public InlineAsset(string content)
        {
            // Exactly what the parser does, and no more: string.ReplaceLineEndings would also rewrite U+2028
            // and the other Unicode line separators, which the parser leaves alone.
            Content = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
            HashSource = $"'sha256-{Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(Content)))}'";
        }

        /// <summary>The text the page writes between the element's tags.</summary>
        public string Content { get; }

        /// <summary>
        /// The CSP source expression for exactly <see cref="Content"/>: <c>'sha256-</c>, the base64 SHA-256 of
        /// its UTF-8 bytes, and <c>'</c>.
        /// </summary>
        public string HashSource { get; }
    }

    private static string Read(string name)
    {
        using var stream = typeof(HostedPageAssets).Assembly.GetManifestResourceStream(ResourcePrefix + name)
            ?? throw new InvalidOperationException(
                $"The page asset '{name}' is not embedded in {typeof(HostedPageAssets).Assembly.GetName().Name}.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
