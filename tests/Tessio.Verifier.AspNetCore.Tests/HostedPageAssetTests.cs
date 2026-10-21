using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The hosted pages' scripts and styles: what they may contain, and the content security policy that lets
/// exactly them run on the page that carries them.
/// </summary>
public sealed partial class HostedPageAssetTests
{
    public static TheoryData<string> Pages => ["start", "return"];

    [Fact]
    public void ThePageScripts_NeverWriteMarkupFromAValue()
    {
        // An issuer identifier on a failing result is whatever the presenter put there. The scripts build
        // every element with textContent, so this rule is what keeps it text.
        string[] scripts = [HostedPageAssets.StartScript.Content, HostedPageAssets.ReturnScript.Content];

        Assert.All(scripts, script =>
        {
            Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("outerHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("insertAdjacentHTML", script, StringComparison.Ordinal);
            Assert.DoesNotContain("document.write", script, StringComparison.Ordinal);
        });
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void ThePolicy_AllowsExactlyThePagesOwnScriptAndStyle(string name)
    {
        var page = Render(name);

        // Hashed here from the HTML as a browser reads it, not taken from the code that wrote the policy, so
        // a page that writes its script differently from what was hashed fails.
        var script = Assert.Single(ModuleScript().Matches(page.Html)).Groups[1].Value;
        var style = Assert.Single(StyleElement().Matches(page.Html)).Groups[1].Value;
        Assert.Equal(
            $"default-src 'none'; script-src {Hash(script)}; style-src {Hash(style)}; connect-src 'self'; "
            + "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            page.ContentSecurityPolicy);
    }

    [Fact]
    public void AnAssetCheckedOutWithWindowsLineEndings_IsHashedAsABrowserReadsIt()
    {
        // A browser's HTML parser turns CRLF and a lone CR into LF before it hashes an inline script, so a
        // CRLF checkout must yield the hash an LF one does, or no page would run its script.
        var crlf = new HostedPageAssets.InlineAsset("first();\r\nsecond();\rthird();\r\n");
        var lf = new HostedPageAssets.InlineAsset("first();\nsecond();\nthird();\n");

        Assert.Equal(lf.HashSource, crlf.HashSource);
        Assert.DoesNotContain('\r', crlf.Content);
        Assert.Equal(Hash("first();\nsecond();\nthird();\n"), crlf.HashSource);

        // The parser leaves the Unicode line separators alone, so the hash must too.
        Assert.Equal("a\u2028b", new HostedPageAssets.InlineAsset("a\u2028b").Content);
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void APage_RunsNoScriptOrStyleThePolicyDoesNotName(string name)
    {
        var page = Render(name).Html;

        // One executable script, a module because the return page awaits at its top level, and the data
        // block, which a browser does not run. Anything else inline would be refused, a page that silently
        // does not work.
        var scripts = ScriptTag().Matches(page).Select(m => m.Value).ToList();
        Assert.Equal(2, scripts.Count);
        Assert.Contains(scripts, s => s == "<script type=\"module\">");
        Assert.Contains(scripts, s => s == "<script id=\"page-config\" type=\"application/json\">");
        Assert.DoesNotContain("style=", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(EventHandlerAttribute(), page);
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public async Task EveryPage_IsServedWithItsPolicy(string name)
    {
        await using var host = new SameDeviceHost();
        var path = name == "start"
            ? "/verify/start"
            : $"/verify/{(await host.CreateCrossDeviceSessionAsync()).SessionId}/return";

        var response = await host.Client.GetAsync(path);
        var html = await response.Content.ReadAsStringAsync();

        var policy = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains(Hash(Assert.Single(ModuleScript().Matches(html)).Groups[1].Value), policy, StringComparison.Ordinal);
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    private static HostedPage Render(string name) => name == "start"
        ? HostedPages.Start("s", "/verify", VerifierMode.Live, "openid4vp://authorize?x=1", offerSameDevice: true)
        : HostedPages.Return("s", "/verify", offerRedemption: true);

    private static string Hash(string text) => $"'sha256-{Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text)))}'";

    [GeneratedRegex("<script type=\"module\">(.*?)</script>", RegexOptions.Singleline)]
    private static partial Regex ModuleScript();

    [GeneratedRegex("<style>(.*?)</style>", RegexOptions.Singleline)]
    private static partial Regex StyleElement();

    [GeneratedRegex("<script[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptTag();

    [GeneratedRegex("<[a-zA-Z][^>]*\\son[a-z]+\\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex EventHandlerAttribute();
}
