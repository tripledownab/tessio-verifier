using Tessio.Verifier.AspNetCore;

namespace Tessio.Verifier.ConformanceHarness;

/// <summary>
/// The two HTML pages. Kept out of Program.cs so the wiring stays readable and the file stays inside
/// the repository's size rule.
/// </summary>
internal static class Pages
{
    /// <summary>
    /// Error messages and claim values reach these pages from the wire, so escape them: a stray angle
    /// bracket in a suite error would otherwise silently mangle the screenshot we submit.
    /// </summary>
    private static string Esc(string value) => System.Net.WebUtility.HtmlEncode(value);

    /// <summary>
    /// One or more evidence rows for a disclosed claim. mdoc discloses claims as
    /// <c>namespace -&gt; { elementIdentifier -&gt; value }</c>, so a nested dictionary is flattened to a
    /// row per element (<c>namespace / element = value</c>) rather than printing the dictionary's type
    /// name. SD-JWT VC claims are scalar and render as a single row.
    /// </summary>
    private static string ClaimRows(string name, object? value)
    {
        if (value is System.Collections.IDictionary nested)
        {
            var rows = new List<string>();
            foreach (System.Collections.DictionaryEntry e in nested)
            {
                rows.Add($"<tr><td><code>{Esc(name)} / {Esc(e.Key.ToString() ?? "null")}</code></td>"
                    + $"<td>{Esc(FormatClaimValue(e.Value))}</td></tr>");
            }

            return string.Concat(rows);
        }

        return $"<tr><td><code>{Esc(name)}</code></td><td>{Esc(FormatClaimValue(value))}</td></tr>";
    }

    /// <summary>Renders a leaf claim value; shows byte strings (portrait, etc.) as a size, not raw bytes.</summary>
    private static string FormatClaimValue(object? value) => value switch
    {
        null => "null",
        byte[] bytes => $"[{bytes.Length} bytes]",
        _ => value.ToString() ?? "null",
    };

    private const string Style = """
        body { font: 15px/1.55 system-ui, sans-serif; margin: 2.5rem auto; max-width: 52rem; padding: 0 1rem; }
        dt { font-weight: 600; margin-top: .6rem; }
        dd { margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }
        table { border-collapse: collapse; margin: .5rem 0 1.5rem; width: 100%; }
        td, th { border: 1px solid #8884; padding: .4rem .6rem; text-align: left; vertical-align: top; }
        th { background: #8881; }
        code { font-family: ui-monospace, monospace; word-break: break-all; }
        pre { background: #8881; padding: .8rem; border-radius: .4rem; overflow-x: auto;
              font-size: 12px; line-height: 1.35; }
        .verdict { font-size: 1.5rem; font-weight: 700; padding: .9rem 1.2rem; border-radius: .5rem; margin: 1rem 0; }
        .ok { background: #2e7d3222; color: #1b5e20; }
        .fail { background: #c6282822; color: #b71c1c; }
        .pending { background: #8883; }
        .warn { background: #ef6c0022; color: #e65100; padding: .7rem 1rem; border-radius: .4rem; }
        a.start { display: inline-block; margin: 1.5rem 0; padding: .6rem 1.1rem;
                  background: #12395c; color: #fff; text-decoration: none; border-radius: .4rem; }
        """;

    /// <summary>
    /// Prints the configuration actually in effect. The commonest way to waste an afternoon here is
    /// running a module against a stale variant and only noticing at the screenshot.
    /// </summary>
    public static string Landing(HarnessSettings s)
    {
        var formatRow = s.IsMdoc
            ? $"<dt>Document type</dt><dd>{Esc(s.ExpectedDocType!)}</dd>"
              + $"<dt>Namespace</dt><dd>{Esc(s.MdocNamespace!)}</dd>"
            : $"<dt>Credential type (vct)</dt><dd>{Esc(s.ExpectedVct ?? "(unset)")}</dd>";

        // An identifier-only trust list rejects every x5c credential. For SD-JWT VC that depends on how
        // the suite signs, which is worth stating rather than discovering through eight bad screenshots.
        var trustWarning = s.TrustAnchors.Count == 0
            ? """
              <p class="warn"><strong>No trust anchors configured.</strong> This works only if the suite's
              credential is signed with a key resolved from issuer metadata. If it presents an x5c chain,
              every module will reject, and the negative modules will look like passes for the wrong
              reason. Set <code>Suite:TrustAnchors</code> if that happens.</p>
              """
            : $"<p>Trust anchors configured: <code>{s.TrustAnchors.Count}</code></p>";

        return $$"""
            <!doctype html>
            <meta charset="utf-8">
            <title>Tessio conformance harness</title>
            <style>{{Style}}</style>
            <h1>Tessio conformance harness</h1>
            <p>Verifier under test, driven by the OpenID Foundation conformance suite acting as the wallet.</p>
            <a class="start" href="/verify/start">Start a verification</a>
            <p>After the suite responds, open <code>/evidence/{sessionId}</code> for the screenshot artifact.</p>
            {{trustWarning}}
            <h2>Paste this into the suite</h2>
            <p>The plan's one configuration field is <code>client.request_object_trust_anchor_pem</code>.
               It is this certificate, and it is stable across restarts.</p>
            <pre>{{Esc(s.RequestObjectTrustAnchorPem)}}</pre>
            <h2>Configuration in effect</h2>
            <dl>
              <dt>client_id</dt><dd>{{Esc(s.ClientId)}}</dd>
              <dt>Credential format</dt><dd>{{Esc(s.CredentialFormat)}}</dd>
              {{formatRow}}
              <dt>Response mode</dt><dd>{{s.ResponseMode}}</dd>
              <dt>Requested claim</dt><dd>{{Esc(s.RequestedClaim)}}</dd>
              <dt>Suite authorization endpoint</dt><dd>{{Esc(s.AuthorizationEndpoint)}}</dd>
              <dt>Trusted issuer</dt><dd>{{Esc(s.Issuer)}}</dd>
              <dt>Request URI base</dt><dd>{{Esc(new Uri(s.PublicBaseUri, "verify/request").ToString())}}</dd>
            </dl>
            """;
    }

    /// <summary>
    /// The screenshot artifact. Eight of the twelve modules are negative tests where rejecting IS the
    /// pass, and each finishes as REVIEW against an uploaded image. The library's built-in status page
    /// prints "Verification failed" without the reason, which cannot distinguish "rejected the tampered
    /// sd_hash, exactly as required" from "rejected because the trust list was misconfigured".
    /// </summary>
    public static string Evidence(string sessionId, VerificationSession session, HarnessSettings s)
    {
        var result = session.Result;
        var verdictClass = result is null ? "pending" : result.IsValid ? "ok" : "fail";
        var verdictText = result is null ? "NO RESPONSE YET" : result.IsValid ? "ACCEPTED" : "REJECTED";

        var errors = result is null || result.Errors.Count == 0
            ? "<p><em>No errors recorded.</em></p>"
            : "<table><tr><th>Code</th><th>Message</th></tr>"
              + string.Concat(result.Errors.Select(e =>
                  $"<tr><td><code>{Esc(e.Code)}</code></td><td>{Esc(e.Message)}</td></tr>"))
              + "</table>";

        var claims = result is null || result.DisclosedClaims.Count == 0
            ? "<p><em>No claims disclosed.</em></p>"
            : "<table><tr><th>Claim</th><th>Value</th></tr>"
              + string.Concat(result.DisclosedClaims.Select(c => ClaimRows(c.Key, c.Value)))
              + "</table>";

        var issuer = result is null
            ? "<p><em>Not resolved.</em></p>"
            : "<table>"
              + $"<tr><td>Identifier</td><td><code>{Esc(result.Issuer.Identifier)}</code></td></tr>"
              + $"<tr><td>Trusted</td><td><code>{result.Issuer.Trusted}</code></td></tr>"
              + $"<tr><td>Key resolution</td><td><code>{Esc(result.Issuer.KeyResolutionMethod)}</code></td></tr>"
              + "</table>";

        // Only explain the negative-module convention when we actually rejected. This is a screenshot a
        // certification reviewer reads, so the word REJECTED must not appear on an ACCEPTED page.
        var negativeNote = result is { IsValid: false }
            ? "<p>For a negative test module, REJECTED is the expected outcome and the errors below are the evidence.</p>"
            : "";

        // Warn only when the rejection was OUR trust configuration, not the tampering under test.
        // Keyed off the error code, not Issuer.Trusted: a failed issuer signature also leaves Trusted
        // false (trust cannot be established over a signature that does not verify), and on the
        // invalid-credential-signature module that IS the behaviour under test, not a misconfiguration.
        // Only issuer_untrusted, and the issuer-resolution codes, mean the credential was refused
        // before the tampering could matter.
        string[] configCodes = ["issuer_untrusted", "issuer_key_unresolvable", "issuer_certificate_mismatch"];
        var trustNote = result is { IsValid: false } && result.Errors.Any(e => configCodes.Contains(e.Code))
            ? """
              <p class="warn"><strong>The issuer was not trusted.</strong> On a negative module this is
              probably the wrong rejection: the credential was refused before the tampering under test
              could matter. Check <code>Suite:Issuer</code> and <code>Suite:TrustAnchors</code>.</p>
              """
            : "";

        return $$"""
            <!doctype html>
            <meta charset="utf-8">
            <title>Evidence {{Esc(sessionId)}}</title>
            <style>{{Style}}</style>
            <h1>Verification evidence</h1>
            <p>Session <code>{{Esc(sessionId)}}</code> · status <code>{{Esc(session.Status.ToString())}}</code></p>
            <p>client_id <code>{{Esc(s.ClientId)}}</code> · format <code>{{Esc(s.CredentialFormat)}}</code>
               · response_mode <code>{{s.ResponseMode}}</code></p>
            <div class="verdict {{verdictClass}}">{{verdictText}}</div>
            {{negativeNote}}
            {{trustNote}}
            <h2>Errors</h2>
            {{errors}}
            <h2>Issuer</h2>
            {{issuer}}
            <h2>Disclosed claims</h2>
            {{claims}}
            """;
    }
}
