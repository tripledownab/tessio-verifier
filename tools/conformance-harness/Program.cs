using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.AspNetCore;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

// Harness for the OpenID Foundation conformance suite, verifier side. See README.md.
//
// The suite plays the wallet and we play the verifier, so the traffic runs opposite to normal
// testing: the suite fetches our signed request, mints a credential, and posts a presentation back
// for us to accept or reject. Eight of the twelve modules are negative tests where rejecting is the
// pass, which is why the evidence page below reports the failing check rather than a bare "invalid".

var builder = WebApplication.CreateBuilder(args);

// The two suite values are per-run and not ours to commit, so they live in an untracked local file
// rather than in appsettings.json. Named rather than environment-based so the error message below can
// point at a file that actually gets read.
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false);

var cfg = builder.Configuration;

string Required(string key) => cfg[key] is { Length: > 0 } value
    ? value
    : throw new InvalidOperationException(
        $"Missing configuration '{key}'. Create the test plan in the suite first, then copy its values "
        + "into appsettings.Local.json. See README.md.");

// Error messages and claim values reach the evidence page from the wire, so escape them: a stray
// angle bracket in a suite error would otherwise silently mangle the screenshot we submit.
static string Esc(string value) => System.Net.WebUtility.HtmlEncode(value);

var publicBaseUri = new Uri(Required("PublicBaseUri"));
var credentialFormat = cfg["Request:CredentialFormat"] ?? "dc+sd-jwt";
var responseMode = Enum.Parse<ResponseMode>(cfg["Request:ResponseMode"] ?? nameof(ResponseMode.DirectPostJwt));
var requestedClaim = cfg["Request:Claim"] ?? "age_over_18";

// A fresh EC key and self-signed certificate per run. The suite checks that the x509_hash in our
// client_id matches the leaf we send in x5c, not that the chain is publicly trusted, so self-signed
// is sufficient and keeps real access-certificate material out of this tool entirely.
var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var certificate = new CertificateRequest(
        "CN=conformance.tessio.local", key, HashAlgorithmName.SHA256)
    .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

var clientId = ClientIdentifier.X509Hash(certificate);

builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),

        // The wallet has no other way to obtain the certificate whose hash it must check.
        SigningCertificateChain = [certificate],

        // HAIP pins request_method to request_uri_signed, so the JAR is fetched rather than inlined.
        // The suite runs in Docker and reaches us over host.docker.internal, hence PublicBaseUri.
        RequestUriBase = new Uri(publicBaseUri, "verify/request"),

        // Point the wallet-facing URI at the suite's mock wallet instead of the openid4vp:// scheme.
        AuthorizationEndpoint = Required("Suite:AuthorizationEndpoint"),
    }));

// The suite signs the credentials it issues with its own key, so it is the issuer we have to trust.
// Live mode refuses to start with the dev resolver still registered, which is the point.
builder.Services.AddSingleton<ITrustListResolver>(new StaticTrustListResolver(
    [Required("Suite:Issuer")], source: "oidf-conformance-suite"));

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;
    options.ClientId = clientId;

    // The suite requires the DCQL query to name exactly one credential.
    options.RequestedClaims = [requestedClaim];
    options.CredentialFormat = credentialFormat;
    options.ResponseMode = responseMode;

    if (cfg["Request:ExpectedVct"] is { Length: > 0 } vct)
    {
        options.ExpectedVct = vct;
    }
});

var app = builder.Build();

// Present the public authority on every request.
//
// The library derives response_uri from Request.Host, which is right: in production you sit behind a
// proxy and UseForwardedHeaders supplies the public name. Here there is no proxy, so a browser on
// localhost would mint response_uri = http://localhost:5099/verify/callback, and "localhost" inside
// the suite's container is the container itself. The wallet would post the presentation to itself and
// the session would sit pending until it expired, with nothing in either log to say why.
//
// host.docker.internal does not resolve on the host, so we cannot simply browse through it either.
app.Use(async (context, next) =>
{
    context.Request.Host = new HostString(publicBaseUri.Authority);
    context.Request.Scheme = publicBaseUri.Scheme;
    await next();
});

app.MapTessioVerifier();

// Landing page. Prints the configuration actually in effect, because the commonest way to waste an
// afternoon here is running a module against a stale variant and only noticing at the screenshot.
app.MapGet("/", () => Results.Content($$"""
    <!doctype html>
    <meta charset="utf-8">
    <title>Tessio conformance harness</title>
    <style>
      body { font: 15px/1.55 system-ui, sans-serif; margin: 2.5rem auto; max-width: 46rem; padding: 0 1rem; }
      dt { font-weight: 600; margin-top: .6rem; }
      dd { margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }
      a.start { display: inline-block; margin: 1.5rem 0; padding: .6rem 1.1rem;
                background: #12395c; color: #fff; text-decoration: none; border-radius: .4rem; }
    </style>
    <h1>Tessio conformance harness</h1>
    <p>Verifier under test, driven by the OpenID Foundation conformance suite acting as the wallet.</p>
    <a class="start" href="/verify/start">Start a verification</a>
    <p>After the suite responds, open <code>/evidence/{sessionId}</code> for the screenshot artifact.</p>
    <h2>Configuration in effect</h2>
    <dl>
      <dt>client_id</dt><dd>{{Esc(clientId)}}</dd>
      <dt>Credential format</dt><dd>{{Esc(credentialFormat)}}</dd>
      <dt>Response mode</dt><dd>{{responseMode}}</dd>
      <dt>Requested claim</dt><dd>{{Esc(requestedClaim)}}</dd>
      <dt>Suite authorization endpoint</dt><dd>{{Esc(Required("Suite:AuthorizationEndpoint"))}}</dd>
      <dt>Trusted issuer</dt><dd>{{Esc(Required("Suite:Issuer"))}}</dd>
      <dt>Request URI base</dt><dd>{{Esc(new Uri(publicBaseUri, "verify/request").ToString())}}</dd>
    </dl>
    """, "text/html"));

// Evidence page. Each module finishes as REVIEW against an uploaded screenshot, and eight of the
// twelve are negative tests where rejecting IS the pass. The library's built-in status page reports
// "Verification failed" without saying which check failed, which is a weak artifact to submit: it
// cannot distinguish "rejected the tampered sd_hash, as required" from "rejected for an unrelated
// reason". So render the errors, the issuer and the disclosed claims in full.
app.MapGet("/evidence/{sessionId}", async (string sessionId, ISessionStore store, CancellationToken ct) =>
{
    var session = await store.GetAsync(sessionId, ct);
    if (session is null)
    {
        return Results.NotFound($"No session '{sessionId}'.");
    }

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
          + string.Concat(result.DisclosedClaims.Select(c =>
              $"<tr><td><code>{Esc(c.Key)}</code></td><td>{Esc(c.Value?.ToString() ?? "null")}</td></tr>"))
          + "</table>";

    var issuer = result is null
        ? "<p><em>Not resolved.</em></p>"
        : "<table>"
          + $"<tr><td>Identifier</td><td><code>{Esc(result.Issuer.Identifier)}</code></td></tr>"
          + $"<tr><td>Trusted</td><td><code>{result.Issuer.Trusted}</code></td></tr>"
          + $"<tr><td>Key resolution</td><td><code>{Esc(result.Issuer.KeyResolutionMethod)}</code></td></tr>"
          + "</table>";

    return Results.Content($$"""
        <!doctype html>
        <meta charset="utf-8">
        <title>Evidence {{Esc(sessionId)}}</title>
        <style>
          body { font: 15px/1.55 system-ui, sans-serif; margin: 2.5rem auto; max-width: 52rem; padding: 0 1rem; }
          .verdict { font-size: 1.5rem; font-weight: 700; padding: .9rem 1.2rem; border-radius: .5rem; margin: 1rem 0; }
          .ok { background: #2e7d3222; color: #1b5e20; }
          .fail { background: #c6282822; color: #b71c1c; }
          .pending { background: #8883; }
          table { border-collapse: collapse; margin: .5rem 0 1.5rem; width: 100%; }
          td, th { border: 1px solid #8884; padding: .4rem .6rem; text-align: left; vertical-align: top; }
          th { background: #8881; }
          code { font-family: ui-monospace, monospace; word-break: break-all; }
        </style>
        <h1>Verification evidence</h1>
        <p>Session <code>{{Esc(sessionId)}}</code> · status <code>{{Esc(session.Status.ToString())}}</code></p>
        <p>client_id <code>{{Esc(clientId)}}</code> · format <code>{{Esc(credentialFormat)}}</code>
           · response_mode <code>{{responseMode}}</code></p>
        <div class="verdict {{verdictClass}}">{{verdictText}}</div>
        <p>For a negative test module, REJECTED is the expected outcome and the errors below are the evidence.</p>
        <h2>Errors</h2>
        {{errors}}
        <h2>Issuer</h2>
        {{issuer}}
        <h2>Disclosed claims</h2>
        {{claims}}
        """, "text/html");
});

app.Lifetime.ApplicationStopped.Register(() =>
{
    certificate.Dispose();
    key.Dispose();
});

app.Run();
