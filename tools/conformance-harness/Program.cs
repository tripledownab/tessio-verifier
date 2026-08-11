using Tessio.Verifier.ConformanceHarness;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.AspNetCore;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

// Harness for the OpenID Foundation conformance suite, verifier side. See README.md.
//
// The suite plays the wallet and we play the verifier, so the traffic runs opposite to normal
// testing: the suite fetches our signed request, mints a credential, and posts a presentation back
// for us to accept or reject. Eight of the twelve modules are negative tests where rejecting is the
// pass, which is why Pages.Evidence reports the failing check rather than a bare "invalid".

var builder = WebApplication.CreateBuilder(args);

// The suite values are per-run and not ours to commit, so they live in an untracked local file rather
// than in appsettings.json. Named rather than environment-based so the error message can point at a
// file that actually gets read.
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false);

// Persisted between runs on purpose: this certificate is what you paste into the plan's
// client.request_object_trust_anchor_pem field, so regenerating it would invalidate the suite
// configuration on every restart. See HarnessCertificate.
var signing = HarnessCertificate.LoadOrCreate(
    builder.Configuration["Certificate:LeafPath"] ?? "harness-leaf.pem",
    builder.Configuration["Certificate:KeyPath"] ?? "harness-key.pem",
    builder.Configuration["Certificate:AuthorityPath"] ?? "harness-ca.pem");

// HTTPS, because OpenID4VP 1.0 requires request_uri (JAR-5.2) and response_uri (§8.2) to be https.
// A self-signed chain suffices: the suite installs a trust-all X509TrustManager and a
// NoopHostnameVerifier, so nothing has to be added to the container's truststore.
builder.WebHost.ConfigureKestrel(kestrel =>
    kestrel.ListenAnyIP(
        new Uri(builder.Configuration["PublicBaseUri"]!).Port,
        listen => listen.UseHttps(signing.TlsCertificate())));

var settings = HarnessSettings.Load(builder.Configuration) with
{
    ClientId = ClientIdentifier.X509Hash(signing.Leaf),
    RequestObjectTrustAnchorPem = signing.AuthorityPem,
};

builder.Services.AddSingleton(settings);

builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(signing.Key), SecurityAlgorithms.EcdsaSha256),

        // The wallet has no other way to obtain the certificate whose hash it must check.
        SigningCertificateChain = signing.Chain,

        // HAIP pins request_method to request_uri_signed, so the JAR is fetched rather than inlined.
        // The suite runs in Docker and reaches us over host.docker.internal, hence PublicBaseUri.
        RequestUriBase = new Uri(settings.PublicBaseUri, "verify/request"),

        // Point the wallet-facing URI at the suite's mock wallet instead of the openid4vp:// scheme.
        AuthorizationEndpoint = settings.AuthorizationEndpoint,
    }));

// The suite signs the credentials it issues with its own key, so it is the issuer we have to trust.
// Anchors matter when that key arrives in an x5c or x5chain header: without them StaticTrustListResolver
// rejects every such credential, which would fail the positive modules and, worse, make the negative
// ones look like passes. HarnessSettings refuses to start in the mdoc case, where anchors are mandatory.
builder.Services.AddSingleton<ITrustListResolver>(new StaticTrustListResolver(
    [settings.Issuer], source: "oidf-conformance-suite", trustAnchors: settings.TrustAnchors));

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;
    options.ClientId = settings.ClientId;

    // The suite requires the DCQL query to name exactly one credential.
    options.RequestedClaims = [settings.RequestedClaim];
    options.CredentialFormat = settings.CredentialFormat;
    options.ResponseMode = settings.ResponseMode;

    if (settings.ExpectedVct is { Length: > 0 } vct)
    {
        options.ExpectedVct = vct;
    }

    if (settings.IsMdoc)
    {
        options.ExpectedDocType = settings.ExpectedDocType!;
        options.MdocNamespace = settings.MdocNamespace!;
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
    // Two audiences, two hostnames. request_uri and response_uri are minted at /verify/start and
    // fetched by the suite's container, so they must say host.docker.internal. redirect_uri is minted
    // at /verify/callback and followed by the BROWSER, which cannot resolve that name at all: only the
    // container can. Rewriting everything to one host sends the user to a dead address after an
    // otherwise successful verification.
    var target = context.Request.Path.StartsWithSegments("/verify/callback")
        ? settings.BrowserBaseUri
        : settings.PublicBaseUri;

    context.Request.Host = new HostString(target.Authority);
    context.Request.Scheme = target.Scheme;
    await next();
});

app.MapTessioVerifier();

app.MapGet("/", (HarnessSettings s) => Results.Content(Pages.Landing(s), "text/html"));

app.MapGet("/evidence/{sessionId}", async (
    string sessionId, ISessionStore store, HarnessSettings s, CancellationToken ct) =>
{
    var session = await store.GetAsync(sessionId, ct);
    return session is null
        ? Results.NotFound($"No session '{sessionId}'.")
        : Results.Content(Pages.Evidence(sessionId, session, s), "text/html");
});

app.Lifetime.ApplicationStopped.Register(() =>
{
    foreach (var anchor in settings.TrustAnchors)
    {
        anchor.Dispose();
    }

    signing.Dispose();
});

app.Run();
