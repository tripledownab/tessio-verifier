using Tessio.Verifier.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // auto-completes locally, no real wallet needed
    options.RequestedClaims = ["age_over_18"]; // selective disclosure: ask only for what you need
});

var app = builder.Build();

app.MapTessioVerifier();   // /verify/start, /verify/{id}, /verify/{id}/stream (SSE), /verify/callback

app.MapGet("/", () => Results.Content(
    """
    <!doctype html>
    <meta charset="utf-8">
    <title>Tessio.Verifier sample</title>
    <p><a href="/verify/start">Start a verification</a> (DEMO mode)</p>
    """,
    "text/html"));

app.Run();
