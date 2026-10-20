using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The wallet's <c>response_uri</c>, <c>POST {prefix}/callback</c> and its same-device twin: reading the form,
/// handing it to <see cref="WalletCallbackProcessor"/>, and answering the wallet with a status and a
/// <c>redirect_uri</c>.
/// </summary>
internal static class WalletCallbackEndpoint
{
    /// <summary>
    /// The callback path under the route prefix for a cross-device request, the start page's own. A
    /// same-device request names <see cref="SameDeviceRequests.CallbackPath"/> instead.
    /// </summary>
    public const string CallbackPath = "/callback";

    public static async Task HandleAsync(HttpContext http, string prefix, JsonSerializerOptions serializerOptions)
    {
        // SPEC: OpenID4VP 1.0 §8.2 — wallets POST application/x-www-form-urlencoded to response_uri.
        if (!http.Request.HasFormContentType)
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            await http.Response.WriteAsJsonAsync(
                new { error = "invalid_request", message = "Expected an application/x-www-form-urlencoded wallet response." },
                serializerOptions, http.RequestAborted).ConfigureAwait(false);
            return;
        }

        var form = await http.Request.ReadFormAsync(http.RequestAborted).ConfigureAwait(false);
        var response = new Tessio.Verifier.OpenId4Vp.WalletResponseData
        {
            ContentType = http.Request.ContentType ?? "application/x-www-form-urlencoded",
            Form = form.ToDictionary(
                static f => f.Key,
                static f => (IReadOnlyList<string>)f.Value.Where(v => v is not null).Cast<string>().ToArray(),
                StringComparer.Ordinal),
            Body = ReadOnlyMemory<byte>.Empty,
        };

        var processor = http.RequestServices.GetRequiredService<WalletCallbackProcessor>();
        var result = await processor.ProcessAsync(response, http.RequestAborted).ConfigureAwait(false);

        (http.Response.StatusCode, var error) = result.Outcome switch
        {
            CallbackOutcome.Completed => (StatusCodes.Status200OK, (string?)null),
            // Verified and waiting for its browser: processed, as far as the wallet is concerned.
            CallbackOutcome.Held => (StatusCodes.Status200OK, null),
            CallbackOutcome.UnknownSession => (StatusCodes.Status400BadRequest, "unknown_session"),
            CallbackOutcome.SessionNotPending => (StatusCodes.Status409Conflict, "session_not_pending"),
            // The response may be perfectly well formed. It is the stored session that cannot be checked
            // against, so this is a conflict with the session's state rather than a bad request.
            CallbackOutcome.SessionNotVerifiable => (StatusCodes.Status409Conflict, "session_not_verifiable"),
            // The response was read and checked, and the credential failed. The session stays open for another
            // response (VerifierOptions.CompleteOnlyOnValidResponse), so the wallet is told the answer was refused.
            CallbackOutcome.PresentationRejected => (StatusCodes.Status400BadRequest, "invalid_response"),
            _ => (StatusCodes.Status400BadRequest, "invalid_response"),
        };

        await http.Response.WriteAsJsonAsync(
            error is null ? new { redirect_uri = RedirectUri(http, prefix, result) } : (object)new { error },
            serializerOptions, http.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>
    /// Where the wallet sends the user after a processed response: the session's return page, with a response
    /// code in the fragment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: HAIP 1.0 section 5.1 requires this response to carry <c>redirect_uri</c> for the same-device
    /// flow. OpenID4VP 1.0 section 8.2: "The Verifier MUST include a fresh, cryptographically random value in
    /// the URL", which "can be added as a path component, as a fragment or as a parameter". A fragment, so
    /// the code never reaches a server log or a Referer header.
    /// </para>
    /// <para>
    /// EVERY ONE CARRIES A CODE. Only the code for a held same-device presentation can be redeemed. The
    /// others are fresh and stored nowhere, so the browser lands on the return page, whose redemption finds
    /// nothing, and shows the session as it stands. A wallet gets the same shape of answer in both flows.
    /// </para>
    /// </remarks>
    private static string RedirectUri(HttpContext http, string prefix, CallbackResult result) =>
        $"{http.Request.Scheme}://{http.Request.Host}{prefix}/{Uri.EscapeDataString(result.SessionId!)}/return"
        + $"#response_code={result.ResponseCode ?? SameDeviceSecrets.NewSecret()}";
}
