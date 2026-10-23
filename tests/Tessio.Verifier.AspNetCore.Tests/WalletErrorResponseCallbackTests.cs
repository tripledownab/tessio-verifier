using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// What the built-in callback does with a wallet's cleartext Authorization Error Response, for example a holder
/// who declined. OpenID4VP 1.0 section 8.2: "If the Response URI has successfully processed the Authorization
/// Response or Authorization Error Response, it MUST respond with an HTTP status code of 200", and the answer
/// "MAY return the redirect_uri parameter ... for Error Responses". HAIP 1.0 section 5.1 makes that a MUST for
/// the same-device flow. The built-in callback returns one in both flows.
/// </summary>
public sealed class WalletErrorResponseCallbackTests
{
    private static IHost StartHost(
        bool completeOnlyOnValid, ResponseMode responseMode = ResponseMode.DirectPost, CapturingLoggerProvider? logs = null) => new HostBuilder()
        .ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureServices(services =>
            {
                if (logs is not null)
                {
                    services.AddLogging(builder => builder.AddProvider(logs));
                }

                services.AddRouting().AddTessioVerifier(options =>
                {
                    options.Mode = VerifierMode.Mock;
                    options.ResponseMode = responseMode;
                    options.RequestedClaims = ["age_over_18"];
                    options.CompleteOnlyOnValidResponse = completeOnlyOnValid;
                });
            })
            .Configure(app => app.UseRouting().UseEndpoints(e => e.MapTessioVerifier())))
        .Start();

    private static async Task<VerificationSession> CreateSessionAsync(IHost host)
    {
        var options = host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var encryptionJwk = options.ResponseMode == ResponseMode.DirectPostJwt
            ? host.Services.GetRequiredService<ResponseEncryptionKeyStore>().CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk
            : null;
        return await host.Services.GetRequiredService<ISessionStore>().CreateAsync(
            DemoRequestOptionsFactory.Create(options, new Uri("http://localhost/verify/callback"), encryptionJwk));
    }

    private static FormUrlEncodedContent Declined(string state) => new(new Dictionary<string, string>
    {
        ["error"] = "access_denied",
        ["error_description"] = "The holder declined",
        ["state"] = state,
    });

    private static async Task<VerificationSession> ReadAsync(IHost host, string sessionId) =>
        (await host.Services.GetRequiredService<ISessionStore>().GetAsync(sessionId))!;

    [Fact]
    public async Task ADeclinedRequest_IsAnswered200_WithARedirectToTheSessionsReturnPage()
    {
        using var host = StartHost(completeOnlyOnValid: false);
        var session = await CreateSessionAsync(host);

        var response = await host.GetTestClient().PostAsync("/verify/callback", Declined(session.Request.State!));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var redirect = new Uri((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirect_uri").GetString()!);
        Assert.Equal($"/verify/{session.SessionId}/return", redirect.AbsolutePath);
        Assert.StartsWith("#response_code=", redirect.Fragment, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ByDefault_ItCompletesTheSessionAsInvalid_WithTheWalletErrorCode()
    {
        using var host = StartHost(completeOnlyOnValid: false);
        var session = await CreateSessionAsync(host);

        await host.GetTestClient().PostAsync("/verify/callback", Declined(session.Request.State!));

        var after = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, after.Status);
        Assert.False(after.Result!.IsValid);
        var error = Assert.Single(after.Result.Errors);
        Assert.Equal(ErrorCodes.WalletError, error.Code);
        Assert.Contains("access_denied", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("holder declined", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithCompleteOnlyOnValidResponse_ItIsAFailedAttempt_AndTheSessionStaysOpen()
    {
        using var host = StartHost(completeOnlyOnValid: true);
        var session = await CreateSessionAsync(host);

        var response = await host.GetTestClient().PostAsync("/verify/callback", Declined(session.Request.State!));

        // Still 200: the wallet's error response was processed. Only the session's handling differs.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var kept = await ReadAsync(host, session.SessionId);
        Assert.Equal(VerificationSessionStatus.Pending, kept.Status);
        Assert.Equal(1, kept.FailedAttempts);
        Assert.Equal(ErrorCodes.WalletError, Assert.Single(kept.LastFailure!.Errors).Code);
    }

    [Fact]
    public async Task ACleartextErrorResponse_ToAnEncryptedRequest_IsStillProcessed()
    {
        // OpenID4VP 1.0 section 8.3.1 lets a wallet that cannot encrypt send its error in the clear, so the
        // response mode check that refuses a plaintext presentation does not apply to it.
        using var host = StartHost(completeOnlyOnValid: false, ResponseMode.DirectPostJwt);
        var session = await CreateSessionAsync(host);

        var response = await host.GetTestClient().PostAsync("/verify/callback", Declined(session.Request.State!));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ErrorCodes.WalletError, Assert.Single((await ReadAsync(host, session.SessionId)).Result!.Errors).Code);
    }

    [Fact]
    public async Task AnErrorResponse_NamingNoKnownSession_IsRefused_AsBefore()
    {
        using var host = StartHost(completeOnlyOnValid: false);

        var response = await host.GetTestClient().PostAsync("/verify/callback", Declined("no-such-state"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("unknown_session", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnErrorResponse_ToACompletedSession_DoesNotChangeIt()
    {
        using var host = StartHost(completeOnlyOnValid: false);
        var session = await CreateSessionAsync(host);
        var client = host.GetTestClient();
        await client.PostAsync("/verify/callback", Declined(session.Request.State!));

        var second = await client.PostAsync("/verify/callback", Declined(session.Request.State!));

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task ThePublicVerifier_ReportsAnErrorResponse_AsTheWalletsError()
    {
        using var host = StartHost(completeOnlyOnValid: false);
        var session = await CreateSessionAsync(host);
        var form = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["error"] = ["access_denied"],
                ["state"] = [session.Request.State!],
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        var result = await host.Services.GetRequiredService<IWalletResponseVerifier>().VerifyAsync(session, form);

        Assert.False(result.IsValid);
        Assert.Equal(ErrorCodes.WalletError, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AnErrorFieldBesideAnEncryptedResponse_IsRefused_ForTheResponsesOwnReason()
    {
        // A sealed response naming a key no session holds. The registered parser refuses it for that; the
        // callback's keyless error reader would refuse it for having no key at all, which is the wrong reason.
        var logs = new CapturingLoggerProvider();
        using var host = StartHost(completeOnlyOnValid: false, ResponseMode.DirectPostJwt, logs);
        var header = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode("""{"alg":"ECDH-ES","enc":"A128GCM","kid":"no-such-key"}""");
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response"] = $"{header}..AAAA.AAAA.AAAA",
            ["error"] = "access_denied",
            ["state"] = "s-1",
        });

        var response = await host.GetTestClient().PostAsync("/verify/callback", form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var reasons = string.Join("\n", logs.Records.Select(r => r.Exception?.Message ?? r.Message));
        Assert.Contains("no known response-encryption key", reasons, StringComparison.Ordinal);
        Assert.DoesNotContain("no ResponseDecryptionKey is configured", reasons, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnErrorCodeOutsideRfc6749_IsRefused_ForThatReason()
    {
        // The registered parser refuses the form for lacking a presentation; the error reader refuses it for the
        // code. The log must say the second, or it would claim the form named no error at all.
        var logs = new CapturingLoggerProvider();
        using var host = StartHost(completeOnlyOnValid: false, logs: logs);
        var session = await CreateSessionAsync(host);
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["error"] = "access\"denied",
            ["state"] = session.Request.State!,
        });

        var response = await host.GetTestClient().PostAsync("/verify/callback", form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(VerificationSessionStatus.Pending, (await ReadAsync(host, session.SessionId)).Status);
        var reasons = string.Join("\n", logs.Records.Select(r => r.Exception?.Message ?? r.Message));
        Assert.Contains("RFC 6749", reasons, StringComparison.Ordinal);
        Assert.DoesNotContain("carries neither", reasons, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheParserAHostResolves_StillThrowsOnAnErrorResponse()
    {
        // The callback reads error responses through its own parser. The registered one stays at the default, so
        // a host with its own callback is never handed an empty presentation for a declined request.
        using var host = StartHost(completeOnlyOnValid: false);
        var form = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["error"] = ["access_denied"],
                ["state"] = ["s-1"],
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        await Assert.ThrowsAsync<WalletResponseException>(() =>
            host.Services.GetRequiredService<WalletResponseParser>().ParseDetailedAsync(form));
    }

    [Fact]
    public async Task WithCompleteOnlyOnValidResponse_AnErrorResponse_CannotEndAHeldSameDevicePresentation()
    {
        // Anyone holding `state` can post an error response. Without the option it ends the session, as a failing
        // presentation does (going-live.md). With it, the held presentation survives and its browser redeems it.
        await using var host = new SameDeviceHost(completeOnlyOnValidResponse: true);
        var started = await host.StartSameDeviceAsync();
        var (_, sessionId, code) = await SameDeviceHost.RedirectOf(await host.PresentAsync(started));

        var declined = await host.Client.PostAsync("/verify/callback/same-device", Declined(started.State));

        Assert.Equal(HttpStatusCode.OK, declined.StatusCode);
        Assert.Equal("redeemed", await host.RedeemAsync(sessionId, code, started.Cookie));
        Assert.True((await host.SessionAsync(sessionId)).Result!.IsValid);
    }
}
