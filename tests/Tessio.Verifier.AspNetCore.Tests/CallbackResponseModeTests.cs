using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Whether a wallet callback answers the request in the response mode the request asked for, and what
/// happens to the session when it does not. Everything about response mode at the callback belongs here.
/// </summary>
/// <remarks>
/// A response that does not answer the request in the mode it asked for is not the wallet's answer, so it
/// must not end the session. It is refused the way a missing state is: before completion, with the
/// session left open. That covers a plaintext form answering a <c>direct_post.jwt</c> request and a
/// <c>response</c> token that is not encrypted.
/// </remarks>
public sealed class CallbackResponseModeTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider;

    public CallbackResponseModeTests()
    {
        var services = new ServiceCollection();
        // The default response mode, direct_post.jwt, which is what HAIP requires.
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.RequestedClaims = ["age_over_18"];
        });
        _provider = services.BuildServiceProvider();
    }

    private async Task<VerificationSession> PendingEncryptedSessionAsync()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        Assert.Equal(ResponseMode.DirectPostJwt, options.ResponseMode);
        var encryptionJwk = _provider.GetRequiredService<ResponseEncryptionKeyStore>()
            .CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk;
        return await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(
            DemoRequestOptionsFactory.Create(options, new Uri("https://verifier.example/verify/callback"), encryptionJwk));
    }

    private static WalletResponseData PlaintextForm(string vpTokenCredential, string state) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["vp_token"] = [$$"""{"credential":["{{vpTokenCredential}}"]}"""],
            ["state"] = [state],
        },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    [Fact]
    public async Task ForgedPlaintextResponse_WithTheStolenState_IsRefused_AndTheRealWalletStillCompletes()
    {
        var session = await PendingEncryptedSessionAsync();
        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();

        // The attack: junk, but carrying the right state, and not encrypted.
        var forged = await processor.ProcessAsync(PlaintextForm("a.b.c~", session.Request.State!), CancellationToken.None);

        Assert.Equal(CallbackOutcome.ResponseInvalid, forged.Outcome);
        Assert.Equal(VerificationSessionStatus.Pending, (await store.GetAsync(session.SessionId))!.Status);

        // What it cost the real wallet: nothing. It answers encrypted, as asked, and completes.
        await _provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var terminal = await store.WaitForTerminalAsync(session.SessionId, timeout.Token);
        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        Assert.True(terminal.Result!.IsValid, string.Join("; ", terminal.Result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task ValidPresentation_SentInPlaintext_ToAnEncryptedRequest_IsRefused()
    {
        var session = await PendingEncryptedSessionAsync();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var presentation = _provider.GetRequiredService<MockCredentialIssuer>().IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, session.Request.Nonce, options.ClientId);

        var result = await _provider.GetRequiredService<WalletCallbackProcessor>()
            .ProcessAsync(PlaintextForm(presentation, session.Request.State!), CancellationToken.None);

        // The mode is enforced, not only validity: a presentation that would verify is still not an answer
        // to a request that asked for encryption, because the request said how it wanted to be answered.
        Assert.Equal(CallbackOutcome.ResponseInvalid, result.Outcome);
        Assert.Equal(VerificationSessionStatus.Pending,
            (await _provider.GetRequiredService<InMemorySessionStore>().GetAsync(session.SessionId))!.Status);
    }

    [Fact]
    public async Task UnsecuredResponseToken_WithTheStolenState_IsRefused_AndTheSessionStaysOpen()
    {
        var session = await PendingEncryptedSessionAsync();
        var kid = RequestParameters.TryGetEncryptionJwkJson(session.Request) is { } jwk
            ? System.Text.Json.JsonDocument.Parse(jwk).RootElement.GetProperty("kid").GetString()
            : null;
        Assert.NotNull(kid);

        // Shaped like a direct_post.jwt response, carrying the session's own key id, which the request
        // object advertises, and its state. Not encrypted and not signed: alg "none". OpenID4VP 1.0 §8.3
        // requires an unsigned, ENCRYPTED JWT, so this is not an answer, and it must not end the session.
        static string B64(string json) => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            System.Text.Encoding.UTF8.GetBytes(json));
        var unsecured = B64($$"""{"alg":"none","kid":"{{kid}}"}""") + "."
            + B64($$"""{"vp_token":{"credential":["a.b.c~"]},"state":"{{session.Request.State}}"}""") + ".";

        var result = await _provider.GetRequiredService<WalletCallbackProcessor>().ProcessAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [unsecured] },
            Body = ReadOnlyMemory<byte>.Empty,
        }, CancellationToken.None);

        Assert.Equal(CallbackOutcome.ResponseInvalid, result.Outcome);
        Assert.Equal(VerificationSessionStatus.Pending,
            (await _provider.GetRequiredService<InMemorySessionStore>().GetAsync(session.SessionId))!.Status);
    }

    [Fact]
    public async Task MockWallet_AnswersInTheModeItsSessionAsked_NotTheConfiguredDefault()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        // The host defaults to direct_post.jwt, and this one session asks for direct_post. A wallet
        // answers what the request asked for, so the mock wallet must too, or the callback refuses its
        // answer as the wrong mode and the session waits out its lifetime.
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")) with { ResponseMode = ResponseMode.DirectPost });

        await _provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var terminal = await store.WaitForTerminalAsync(session.SessionId, timeout.Token);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        Assert.True(terminal.Result!.IsValid, string.Join("; ", terminal.Result.Errors.Select(e => e.Code)));
    }

    public async ValueTask DisposeAsync() => await _provider.DisposeAsync();
}
