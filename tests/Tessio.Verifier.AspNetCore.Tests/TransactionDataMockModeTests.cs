using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Transaction data end to end: options.TransactionData rides base64url-encoded in the request
/// object, the mock wallet acknowledges it with KB-JWT hashes and the processor verifies them.
/// </summary>
public sealed class TransactionDataMockModeTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider;

    public TransactionDataMockModeTests()
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.RequestedClaims = ["age_over_18"];
            options.TransactionData = ["""{"type":"payment_confirmation","amount":"120.00 EUR"}"""];
        });
        _provider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task MockMode_WithTransactionData_VerifiesTheAcknowledgment()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // The request object carries the encoded transaction data for the wallet to hash.
        var tds = RequestObjectPayload.TryGetTransactionData(session.Request.SignedRequestObject);
        Assert.NotNull(tds);
        var decoded = System.Text.Encoding.UTF8.GetString(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(Assert.Single(tds!)));
        Assert.Contains("payment_confirmation", decoded, StringComparison.Ordinal);
        Assert.Contains("\"credential_ids\":[\"credential\"]", decoded, StringComparison.Ordinal);

        await _provider.GetRequiredService<MockWalletQueue>().EnqueueAsync(session.SessionId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var terminal = await store.WaitForTerminalAsync(session.SessionId, timeout.Token);

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
        Assert.True(terminal.Result!.IsValid,
            string.Join("; ", terminal.Result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task WalletIgnoringTransactionData_FailsVerification()
    {
        var store = _provider.GetRequiredService<InMemorySessionStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var issuer = _provider.GetRequiredService<MockCredentialIssuer>();
        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // A wallet that presents correctly but never acknowledges the transaction data.
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, session.Request.Nonce, options.ClientId,
            transactionData: null);

        var response = new Tessio.Verifier.OpenId4Vp.WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["vp_token"] = new[] { $$"""{"credential":["{{presentation}}"]}""" },
                ["state"] = new[] { session.Request.State! },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        Assert.Equal(CallbackOutcome.Completed, await processor.ProcessAsync(response, CancellationToken.None));

        var terminal = await store.GetAsync(session.SessionId);
        Assert.False(terminal!.Result!.IsValid);
        Assert.Contains(terminal.Result.Errors, e => e.Code == "transaction_data_missing");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var hosted in _provider.GetServices<IHostedService>())
        {
            await hosted.StopAsync(CancellationToken.None);
        }

        await _provider.DisposeAsync();
    }
}
