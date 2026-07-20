using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore.Tests;

public class DemoCompletionServiceTests
{
    [Fact]
    public async Task DemoMode_AutoCompletesEnqueuedSession_WithValidResult()
    {
        var options = Options.Create(new VerifierOptions
        {
            Mode = VerifierMode.Demo,
            DemoCompletionDelay = TimeSpan.FromMilliseconds(20),
            RequestedClaims = { "age_over_18" },
        });

        var clock = TimeProvider.System;
        var store = new InMemorySessionStore(new DemoPresentationRequestBuilder(clock), clock);
        var queue = new DemoCompletionQueue();
        var service = new DemoCompletionService(queue, store, clock, options);

        await ((IHostedService)service).StartAsync(CancellationToken.None);
        try
        {
            var requestOptions = DemoRequestOptionsFactory.Create(
                options.Value, new Uri("https://verifier.example/verify/callback"));
            var session = await store.CreateAsync(requestOptions);

            await queue.EnqueueAsync(session.SessionId);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var terminal = await store.WaitForTerminalAsync(session.SessionId, timeout.Token);

            Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
            Assert.NotNull(terminal.Result);
            Assert.True(terminal.Result!.IsValid);
            Assert.True((bool)terminal.Result.DisclosedClaims["age_over_18"]);
        }
        finally
        {
            await ((IHostedService)service).StopAsync(CancellationToken.None);
        }
    }
}
