namespace Tessio.Verifier.AspNetCore.Tests;

public class SessionEvictionTests
{
    private sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task StaleSessions_AreEvicted_OnCreate_IncludingStateIndex()
    {
        var clock = new TestClock();
        var store = new InMemorySessionStore(new DemoPresentationRequestBuilder(clock), clock);
        var options = new VerifierOptions { SessionLifetime = TimeSpan.FromMinutes(5) };

        var stale = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // Move past expiry + the 15-minute retention window; the next create sweeps.
        clock.Now += TimeSpan.FromMinutes(21);
        var fresh = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        Assert.Null(await store.GetAsync(stale.SessionId));
        Assert.Null(await store.FindByStateAsync(stale.Request.State!));
        Assert.NotNull(await store.GetAsync(fresh.SessionId));
    }

    [Fact]
    public async Task ExpiredButWithinRetention_IsStillReadable_AsExpired()
    {
        var clock = new TestClock();
        var store = new InMemorySessionStore(new DemoPresentationRequestBuilder(clock), clock);
        var options = new VerifierOptions { SessionLifetime = TimeSpan.FromMinutes(5) };

        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        // Past expiry, inside retention: still readable so a result page can show "expired".
        clock.Now += TimeSpan.FromMinutes(10);
        await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("https://verifier.example/verify/callback")));

        var read = await store.GetAsync(session.SessionId);
        Assert.NotNull(read);
        Assert.Equal(VerificationSessionStatus.Expired, read!.Status);
    }
}
