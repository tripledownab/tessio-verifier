using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

public class InMemorySessionStoreTests
{
    private static InMemorySessionStore NewStore() =>
        new(new DemoPresentationRequestBuilder(TimeProvider.System), TimeProvider.System);

    private static PresentationRequestOptions SampleOptions() =>
        DemoRequestOptionsFactory.Create(
            new VerifierOptions { RequestedClaims = { "age_over_18" } },
            new Uri("https://verifier.example/verify/callback"));

    private static VerificationResult ValidResult() => new()
    {
        IsValid = true,
        DisclosedClaims = new Dictionary<string, object> { ["age_over_18"] = true },
        Issuer = new IssuerInfo { Identifier = "https://issuer.example", Trusted = true, KeyResolutionMethod = "x5c" },
        Errors = Array.Empty<VerificationError>(),
    };

    [Fact]
    public async Task CreateAsync_ReturnsPendingSession_WithByValueRequest()
    {
        var store = NewStore();

        var session = await store.CreateAsync(SampleOptions());

        Assert.Equal(VerificationSessionStatus.Pending, session.Status);
        Assert.Null(session.Result);
        Assert.NotEmpty(session.SessionId);
        Assert.IsType<PresentationRequest.ByValue>(session.Request);
    }

    [Fact]
    public async Task GetAsync_ReturnsCreatedSession()
    {
        var store = NewStore();
        var created = await store.CreateAsync(SampleOptions());

        var fetched = await store.GetAsync(created.SessionId);

        Assert.NotNull(fetched);
        Assert.Equal(created.SessionId, fetched!.SessionId);
    }

    [Fact]
    public async Task GetAsync_UnknownSession_ReturnsNull()
    {
        var store = NewStore();

        Assert.Null(await store.GetAsync("does-not-exist"));
    }

    [Fact]
    public async Task CompleteAsync_TransitionsToCompleted_WithResult()
    {
        var store = NewStore();
        var session = await store.CreateAsync(SampleOptions());

        await store.CompleteAsync(session.SessionId, ValidResult());

        var fetched = await store.GetAsync(session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, fetched!.Status);
        Assert.NotNull(fetched.Result);
        Assert.True(fetched.Result!.IsValid);
    }

    [Fact]
    public async Task CompleteAsync_UnknownSession_Throws()
    {
        var store = NewStore();

        await Assert.ThrowsAsync<KeyNotFoundException>(
            async () => await store.CompleteAsync("does-not-exist", ValidResult()));
    }

    [Fact]
    public async Task WaitForTerminalAsync_ResolvesWhenSessionCompletes()
    {
        var store = NewStore();
        var session = await store.CreateAsync(SampleOptions());

        var waitTask = store.WaitForTerminalAsync(session.SessionId, CancellationToken.None);
        Assert.False(waitTask.IsCompleted);

        await store.CompleteAsync(session.SessionId, ValidResult());
        var terminal = await waitTask;

        Assert.Equal(VerificationSessionStatus.Completed, terminal.Status);
    }
}
