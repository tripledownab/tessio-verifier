namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// How the parser reads a wallet's cleartext Authorization Error Response (OpenID4VP 1.0 section 8.5): returned
/// as one by <see cref="WalletResponseParser.ParseDetailedAsync"/> when the caller opts in, still thrown by the
/// credentials-only <see cref="WalletResponseParser.ParseAsync"/> and by a parser that did not opt in.
/// </summary>
public sealed class AuthorizationErrorResponseParsingTests
{
    private const string SampleSdJwt = "eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~WyJzYWx0IiwibmFtZSIsInYiXQ~";

    private static WalletResponseParser Reading() => new(new WalletResponseParserOptions { ReadErrorResponses = true });

    [Fact]
    public async Task ByDefault_AnErrorResponse_IsStillThrown_SoNoCallerIsHandedAnEmptyPresentation()
    {
        Assert.False(new WalletResponseParserOptions().ReadErrorResponses);
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            new WalletResponseParser().ParseDetailedAsync(Form(("error", "access_denied"), ("state", "s-1"))));
    }

    private static WalletResponseData Form(params (string Key, string Value)[] fields) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = fields.ToDictionary(f => f.Key, f => (IReadOnlyList<string>)new[] { f.Value }, StringComparer.Ordinal),
        Body = ReadOnlyMemory<byte>.Empty,
    };

    [Fact]
    public async Task ErrorResponse_IsReturned_WithItsCodeAndState_AndNoCredentials()
    {
        var parsed = await Reading().ParseDetailedAsync(Form(
            ("error", "access_denied"), ("error_description", "The holder declined"), ("state", "s-1")));

        Assert.Equal("access_denied", parsed.Error);
        Assert.Equal("s-1", parsed.State);
        Assert.Empty(parsed.Credentials);
        Assert.False(parsed.Encrypted);
    }

    [Fact]
    public async Task ErrorResponse_WithoutState_IsReturned_ForTheCallerToRefuse()
    {
        var parsed = await Reading().ParseDetailedAsync(Form(("error", "access_denied")));

        Assert.Equal("access_denied", parsed.Error);
        Assert.Null(parsed.State);
    }

    [Fact]
    public async Task AnErrorFieldBesideAPresentation_IsReadAsThePresentation()
    {
        // An `error` field must not hide a presentation from the verifier.
        var parsed = await Reading().ParseDetailedAsync(Form(
            ("vp_token", SampleSdJwt), ("error", "access_denied"), ("state", "s-1")));

        Assert.Null(parsed.Error);
        Assert.Equal(SampleSdJwt, Assert.Single(parsed.Credentials).RawValue);
    }

    [Theory]
    [InlineData("")]
    [InlineData("access\"denied")]
    [InlineData("access\\denied")]
    [InlineData("access_denied\n")]
    [InlineData("accès_refusé")]
    public async Task ErrorCode_OutsideTheCharactersRfc6749Allows_IsRefused(string code)
    {
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            Reading().ParseDetailedAsync(Form(("error", code), ("state", "s-1"))));
    }

    [Fact]
    public async Task ErrorCode_LongerThanTheLimit_IsRefused_AndOneAtTheLimitIsRead()
    {
        var parser = Reading();

        Assert.Equal(64, (await parser.ParseDetailedAsync(Form(("error", new string('e', 64))))).Error!.Length);
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            parser.ParseDetailedAsync(Form(("error", new string('e', 65)))));
    }

    [Fact]
    public async Task ParseAsync_StillThrows_OnAnErrorResponse()
    {
        // The credentials-only contract has no way to say "the wallet declined", so it keeps the exception
        // its callers have always met here, rather than returning an empty list they would read as a presentation.
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            Reading().ParseAsync(Form(("error", "access_denied"), ("state", "s-1"))));
    }

    [Fact]
    public async Task AFormWithNoPresentationAndNoError_IsStillRefused()
    {
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            Reading().ParseDetailedAsync(Form(("state", "s-1"))));
    }
}
