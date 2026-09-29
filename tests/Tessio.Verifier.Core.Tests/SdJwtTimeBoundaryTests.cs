using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// The exact edges of every SD-JWT VC date check: credential <c>exp</c> and <c>nbf</c>, and KB-JWT
/// <c>iat</c> freshness, each one second either side of its boundary under a fixed clock.
/// </summary>
/// <remarks>
/// What belongs here: where a date check flips, not whether it exists. The tests in
/// <c>SdJwtVcVerifierTests</c> sit hours from the boundary, so they stay green if a comparison loses its
/// equality or the skew is dropped or applied in the wrong direction. These do not.
/// </remarks>
public class SdJwtTimeBoundaryTests
{
    /// <summary>The verifier's default tolerance, restated so a change to the default fails loudly here.</summary>
    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    /// <summary>The default KB-JWT age limit, restated for the same reason.</summary>
    private static readonly TimeSpan MaxKbAge = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The instant every check here is judged at: whole seconds, because every date claim is a Unix time
    /// in seconds, and 400 days from the wall clock, so a check that reads the wall clock instead of the
    /// injected one fails every test here rather than passing by coincidence. The key comes from issuer
    /// metadata, so no certificate validity window depends on the real date.
    /// </summary>
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddDays(400).ToUnixTimeSeconds());

    /// <summary>
    /// A credential valid at <see cref="Now"/>. The builder's default exp is an hour from the WALL clock,
    /// which is long past at <see cref="Now"/>, so every builder here starts from this.
    /// </summary>
    private static long ValidExp => Now.AddHours(1).ToUnixTimeSeconds();

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static async Task<VerificationResult> VerifyAsync(TestCredentialBuilder builder, SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), options, new HttpClient(http), new FixedClock(Now));
        return await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() },
            new VerificationContext { Nonce = TestCredentialBuilder.DefaultNonce, Audience = TestCredentialBuilder.DefaultAudience });
    }

    private static List<string> Codes(VerificationResult result) => result.Errors.Select(e => e.Code).ToList();

    [Fact]
    public void TheDefaults_AreTheOnesTheseEdgesAssume()
    {
        var defaults = new SdJwtVcVerifierOptions();
        Assert.Equal(Skew, defaults.ClockSkew);
        Assert.Equal(MaxKbAge, defaults.MaxKeyBindingAge);
    }

    // exp: expired once now - skew >= exp.
    [Theory]
    [InlineData(0, true)]   // exp exactly at now - skew is already expired
    [InlineData(1, false)]  // one second later is still inside the tolerance
    [InlineData(-1, true)]
    public async Task Exp_FlipsExactlyAtNowMinusSkew(int secondsAfterEdge, bool expired)
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = (Now - Skew).AddSeconds(secondsAfterEdge).ToUnixTimeSeconds(),
            KbIatOverride = Now,
        };

        var result = await VerifyAsync(builder);

        Assert.Equal(expired, Codes(result).Contains(ErrorCodes.CredentialExpired));
        Assert.Equal(!expired, result.IsValid);
    }

    // nbf: not yet valid while now + skew < nbf.
    [Theory]
    [InlineData(0, false)]  // nbf exactly at now + skew is already valid
    [InlineData(1, true)]   // one second later is not yet valid
    [InlineData(-1, false)]
    public async Task Nbf_FlipsExactlyAtNowPlusSkew(int secondsAfterEdge, bool notYetValid)
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = ValidExp,
            Nbf = (Now + Skew).AddSeconds(secondsAfterEdge).ToUnixTimeSeconds(),
            KbIatOverride = Now,
        };

        var result = await VerifyAsync(builder);

        Assert.Equal(notYetValid, Codes(result).Contains(ErrorCodes.CredentialNotYetValid));
        Assert.Equal(!notYetValid, result.IsValid);
    }

    // KB-JWT iat: stale when older than now - maxAge - skew.
    [Theory]
    [InlineData(0, false)]  // exactly at the oldest accepted instant is fresh
    [InlineData(-1, true)]  // one second older is stale
    [InlineData(1, false)]
    public async Task KbIat_IsStale_OnlyBeforeNowMinusMaxAgeMinusSkew(int secondsAfterEdge, bool stale)
    {
        using var builder = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = (Now - MaxKbAge - Skew).AddSeconds(secondsAfterEdge) };

        var result = await VerifyAsync(builder);

        Assert.Equal(stale, Codes(result).Contains(ErrorCodes.KeyBindingInvalid));
        Assert.Equal(!stale, result.IsValid);
    }

    // KB-JWT iat: in the future when later than now + skew.
    [Theory]
    [InlineData(0, false)]  // exactly at now + skew is tolerated
    [InlineData(1, true)]   // one second later is in the future
    [InlineData(-1, false)]
    public async Task KbIat_IsFuture_OnlyAfterNowPlusSkew(int secondsAfterEdge, bool future)
    {
        using var builder = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = (Now + Skew).AddSeconds(secondsAfterEdge) };

        var result = await VerifyAsync(builder);

        Assert.Equal(future, Codes(result).Contains(ErrorCodes.KeyBindingInvalid));
        Assert.Equal(!future, result.IsValid);
    }

    // ---- The same edges under non-default options -------------------------------------------------
    //
    // Each check has to READ its option. The default-option tests above would stay green if a check
    // hard-coded the default, so every edge is repeated here with the option moved.

    private static readonly SdJwtVcVerifierOptions NoSkew = new() { ClockSkew = TimeSpan.Zero };

    /// <summary>With no tolerance, exp flips at now itself.</summary>
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public async Task ClockSkew_MovesTheExpEdge(int secondsAfterNow, bool expired)
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = Now.AddSeconds(secondsAfterNow).ToUnixTimeSeconds(),
            KbIatOverride = Now,
        };

        var result = await VerifyAsync(builder, NoSkew);

        Assert.Equal(expired, Codes(result).Contains(ErrorCodes.CredentialExpired));
    }

    /// <summary>With no tolerance, nbf flips at now itself.</summary>
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public async Task ClockSkew_MovesTheNbfEdge(int secondsAfterNow, bool notYetValid)
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = ValidExp,
            Nbf = Now.AddSeconds(secondsAfterNow).ToUnixTimeSeconds(),
            KbIatOverride = Now,
        };

        var result = await VerifyAsync(builder, NoSkew);

        Assert.Equal(notYetValid, Codes(result).Contains(ErrorCodes.CredentialNotYetValid));
    }

    /// <summary>With no tolerance, a KB-JWT iat is in the future from one second after now.</summary>
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public async Task ClockSkew_MovesTheKbIatFutureEdge(int secondsAfterNow, bool future)
    {
        using var builder = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = Now.AddSeconds(secondsAfterNow) };

        var result = await VerifyAsync(builder, NoSkew);

        Assert.Equal(future, Codes(result).Contains(ErrorCodes.KeyBindingInvalid));
    }

    /// <summary>
    /// The stale edge is now minus the age limit minus the skew, and both come from the options.
    /// </summary>
    [Theory]
    [InlineData(0, false)]
    [InlineData(-1, true)]
    public async Task MaxKeyBindingAge_AndClockSkew_MoveTheKbIatStaleEdge(int secondsAfterEdge, bool stale)
    {
        var options = new SdJwtVcVerifierOptions { ClockSkew = TimeSpan.FromSeconds(7), MaxKeyBindingAge = TimeSpan.FromSeconds(60) };
        using var builder = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = Now.AddSeconds(-60 - 7 + secondsAfterEdge) };

        var result = await VerifyAsync(builder, options);

        Assert.Equal(stale, Codes(result).Contains(ErrorCodes.KeyBindingInvalid));
    }

    /// <summary>An infinite age limit accepts any past iat, and still refuses a future one.</summary>
    [Fact]
    public async Task InfiniteMaxKeyBindingAge_AcceptsAnyPastIat_ButNotAFutureOne()
    {
        var options = new SdJwtVcVerifierOptions { MaxKeyBindingAge = Timeout.InfiniteTimeSpan };

        using var old = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = Now.AddYears(-10) };
        Assert.True((await VerifyAsync(old, options)).IsValid);

        using var future = new TestCredentialBuilder { Exp = ValidExp, KbIatOverride = (Now + Skew).AddSeconds(1) };
        Assert.Contains(ErrorCodes.KeyBindingInvalid, Codes(await VerifyAsync(future, options)));
    }
}
