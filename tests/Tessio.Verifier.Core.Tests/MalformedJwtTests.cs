using Microsoft.IdentityModel.JsonWebTokens;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Every place this library parses a compact JWT that came from outside must report a malformed one as a
/// verification error, never as a thrown exception.
/// </summary>
/// <remarks>
/// <para>
/// Each site used to write its own <c>catch (ArgumentException)</c>, which is one of the two complaints
/// <see cref="JsonWebToken"/>'s constructor makes. The other is a <see cref="FormatException"/>, raised
/// when a segment is not valid base64url. Every one of these tokens reaches the library from outside, so
/// both complaints have to end as a verification error.
/// </para>
/// <para>
/// The mutation suite in <see cref="SdJwtRobustnessTests"/> asserts the same property over random input
/// and did not find this, so these cases are written as the specific string that triggers it rather than
/// left to a seeded fuzzer to rediscover.
/// </para>
/// </remarks>
public class MalformedJwtTests
{
    /// <summary>
    /// Three segments that look like a JWT and are not. This is the shape the old guards let through:
    /// the segment count is right, so the constructor gets as far as decoding, and the decode throws
    /// FormatException rather than any ArgumentException.
    /// </summary>
    private const string FormatExceptionShaped = "eyJhbGciOiJFQ0RILUVTIn0.not.a.real.jwe";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static SdJwtVcVerifier VerifierFor(TestCredentialBuilder builder, FakeHttpHandler? http = null)
    {
        http ??= new FakeHttpHandler();
        http.Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        return new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));
    }

    [Theory]
    [InlineData(FormatExceptionShaped)] // base64url that will not decode
    [InlineData("!!!.???.***")]         // no valid segment at all
    [InlineData("one-segment-only")]    // too few segments
    [InlineData("a.b.c.d.e.f")]         // too many segments
    public void TryParse_RefusesAMalformedToken(string value)
    {
        Assert.False(CompactJwt.TryParse(value, out var token));
        Assert.Null(token);
    }

    [Fact]
    public void TryParse_AcceptsAWellFormedToken()
    {
        Assert.True(CompactJwt.TryParse("e30.e30.", out var token));
        Assert.NotNull(token);
    }

    /// <summary>The issuer-signed JWT, which is everything before the first <c>~</c>.</summary>
    [Fact]
    public async Task AMalformedIssuerJwtIsAnInvalidResult()
    {
        var result = await VerifierFor(new TestCredentialBuilder()).VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = $"{FormatExceptionShaped}~" },
            Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StructureInvalid);
    }

    /// <summary>
    /// The KB-JWT, which is everything after the last <c>~</c>. Built from a real presentation so the
    /// credential gets far enough to have its key binding checked at all.
    /// </summary>
    [Fact]
    public async Task AMalformedKeyBindingJwtIsAnInvalidResult()
    {
        using var builder = new TestCredentialBuilder();
        var presentation = builder.Build();
        var withoutKb = presentation[..(presentation.LastIndexOf('~') + 1)];

        var result = await VerifierFor(builder).VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = withoutKb + FormatExceptionShaped },
            Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.KeyBindingInvalid);
    }

    /// <summary>
    /// The status list token, which arrives over HTTP from the issuer rather than from the holder. It is
    /// still untrusted: the response is whatever answered that URL.
    /// </summary>
    [Fact]
    public async Task AMalformedStatusListTokenIsAnInvalidResult()
    {
        const string statusUri = "https://issuer.example/statuslists/1";
        using var builder = new TestCredentialBuilder { Status = (1, statusUri) };
        var http = new FakeHttpHandler().Map(statusUri, FormatExceptionShaped);

        var result = await VerifierFor(builder, http).VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StatusInvalid);
    }
}
