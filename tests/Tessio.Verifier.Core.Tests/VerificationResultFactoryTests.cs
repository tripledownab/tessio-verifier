namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// The <c>VerificationResult.Valid</c> / <c>VerificationResult.Invalid</c> factory helpers let tests and
/// self-driving hosts synthesize results without hand-populating every required member.
/// </summary>
public sealed class VerificationResultFactoryTests
{
    private static readonly IssuerInfo Issuer = new()
    {
        Identifier = "https://issuer.example",
        Trusted = true,
        KeyResolutionMethod = "jwt-vc-issuer-metadata",
    };

    [Fact]
    public void Valid_CarriesClaimsAndIssuer_WithNoErrors()
    {
        var claims = new Dictionary<string, object> { ["age_over_18"] = true };

        var result = VerificationResult.Valid(claims, Issuer);

        Assert.True(result.IsValid);
        Assert.Same(claims, result.DisclosedClaims);
        Assert.Same(Issuer, result.Issuer);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Invalid_SingleError_DefaultsToUnknownIssuer()
    {
        var error = new VerificationError { Code = "structure_invalid", Message = "bad" };

        var result = VerificationResult.Invalid(error);

        Assert.False(result.IsValid);
        Assert.Empty(result.DisclosedClaims);
        Assert.Same(IssuerInfo.Unknown, result.Issuer);
        Assert.Equal("none", result.Issuer.KeyResolutionMethod);
        Assert.False(result.Issuer.Trusted);
        Assert.Equal(new[] { error }, result.Errors);
    }

    [Fact]
    public void Invalid_KeepsSuppliedIssuer_WhenResolved()
    {
        var errors = new[]
        {
            new VerificationError { Code = "signature_invalid", Message = "no" },
            new VerificationError { Code = "issuer_untrusted", Message = "no" },
        };

        var result = VerificationResult.Invalid(errors, Issuer);

        Assert.False(result.IsValid);
        Assert.Same(Issuer, result.Issuer);
        Assert.Equal(2, result.Errors.Count);
    }

    [Fact]
    public void Factories_RejectNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Valid(null!, Issuer));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Valid(new Dictionary<string, object>(), null!));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Invalid((VerificationError)null!));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Invalid((IReadOnlyList<VerificationError>)null!));
    }
}
