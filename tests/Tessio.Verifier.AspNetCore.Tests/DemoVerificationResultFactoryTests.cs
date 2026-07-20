namespace Tessio.Verifier.AspNetCore.Tests;

public class DemoVerificationResultFactoryTests
{
    [Fact]
    public void Create_MapsRequestedClaims_ToSampleValues()
    {
        var result = DemoVerificationResultFactory.Create(
            new VerifierOptions { RequestedClaims = { "age_over_18", "given_name" } });

        Assert.True(result.IsValid);
        Assert.True((bool)result.DisclosedClaims["age_over_18"]);
        Assert.Equal("Erika", (string)result.DisclosedClaims["given_name"]);
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Create_UnknownClaim_FallsBackToDemoValue()
    {
        var result = DemoVerificationResultFactory.Create(
            new VerifierOptions { RequestedClaims = { "favourite_colour" } });

        Assert.Equal("demo-value", (string)result.DisclosedClaims["favourite_colour"]);
    }

    [Fact]
    public void Create_NoRequestedClaims_DefaultsToAgeOver18()
    {
        var result = DemoVerificationResultFactory.Create(new VerifierOptions());

        Assert.True(result.DisclosedClaims.ContainsKey("age_over_18"));
    }
}
