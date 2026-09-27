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

    [Fact]
    public void Create_ReportsTheCredentialTypeThisDeploymentAsksFor()
    {
        // Demo synthesizes a result rather than verifying one, so if it reported no type a caller
        // building against demo would meet a field that is null until live mode suddenly fills it.
        var sdJwt = DemoVerificationResultFactory.Create(new VerifierOptions());
        Assert.Equal(DemoRequestOptionsFactory.DefaultVct, sdJwt.CredentialType);

        var configured = DemoVerificationResultFactory.Create(
            new VerifierOptions { ExpectedVct = "urn:eudi:pid:1" });
        Assert.Equal("urn:eudi:pid:1", configured.CredentialType);

        var mdoc = DemoVerificationResultFactory.Create(
            new VerifierOptions { CredentialFormat = "mso_mdoc", ExpectedDocType = "org.iso.18013.5.1.mDL" });
        Assert.Equal("org.iso.18013.5.1.mDL", mdoc.CredentialType);
    }
}
