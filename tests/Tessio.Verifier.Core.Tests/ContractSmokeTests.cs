using Tessio.Verifier.Core;

namespace Tessio.Verifier.Core.Tests;

public class ContractSmokeTests
{
    [Fact]
    public void ICredentialVerifier_IsPublicInterface()
    {
        var type = typeof(ICredentialVerifier);
        Assert.True(type.IsInterface);
        Assert.True(type.IsPublic);
    }

    [Fact]
    public void PresentedCredential_DcSdJwt_Format()
    {
        var credential = new PresentedCredential
        {
            Format = "dc+sd-jwt",
            RawValue = "header.payload.sig~",
        };
        Assert.Equal("dc+sd-jwt", credential.Format);
    }

    [Fact]
    public void VerificationContext_OmitsExpectedVct_WhenNotSpecified()
    {
        var ctx = new VerificationContext
        {
            Nonce = "n-0S6_WzA2Mj",
            Audience = "https://verifier.example",
        };
        Assert.Null(ctx.ExpectedVct);
    }

    [Fact]
    public void VerificationResult_Valid_CarriesDisclosedClaims()
    {
        var issuer = new IssuerInfo
        {
            Identifier = "https://issuer.example",
            Trusted = true,
            KeyResolutionMethod = "jwt-vc-issuer-metadata",
        };
        var result = new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = new Dictionary<string, object> { ["age_over_18"] = true },
            Issuer = issuer,
            Errors = Array.Empty<VerificationError>(),
        };

        Assert.True(result.IsValid);
        Assert.True((bool)result.DisclosedClaims["age_over_18"]);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void VerificationResult_Invalid_CarriesErrors()
    {
        var result = new VerificationResult
        {
            IsValid = false,
            DisclosedClaims = new Dictionary<string, object>(),
            Issuer = new IssuerInfo { Identifier = "?", Trusted = false, KeyResolutionMethod = "x5c" },
            Errors = new[] { new VerificationError { Code = "signature_invalid", Message = "JWS signature does not verify" } },
        };
        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Equal("signature_invalid", result.Errors[0].Code);
    }
}
