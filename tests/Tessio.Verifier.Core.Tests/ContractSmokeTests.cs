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
        // The three properties added to this frozen record round-trip here, as every other property in
        // this file does. A full-length digest so the literal has the shape a caller stores.
        const string Digest = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var anchored = new IssuerInfo
        {
            Identifier = "https://issuer.example",
            Trusted = true,
            KeyResolutionMethod = "x5c",
            TrustListSource = "lotl://eu",
            TrustAnchorSubject = "CN=Some Root, C=EU",
            TrustAnchorThumbprint = Digest,
        };
        Assert.Equal("lotl://eu", anchored.TrustListSource);
        Assert.Equal("CN=Some Root, C=EU", anchored.TrustAnchorSubject);
        Assert.Equal(Digest, anchored.TrustAnchorThumbprint);

        // The placeholder for a result produced before any issuer resolved carries no provenance. "No
        // anchor vouched" and "we never got far enough to ask" both render as null, so the one place that
        // states the second case says so explicitly.
        Assert.Null(IssuerInfo.Unknown.TrustListSource);
        Assert.Null(IssuerInfo.Unknown.TrustAnchorSubject);
        Assert.Null(IssuerInfo.Unknown.TrustAnchorThumbprint);

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
