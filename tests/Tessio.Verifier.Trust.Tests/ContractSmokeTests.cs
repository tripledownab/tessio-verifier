using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Trust.Tests;

public class ContractSmokeTests
{
    [Fact]
    public void ITrustListResolver_IsPublicInterface()
    {
        var type = typeof(ITrustListResolver);
        Assert.True(type.IsInterface);
        Assert.True(type.IsPublic);
    }

    [Fact]
    public void IssuerTrustStatus_InitOnly_RoundTripsAllFields()
    {
        var trusted = new IssuerTrustStatus
        {
            Trusted = true,
            TrustListSource = "lotl://eu",
        };
        Assert.True(trusted.Trusted);
        Assert.Equal("lotl://eu", trusted.TrustListSource);
        Assert.Null(trusted.Reason);

        var untrusted = new IssuerTrustStatus
        {
            Trusted = false,
            TrustListSource = "lotl://eu",
            Reason = "not in any national trusted list",
        };
        Assert.False(untrusted.Trusted);
        Assert.Equal("not in any national trusted list", untrusted.Reason);

        // The name of this test says ALL fields, so the two anchor fields belong in it. A round-trip
        // test that silently stops covering a field promises something it no longer does.
        var anchored = new IssuerTrustStatus
        {
            Trusted = true,
            TrustListSource = "lotl://eu",
            TrustAnchorSubject = "CN=Some Root, C=EU",
            TrustAnchorThumbprint = "0123456789ABCDEF",
        };
        Assert.Equal("CN=Some Root, C=EU", anchored.TrustAnchorSubject);
        Assert.Equal("0123456789ABCDEF", anchored.TrustAnchorThumbprint);
        Assert.Null(trusted.TrustAnchorSubject);
        Assert.Null(trusted.TrustAnchorThumbprint);
    }
}
