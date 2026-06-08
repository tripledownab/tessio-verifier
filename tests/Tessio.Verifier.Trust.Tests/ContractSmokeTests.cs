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
    }
}
