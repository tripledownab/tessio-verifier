using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class ResponseEncryptionKeyProviderTests
{
    [Fact]
    public void SharedKey_YieldsIdenticalJwkAndThumbprintKid_AcrossInstances()
    {
        // Two provider instances built from the same key material, as two scaled-out app instances
        // loading the same persisted key would be.
        using var source = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = source.ExportParameters(true);

        using var a = new ResponseEncryptionKeyProvider(ECDsa.Create(parameters));
        using var b = new ResponseEncryptionKeyProvider(ECDsa.Create(parameters));

        Assert.Equal(a.KeyId, b.KeyId);
        Assert.Equal(a.PublicJwk.ToJsonString(), b.PublicJwk.ToJsonString());
    }

    [Fact]
    public void DifferentKeys_YieldDifferentKids()
    {
        using var a = new ResponseEncryptionKeyProvider();
        using var b = new ResponseEncryptionKeyProvider();
        Assert.NotEqual(a.KeyId, b.KeyId);
    }

    [Fact]
    public void NonP256Key_IsRejected()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        try
        {
            Assert.Throws<ArgumentException>(() => new ResponseEncryptionKeyProvider(key));
        }
        finally
        {
            key.Dispose();
        }
    }
}
