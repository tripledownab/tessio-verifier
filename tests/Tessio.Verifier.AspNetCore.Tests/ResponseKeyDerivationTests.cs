// What belongs here: ResponseKeyDerivation against vectors from an independent implementation, and its
// limits on the master and the salt. The store that uses it is DerivedResponseKeyStoreTests'.
using System.Numerics;
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class ResponseKeyDerivationTests
{
    // From Fixtures/make-response-key-vectors.py, which derives with Python's cryptography package: master,
    // salt, d, x, y and the kid, in that order.
    public static TheoryData<string, string, string, string, string, string> Vectors => new()
    {
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "808182838485868788898a8b8c8d8e8f",
            "281f4cfc7dc8159fcf5487d8e9502cb8aceb6892c2bd770148f2678b99b97a9b",
            "762fd6cc19fb0a9da78dd433b557b7ad3d1b5819875cbb41f86ee51f6106e4b7",
            "e721009c1b40a87bf98a4ba1e026ca77e464cbd54544f96e6a0b5b3b46f65420",
            "WJ11tVcb1KJSQbJO1K4onugqN03IRNns-SYNmbRzOeg"
        },
        {
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "29e16141ba52d472d7fb2fd3f7d7e947217442e646f64c70ec4b964389ab2c1e",
            "a323196ff1d11de4de9f0bf3056cd122c3217422ba8712b561a48242777edf3d",
            "42b85901edec978723fbf49b72ef24adae3306d83b6aaf3bd3b0ea6beef1fc55",
            "bAgMKB2x2XHEyAlIQU2_0qgnWM4SssDx7zn2gLAZpMY"
        },
        {
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "ffffffffffffffffffffffffffffffff",
            "d565bf0cf4a1bc972c0a43db2a91acf3a0d17a9623f74de92bd3e25b76adce8d",
            "7b53373a0a86c184cd97be5435c032b2abeacfb1c997da9d3347678d192f1dcd",
            "cc07112f60a7e8bf2aae9108bb3c867a754c8394a22e6fda926d562a8803e1d6",
            "oCDDWD6mhKvJ0fDGmXiMCmbQ_sjPRxlzOUR_gOKWucg"
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00000000000000000000000000000051",
            "00d07049d722733a75415645893148025392f5b1ade61e85049ceb21beaec951",
            "b2bcbe23816ea8ab9ec8612fd834d158e9245eceaaefae6aa1028cd3b6248fbf",
            "9de376f146939aaf4da02dae02c9090191c559da26cc9818d1d5e7d521d79dd7",
            "hLkgsntnNEcS_8KNknwwbssXxIo7OWRIDOsGDN4MgIk"
        },
    };

    [Theory]
    [MemberData(nameof(Vectors))]
    public void The_derived_key_matches_an_independent_implementation(
        string master, string salt, string d, string x, string y, string kid)
    {
        using var derived = ResponseKeyDerivation.Derive(Convert.FromHexString(master), Convert.FromHexString(salt));
        var parameters = derived.ExportParameters(includePrivateParameters: true);

        Assert.Equal(d, Convert.ToHexString(parameters.D!), ignoreCase: true);
        Assert.Equal(x, Convert.ToHexString(parameters.Q.X!), ignoreCase: true);
        Assert.Equal(y, Convert.ToHexString(parameters.Q.Y!), ignoreCase: true);

        using var keys = new ResponseEncryptionKeyProvider(derived);
        Assert.Equal(kid, keys.KeyId);
    }

    [Fact]
    public void The_order_reduced_by_is_P256s_as_the_platform_states_it()
    {
        using var curve = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var order = new BigInteger(curve.ExportExplicitParameters(false).Curve.Order, isUnsigned: true, isBigEndian: true);

        Assert.Equal(order, ResponseKeyDerivation.Order);
    }

    [Fact]
    public void A_master_or_salt_below_its_minimum_is_refused_and_one_at_it_is_not()
    {
        var master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength);
        var salt = new byte[ResponseKeyDerivation.MinimumSaltLength];
        using (ResponseKeyDerivation.Derive(master, salt))
        {
        }

        Assert.Equal("master", Assert.Throws<ArgumentException>(() => ResponseKeyDerivation.Derive(master.AsSpan(1), salt)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentException>(() => ResponseKeyDerivation.Derive(master, salt.AsSpan(1))).ParamName);
    }

    [Fact]
    public void A_master_of_all_zeros_is_refused()
    {
        var salt = new byte[ResponseKeyDerivation.MinimumSaltLength];
        Assert.Equal("master", Assert.Throws<ArgumentException>(
            () => ResponseKeyDerivation.Derive(new byte[ResponseKeyDerivation.MinimumMasterLength], salt)).ParamName);
    }

    [Fact]
    public void Another_salt_derives_another_key()
    {
        var master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength);
        using var a = new ResponseEncryptionKeyProvider(ResponseKeyDerivation.Derive(master, new byte[16]));
        using var b = new ResponseEncryptionKeyProvider(ResponseKeyDerivation.Derive(master, Enumerable.Repeat((byte)1, 16).ToArray()));

        Assert.NotEqual(a.KeyId, b.KeyId);
    }
}
