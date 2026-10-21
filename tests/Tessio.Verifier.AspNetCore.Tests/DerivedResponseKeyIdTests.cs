// What belongs here: what a derived store does with the kid a wallet's response names, before and after
// it reaches the salt store.
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedResponseKeyIdTests
{
    private readonly ManualClock _clock = new();
    private readonly byte[] _master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength);

    private ResponseEncryptionKeyStore Store(SaltTable salts, byte[]? master = null) => new(_clock, new ResponseKeyDerivationOptions
    {
        Master = master ?? _master,
        Salts = salts,
    });

    [Theory]
    [InlineData("short")]
    [InlineData("e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJg=")]
    [InlineData("e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJgcX")]
    [InlineData("e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJg ")]
    public void A_kid_no_store_could_have_issued_never_reaches_the_salt_store(string kid)
    {
        var salts = new SaltTable();
        using var store = Store(salts);

        Assert.Null(store.Get(kid));
        Assert.Empty(salts.Asked);
    }

    [Fact]
    public void A_kid_shaped_like_an_issued_one_reaches_the_salt_store()
    {
        // The control for the theory above: without it, an empty Asked could mean nothing is ever asked.
        var salts = new SaltTable();
        using var store = Store(salts);

        Assert.Null(store.Get("e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJgc"));
        Assert.Single(salts.Asked);
    }

    [Fact]
    public void A_kid_whose_case_was_changed_names_no_key_in_a_store_that_ignores_case()
    {
        var salts = new SaltTable(StringComparer.OrdinalIgnoreCase);
        using var first = Store(salts);
        var kid = first.CreateForRequest(_clock.Now + TimeSpan.FromMinutes(5)).KeyId;
        var changed = new string(kid.Select(c => char.IsUpper(c) ? char.ToLowerInvariant(c) : char.ToUpperInvariant(c)).ToArray());

        using var second = Store(salts);
        Assert.Null(second.Get(changed));
        Assert.NotNull(second.Get(kid));
    }

    [Fact]
    public void In_a_store_that_ignores_case_another_master_is_still_refused_loudly()
    {
        var salts = new SaltTable(StringComparer.OrdinalIgnoreCase);
        using var first = Store(salts);
        var kid = first.CreateForRequest(_clock.Now + TimeSpan.FromMinutes(5)).KeyId;

        using var other = Store(salts, RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength));
        Assert.Throws<InvalidOperationException>(() => other.Get(kid));
    }
}
